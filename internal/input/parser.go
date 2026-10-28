package input

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/drag-team/relayprobe/internal/model"
)

type Format string

const (
	FormatAuto  Format = "auto"
	FormatText  Format = "text"
	FormatCSV   Format = "csv"
	FormatJSON  Format = "json"
	FormatJSONL Format = "jsonl"
)

type Options struct {
	Format          Format
	DefaultProtocol model.Protocol
	Source          string
	MaxBytes        int64
	MaxEntries      int
	Deduplicate     bool
}

func ParseFormat(s string) (Format, error) {
	f := Format(strings.ToLower(strings.TrimSpace(s)))
	switch f {
	case FormatAuto, FormatText, FormatCSV, FormatJSON, FormatJSONL:
		return f, nil
	default:
		return "", fmt.Errorf("unsupported input format %q", s)
	}
}

type Rejection struct {
	Source string
	Line   int
	Value  string
	Reason string
}

type Parser struct {
	opts      Options
	seen      map[[16]byte]struct{}
	dedupKey  [32]byte
	usedBytes int64
	Stats     model.InputStats
}

func New(opts Options) *Parser {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 256 << 20
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 1_000_000
	}
	if opts.DefaultProtocol == "" {
		opts.DefaultProtocol = model.ProtocolHTTP
	}
	p := &Parser{opts: opts, seen: make(map[[16]byte]struct{})}
	_, _ = rand.Read(p.dedupKey[:])
	return p
}

func ParseProxy(raw string, defaultProtocol model.Protocol) (model.Proxy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return model.Proxy{}, errors.New("empty proxy")
	}
	if strings.ContainsAny(raw, "\r\n\x00") {
		return model.Proxy{}, errors.New("control characters are not allowed")
	}
	if !strings.Contains(raw, "://") && !strings.HasPrefix(raw, "[") && strings.Count(raw, ":") == 3 {
		parts := strings.SplitN(raw, ":", 4)
		if port, portErr := strconv.ParseUint(parts[1], 10, 16); portErr == nil && port > 0 {
			if parts[2] == "" {
				return model.Proxy{}, errors.New("proxy username must not be empty")
			}
			raw = string(defaultProtocol) + "://" + url.UserPassword(parts[2], parts[3]).String() + "@" + net.JoinHostPort(parts[0], parts[1])
		}
	}
	if !strings.Contains(raw, "://") {
		raw = string(defaultProtocol) + "://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return model.Proxy{}, errors.New("invalid proxy URI")
	}
	p, err := model.ParseProtocol(u.Scheme)
	if err != nil {
		return model.Proxy{}, err
	}
	if u.Hostname() == "" {
		return model.Proxy{}, errors.New("missing proxy host")
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return model.Proxy{}, errors.New("proxy URI must not contain path, query, or fragment")
	}
	portText := u.Port()
	if portText == "" {
		return model.Proxy{}, errors.New("missing proxy port")
	}
	port64, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port64 == 0 {
		return model.Proxy{}, errors.New("proxy port must be between 1 and 65535")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if len(host) > 253 {
		return model.Proxy{}, errors.New("proxy host is too long")
	}
	if ip := net.ParseIP(host); ip == nil {
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 {
				return model.Proxy{}, errors.New("invalid proxy hostname")
			}
			for i, r := range label {
				if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || (r == '-' && i > 0 && i < len(label)-1)) {
					return model.Proxy{}, errors.New("invalid proxy hostname")
				}
			}
		}
	}
	proxy := model.Proxy{Protocol: p, Host: host, Port: uint16(port64)}
	if u.User != nil {
		pass, ok := u.User.Password()
		if !ok {
			return model.Proxy{}, errors.New("credentials require explicit username:password")
		}
		user := u.User.Username()
		if user == "" {
			return model.Proxy{}, errors.New("proxy username must not be empty")
		}
		if pass == "***" {
			return model.Proxy{}, errors.New("redacted proxy password cannot be reused")
		}
		if len(user) > 255 || len(pass) > 255 {
			return model.Proxy{}, errors.New("proxy credentials exceed protocol limits")
		}
		proxy.Credentials = &model.Credentials{Username: user, Password: pass}
	}
	return proxy, nil
}

func (p *Parser) Emit(r io.Reader, emit func(model.Proxy) error, reject func(Rejection)) error {
	return p.EmitSource(r, p.opts.Format, p.opts.Source, emit, reject)
}

func (p *Parser) EmitSource(r io.Reader, format Format, source string, emit func(model.Proxy) error, reject func(Rejection)) error {
	remaining := p.opts.MaxBytes - p.usedBytes
	if remaining <= 0 {
		return fmt.Errorf("input exceeds %d-byte aggregate limit", p.opts.MaxBytes)
	}
	oldFormat, oldSource := p.opts.Format, p.opts.Source
	p.opts.Format, p.opts.Source = format, source
	defer func() { p.opts.Format, p.opts.Source = oldFormat, oldSource }()
	lr := &io.LimitedReader{R: r, N: remaining + 1}
	r = lr
	if format == FormatAuto {
		format, r = detectFormat(source, r)
	}
	var err error
	switch format {
	case FormatJSON:
		err = p.emitJSON(r, emit, reject)
	case FormatJSONL:
		err = p.emitJSONL(r, emit, reject)
	case FormatCSV:
		err = p.emitCSV(r, emit, reject)
	default:
		err = p.emitText(r, emit, reject)
	}
	consumed := remaining + 1 - lr.N
	p.usedBytes += consumed
	if err != nil {
		return err
	}
	if consumed > remaining {
		return fmt.Errorf("input exceeds %d-byte aggregate limit", p.opts.MaxBytes)
	}
	return nil
}

func detectFormat(source string, r io.Reader) (Format, io.Reader) {
	lowerSource := strings.ToLower(source)
	if strings.HasSuffix(lowerSource, ".gz") {
		lowerSource = strings.TrimSuffix(lowerSource, ".gz")
	}
	switch filepath.Ext(lowerSource) {
	case ".csv":
		return FormatCSV, r
	case ".json":
		return FormatJSON, r
	case ".jsonl", ".ndjson":
		return FormatJSONL, r
	}
	br := bufio.NewReaderSize(r, 4096)
	peek, _ := br.Peek(4096)
	trimmed := strings.TrimLeft(string(peek), " \t\r\n")
	if strings.HasPrefix(trimmed, "[") {
		return FormatJSON, br
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, `"`) {
		return FormatJSONL, br
	}
	return FormatText, br
}

func MaybeDecompress(r io.Reader) (io.Reader, io.Closer, error) {
	var header [2]byte
	n, err := io.ReadFull(r, header[:])
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, nil, fmt.Errorf("read input header: %w", err)
	}
	stream := io.MultiReader(bytes.NewReader(header[:n]), r)
	if n < 2 || header[0] != 0x1f || header[1] != 0x8b {
		return stream, nil, nil
	}
	gz, err := gzip.NewReader(stream)
	if err != nil {
		return nil, nil, fmt.Errorf("open gzip input: %w", err)
	}
	return gz, gz, nil
}

func (p *Parser) accept(raw string, line int, emit func(model.Proxy) error, reject func(Rejection)) error {
	p.Stats.Read++
	if p.Stats.Read > p.opts.MaxEntries {
		return fmt.Errorf("input exceeds %d-entry aggregate limit", p.opts.MaxEntries)
	}
	proxy, err := ParseProxy(raw, p.opts.DefaultProtocol)
	if err != nil {
		p.Stats.Rejected++
		if reject != nil {
			reject(Rejection{Source: p.opts.Source, Line: line, Value: redactRaw(raw), Reason: err.Error()})
		}
		return nil
	}
	proxy.Source, proxy.Line = p.opts.Source, line
	key := proxy.DedupIdentity(p.dedupKey[:])
	if p.opts.Deduplicate {
		if _, ok := p.seen[key]; ok {
			p.Stats.Duplicates++
			return nil
		}
		p.seen[key] = struct{}{}
	}
	p.Stats.Accepted++
	return emit(proxy)
}

func (p *Parser) emitText(r io.Reader, emit func(model.Proxy) error, reject func(Rejection)) error {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	for s.Scan() {
		line++
		raw := strings.TrimSpace(s.Text())
		if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, ";") {
			continue
		}
		if i := strings.Index(raw, " #"); i >= 0 {
			raw = strings.TrimSpace(raw[:i])
		}
		if err := p.accept(raw, line, emit, reject); err != nil {
			return err
		}
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	return nil
}

func (p *Parser) emitCSV(r io.Reader, emit func(model.Proxy) error, reject func(Rejection)) error {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true
	line := 0
	var columns map[string]int
	for {
		rec, err := cr.Read()
		line++
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read CSV record %d: %w", line, err)
		}
		if len(rec) == 0 {
			continue
		}
		if line == 1 {
			var headerErr error
			columns, headerErr = csvHeader(rec)
			if headerErr != nil {
				return headerErr
			}
			if columns != nil {
				continue
			}
		}
		raw := ""
		if columns != nil {
			raw = csvProxy(rec, columns, p.opts.DefaultProtocol)
		} else {
			raw = rec[0]
			if len(rec) >= 2 && !strings.Contains(raw, "://") {
				raw = strings.TrimSpace(rec[0]) + ":" + strings.TrimSpace(rec[1])
			}
		}
		if err := p.accept(raw, line, emit, reject); err != nil {
			return err
		}
	}
}

func csvHeader(record []string) (map[string]int, error) {
	columns := make(map[string]int, len(record))
	for i, value := range record {
		name := strings.ToLower(strings.TrimSpace(value))
		if name == "" {
			continue
		}
		if _, exists := columns[name]; exists {
			return nil, fmt.Errorf("CSV header contains duplicate column %q", name)
		}
		columns[name] = i
	}
	_, proxy := columns["proxy"]
	_, host := columns["host"]
	_, ip := columns["ip"]
	_, port := columns["port"]
	if proxy || (port && (host || ip)) {
		return columns, nil
	}
	return nil, nil
}

func csvProxy(record []string, columns map[string]int, defaultProtocol model.Protocol) string {
	if index, ok := columns["proxy"]; ok {
		return csvField(record, index)
	}
	hostIndex, ok := columns["host"]
	if !ok {
		hostIndex = columns["ip"]
	}
	host := csvField(record, hostIndex)
	port := csvField(record, columns["port"])
	protocol := string(defaultProtocol)
	if index, ok := columns["protocol"]; ok && csvField(record, index) != "" {
		protocol = strings.ToLower(csvField(record, index))
	} else if index, ok := columns["scheme"]; ok && csvField(record, index) != "" {
		protocol = strings.ToLower(csvField(record, index))
	}
	u := &url.URL{Scheme: protocol, Host: net.JoinHostPort(host, port)}
	username := firstCSVField(record, columns, "username", "user", "login")
	password := firstCSVField(record, columns, "password", "pass")
	if username != "" || password != "" {
		u.User = url.UserPassword(username, password)
	}
	return u.String()
}

func csvField(record []string, index int) string {
	if index < 0 || index >= len(record) {
		return ""
	}
	return strings.TrimSpace(record[index])
}

func firstCSVField(record []string, columns map[string]int, names ...string) string {
	for _, name := range names {
		if index, ok := columns[name]; ok {
			return csvField(record, index)
		}
	}
	return ""
}

func (p *Parser) emitJSON(r io.Reader, emit func(model.Proxy) error, reject func(Rejection)) error {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("read JSON: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return errors.New("JSON input must be an array")
	}
	line := 0
	for dec.More() {
		line++
		var v any
		if err := dec.Decode(&v); err != nil {
			return fmt.Errorf("decode JSON item %d: %w", line, err)
		}
		raw := rawFromJSON(v)
		if raw == "" {
			p.Stats.Read++
			p.Stats.Rejected++
			if reject != nil {
				reject(Rejection{Source: p.opts.Source, Line: line, Value: "<json item>", Reason: "item must be a proxy string or object"})
			}
			continue
		}
		if err := p.accept(raw, line, emit, reject); err != nil {
			return err
		}
	}
	tok, err = dec.Token()
	if err != nil {
		return fmt.Errorf("close JSON array: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != ']' {
		return errors.New("JSON input has an invalid array terminator")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("JSON input contains multiple values")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func (p *Parser) emitJSONL(r io.Reader, emit func(model.Proxy) error, reject func(Rejection)) error {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64<<10), 4<<20)
	line := 0
	for s.Scan() {
		line++
		data := strings.TrimSpace(s.Text())
		if data == "" {
			continue
		}
		var v any
		if err := json.Unmarshal([]byte(data), &v); err != nil {
			return fmt.Errorf("decode JSONL line %d: %w", line, err)
		}
		raw := rawFromJSON(v)
		if raw == "" {
			p.Stats.Read++
			p.Stats.Rejected++
			if reject != nil {
				reject(Rejection{Source: p.opts.Source, Line: line, Value: "<json item>", Reason: "item must be a proxy string or object"})
			}
			continue
		}
		if err := p.accept(raw, line, emit, reject); err != nil {
			return err
		}
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("read JSONL: %w", err)
	}
	return nil
}

func rawFromJSON(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case map[string]any:
		if s, ok := x["proxy"].(string); ok {
			return s
		}
		if h, ok := x["host"].(string); ok {
			protocol := ""
			if s, ok := x["protocol"].(string); ok {
				protocol = strings.ToLower(s)
			}
			host := net.JoinHostPort(h, fmt.Sprint(x["port"]))
			if protocol == "" {
				return host
			}
			u := &url.URL{Scheme: protocol, Host: host}
			username, hasUsername := x["username"].(string)
			password, hasPassword := x["password"].(string)
			if hasUsername || hasPassword {
				u.User = url.UserPassword(username, password)
			}
			return u.String()
		}
	}
	return ""
}

func redactRaw(raw string) string {
	if i := strings.Index(raw, "://"); i >= 0 {
		prefix, rest := raw[:i+3], raw[i+3:]
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			return prefix + "***:***@" + rest[at+1:]
		}
	}
	if at := strings.LastIndex(raw, "@"); at > 0 {
		prefix := raw[:at]
		if strings.Contains(prefix, ":") {
			return "***:***@" + raw[at+1:]
		}
	}
	if !strings.HasPrefix(raw, "[") && strings.Count(raw, ":") >= 3 {
		return "<redacted-invalid-input>"
	}
	return raw
}
