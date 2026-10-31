package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Config struct {
	Concurrency       int                      `json:"concurrency"`
	QueueSize         int                      `json:"queue_size"`
	PerTarget         int                      `json:"per_target_concurrency"`
	RateLimit         float64                  `json:"requests_per_second"`
	ConnectTimeout    time.Duration            `json:"-"`
	RequestTimeout    time.Duration            `json:"-"`
	AutoProbeTimeout  time.Duration            `json:"-"`
	ConnectTimeoutRaw string                   `json:"connect_timeout"`
	RequestTimeoutRaw string                   `json:"request_timeout"`
	AutoProbeRaw      string                   `json:"auto_probe_timeout"`
	Repeat            int                      `json:"repeat"`
	MinSuccessRate    float64                  `json:"min_success_rate"`
	Targets           []string                 `json:"targets"`
	TargetRules       map[string]ResponseRules `json:"target_rules,omitempty"`
	TargetLabels      map[string]string        `json:"target_labels,omitempty"`
	MaxRedirects      int                      `json:"max_redirects"`
	MaxInputBytes     int64                    `json:"max_input_bytes"`
	MaxInputEntries   int                      `json:"max_input_entries"`
	MaxResponseBytes  int64                    `json:"max_response_bytes"`
	IntelligenceBytes int64                    `json:"intelligence_body_bytes"`
	MinResponseBytes  int64                    `json:"min_response_bytes"`
	MinThroughputKBPS float64                  `json:"min_throughput_kbps"`
	ExpectedBodySHA   string                   `json:"expected_body_sha256,omitempty"`
	RequireText       []string                 `json:"require_text,omitempty"`
	RejectText        []string                 `json:"reject_text,omitempty"`
	ExpectJSON        []string                 `json:"expect_json,omitempty"`
	AnonymityBaseline string                   `json:"anonymity_baseline_ip,omitempty"`
	MetadataFile      string                   `json:"metadata_file,omitempty"`
	CABundle          string                   `json:"ca_bundle,omitempty"`
	ProxyCABundle     string                   `json:"proxy_ca_bundle,omitempty"`
	TargetMatrix      bool                     `json:"target_matrix"`
	TargetQuorum      int                      `json:"target_quorum"`
	RotationSamples   int                      `json:"rotation_samples"`
	RotationInterval  time.Duration            `json:"-"`
	RotationRaw       string                   `json:"rotation_interval"`
	Preflight         string                   `json:"preflight"`
	AutoConcurrency   bool                     `json:"-"`
	ScenarioName      string                   `json:"-"`
	AllowPrivate      bool                     `json:"allow_private_targets"`
	AllowRemoteDNS    bool                     `json:"allow_remote_dns"`
	RetryPermanent    bool                     `json:"retry_permanent_failures"`
	StopOnSuccess     bool                     `json:"stop_on_success"`
	RetryBackoff      time.Duration            `json:"-"`
	RetryBackoffRaw   string                   `json:"retry_backoff"`
	DNSCacheTTL       time.Duration            `json:"-"`
	DNSCacheTTLRaw    string                   `json:"dns_cache_ttl"`
	AllowedHosts      []string                 `json:"allowed_target_hosts"`
	DataDir           string                   `json:"data_dir"`
	Save              bool                     `json:"save"`
	ProgressInterval  time.Duration            `json:"-"`
	ProgressRaw       string                   `json:"progress_interval"`
}

type ResponseRules struct {
	MinHTTPStatus     int      `json:"min_http_status,omitempty"`
	MaxHTTPStatus     int      `json:"max_http_status,omitempty"`
	MinResponseBytes  int64    `json:"min_response_bytes,omitempty"`
	MinThroughputKBPS float64  `json:"min_throughput_kbps,omitempty"`
	RequireText       []string `json:"require_text,omitempty"`
	RejectText        []string `json:"reject_text,omitempty"`
	ExpectJSON        []string `json:"expect_json,omitempty"`
	ExpectedBodySHA   string   `json:"expected_body_sha256,omitempty"`
}

const MaxConcurrentCaptureBytes int64 = 512 << 20

func (c Config) ResponseCaptureLimit() int64 {
	limit := min(c.IntelligenceBytes, c.MaxResponseBytes)
	fullCapture := len(c.ExpectJSON) > 0 || hasNonASCII(c.RequireText) || hasNonASCII(c.RejectText)
	for _, rules := range c.TargetRules {
		fullCapture = fullCapture || len(rules.ExpectJSON) > 0 || hasNonASCII(rules.RequireText) || hasNonASCII(rules.RejectText)
	}
	if fullCapture {
		return c.MaxResponseBytes
	}
	return limit
}

func hasNonASCII(values []string) bool {
	for _, value := range values {
		for index := range len(value) {
			if value[index] >= 0x80 {
				return true
			}
		}
	}
	return false
}

func Defaults() Config {
	return Config{
		Concurrency: 128, QueueSize: 256, PerTarget: 64,
		ConnectTimeout: 5 * time.Second, RequestTimeout: 12 * time.Second, AutoProbeTimeout: 3 * time.Second,
		ConnectTimeoutRaw: "5s", RequestTimeoutRaw: "12s", AutoProbeRaw: "3s",
		Repeat: 2, MinSuccessRate: 0.5, Targets: []string{"https://example.com/"}, MaxRedirects: 2,
		MaxInputBytes: 256 << 20, MaxInputEntries: 1_000_000, MaxResponseBytes: 1 << 20, IntelligenceBytes: 64 << 10,
		AllowedHosts: []string{"example.com"},
		DNSCacheTTL:  5 * time.Minute, DNSCacheTTLRaw: "5m",
		RetryBackoff: 100 * time.Millisecond, RetryBackoffRaw: "100ms",
		RotationRaw: "0s", Preflight: "off",
		DataDir: defaultDataDir(), ProgressInterval: 500 * time.Millisecond, ProgressRaw: "500ms",
	}
}

func defaultDataDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "relayprobe")
	}
	return ".relayprobe"
}

type diskConfig Config

func Load(path string) (Config, error) {
	c := Defaults()
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return c, fmt.Errorf("read config: %w", err)
		}
		defer f.Close()
		limited := &io.LimitedReader{R: f, N: (1 << 20) + 1}
		dec := json.NewDecoder(limited)
		dec.DisallowUnknownFields()
		if err := dec.Decode((*diskConfig)(&c)); err != nil {
			return c, fmt.Errorf("parse config: %w", err)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return c, errors.New("parse config: multiple JSON values")
		}
		if limited.N <= 0 {
			return c, errors.New("configuration file exceeds 1 MiB")
		}
	}
	if err := applyEnv(&c); err != nil {
		return c, err
	}
	if err := c.ParseDurations(); err != nil {
		return c, err
	}
	return c, c.Validate()
}

func applyEnv(c *Config) error {
	for _, item := range []struct {
		name string
		dst  *int
	}{
		{"RELAYPROBE_CONCURRENCY", &c.Concurrency},
		{"RELAYPROBE_QUEUE_SIZE", &c.QueueSize},
		{"RELAYPROBE_PER_TARGET_CONCURRENCY", &c.PerTarget},
		{"RELAYPROBE_REPEAT", &c.Repeat},
		{"RELAYPROBE_MAX_REDIRECTS", &c.MaxRedirects},
		{"RELAYPROBE_TARGET_QUORUM", &c.TargetQuorum},
		{"RELAYPROBE_ROTATION_SAMPLES", &c.RotationSamples},
		{"RELAYPROBE_MAX_INPUT_ENTRIES", &c.MaxInputEntries},
	} {
		if err := envInt(item.name, item.dst); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		name string
		dst  *int64
	}{
		{"RELAYPROBE_MAX_INPUT_BYTES", &c.MaxInputBytes},
		{"RELAYPROBE_MAX_RESPONSE_BYTES", &c.MaxResponseBytes},
		{"RELAYPROBE_INTELLIGENCE_BODY_BYTES", &c.IntelligenceBytes},
		{"RELAYPROBE_MIN_RESPONSE_BYTES", &c.MinResponseBytes},
	} {
		if err := envInt64(item.name, item.dst); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		name string
		dst  *float64
	}{
		{"RELAYPROBE_REQUESTS_PER_SECOND", &c.RateLimit},
		{"RELAYPROBE_MIN_SUCCESS_RATE", &c.MinSuccessRate},
		{"RELAYPROBE_MIN_THROUGHPUT_KBPS", &c.MinThroughputKBPS},
	} {
		if err := envFloat(item.name, item.dst); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		name string
		dst  *bool
	}{
		{"RELAYPROBE_ALLOW_PRIVATE_TARGETS", &c.AllowPrivate},
		{"RELAYPROBE_ALLOW_REMOTE_DNS", &c.AllowRemoteDNS},
		{"RELAYPROBE_RETRY_PERMANENT_FAILURES", &c.RetryPermanent},
		{"RELAYPROBE_STOP_ON_SUCCESS", &c.StopOnSuccess},
		{"RELAYPROBE_SAVE", &c.Save},
		{"RELAYPROBE_TARGET_MATRIX", &c.TargetMatrix},
	} {
		if err := envBool(item.name, item.dst); err != nil {
			return err
		}
	}
	if v := os.Getenv("RELAYPROBE_CONNECT_TIMEOUT"); v != "" {
		c.ConnectTimeoutRaw = v
	}
	if v := os.Getenv("RELAYPROBE_REQUEST_TIMEOUT"); v != "" {
		c.RequestTimeoutRaw = v
	}
	if v := os.Getenv("RELAYPROBE_AUTO_PROBE_TIMEOUT"); v != "" {
		c.AutoProbeRaw = v
	}
	if v := os.Getenv("RELAYPROBE_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("RELAYPROBE_METADATA_FILE"); v != "" {
		c.MetadataFile = v
	}
	if v := os.Getenv("RELAYPROBE_CA_BUNDLE"); v != "" {
		c.CABundle = v
	}
	if v := os.Getenv("RELAYPROBE_PROXY_CA_BUNDLE"); v != "" {
		c.ProxyCABundle = v
	}
	if v := os.Getenv("RELAYPROBE_EXPECTED_BODY_SHA256"); v != "" {
		c.ExpectedBodySHA = strings.ToLower(strings.TrimSpace(v))
	}
	if v := os.Getenv("RELAYPROBE_PREFLIGHT"); v != "" {
		c.Preflight = strings.ToLower(strings.TrimSpace(v))
	}
	if v := os.Getenv("RELAYPROBE_TARGETS"); v != "" {
		c.Targets = envList(v)
	}
	if v := os.Getenv("RELAYPROBE_ALLOWED_TARGET_HOSTS"); v != "" {
		c.AllowedHosts = envList(v)
	}
	if v := os.Getenv("RELAYPROBE_REQUIRE_TEXT"); v != "" {
		c.RequireText = envList(v)
	}
	if v := os.Getenv("RELAYPROBE_REJECT_TEXT"); v != "" {
		c.RejectText = envList(v)
	}
	if v := os.Getenv("RELAYPROBE_EXPECT_JSON"); v != "" {
		c.ExpectJSON = envList(v)
	}
	if v := os.Getenv("RELAYPROBE_ANONYMITY_BASELINE_IP"); v != "" {
		c.AnonymityBaseline = strings.TrimSpace(v)
	}
	if v := os.Getenv("RELAYPROBE_DNS_CACHE_TTL"); v != "" {
		c.DNSCacheTTLRaw = v
	}
	if v := os.Getenv("RELAYPROBE_RETRY_BACKOFF"); v != "" {
		c.RetryBackoffRaw = v
	}
	if v := os.Getenv("RELAYPROBE_ROTATION_INTERVAL"); v != "" {
		c.RotationRaw = v
	}
	if v := os.Getenv("RELAYPROBE_PROGRESS_INTERVAL"); v != "" {
		c.ProgressRaw = v
	}
	return nil
}

func envInt(name string, dst *int) error {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	*dst = n
	return nil
}

func envInt64(name string, dst *int64) error {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	*dst = n
	return nil
}

func envFloat(name string, dst *float64) error {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	*dst = n
	return nil
}

func envBool(name string, dst *bool) error {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	*dst = b
	return nil
}

func envList(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func (c *Config) ParseDurations() error {
	var err error
	if c.ConnectTimeout, err = time.ParseDuration(c.ConnectTimeoutRaw); err != nil {
		return fmt.Errorf("invalid connect_timeout: %w", err)
	}
	if c.RequestTimeout, err = time.ParseDuration(c.RequestTimeoutRaw); err != nil {
		return fmt.Errorf("invalid request_timeout: %w", err)
	}
	if c.AutoProbeTimeout, err = time.ParseDuration(c.AutoProbeRaw); err != nil {
		return fmt.Errorf("invalid auto_probe_timeout: %w", err)
	}
	if c.ProgressInterval, err = time.ParseDuration(c.ProgressRaw); err != nil {
		return fmt.Errorf("invalid progress_interval: %w", err)
	}
	if c.DNSCacheTTL, err = time.ParseDuration(c.DNSCacheTTLRaw); err != nil {
		return fmt.Errorf("invalid dns_cache_ttl: %w", err)
	}
	if c.RetryBackoff, err = time.ParseDuration(c.RetryBackoffRaw); err != nil {
		return fmt.Errorf("invalid retry_backoff: %w", err)
	}
	if c.RotationInterval, err = time.ParseDuration(c.RotationRaw); err != nil {
		return fmt.Errorf("invalid rotation_interval: %w", err)
	}
	return nil
}

func (c Config) Validate() error {
	if c.Concurrency < 1 || c.Concurrency > 4096 {
		return errors.New("concurrency must be between 1 and 4096")
	}
	if c.QueueSize < 1 || c.QueueSize > 65536 {
		return errors.New("queue_size must be between 1 and 65536")
	}
	if c.PerTarget < 1 || c.PerTarget > 4096 {
		return errors.New("per_target_concurrency must be between 1 and 4096")
	}
	if c.Repeat < 1 || c.Repeat > 20 {
		return errors.New("repeat must be between 1 and 20")
	}
	if math.IsNaN(c.MinSuccessRate) || math.IsInf(c.MinSuccessRate, 0) || c.MinSuccessRate <= 0 || c.MinSuccessRate > 1 {
		return errors.New("min_success_rate must be greater than 0 and at most 1")
	}
	if math.IsNaN(c.RateLimit) || math.IsInf(c.RateLimit, 0) || c.RateLimit < 0 || c.RateLimit > 100000 || (c.RateLimit > 0 && c.RateLimit < 0.1) {
		return errors.New("requests_per_second must be 0 (disabled) or between 0.1 and 100000")
	}
	if c.ConnectTimeout < 100*time.Millisecond || c.ConnectTimeout > 2*time.Minute {
		return errors.New("connect_timeout must be between 100ms and 2m")
	}
	if c.RequestTimeout < c.ConnectTimeout || c.RequestTimeout > 5*time.Minute {
		return errors.New("request_timeout must be >= connect_timeout and <= 5m")
	}
	if c.AutoProbeTimeout < 100*time.Millisecond || c.AutoProbeTimeout > 2*time.Minute {
		return errors.New("auto_probe_timeout must be between 100ms and 2m")
	}
	if c.DNSCacheTTL < 0 || c.DNSCacheTTL > 24*time.Hour {
		return errors.New("dns_cache_ttl must be between 0 and 24h")
	}
	if c.RetryBackoff < 0 || c.RetryBackoff > 30*time.Second {
		return errors.New("retry_backoff must be between 0 and 30s")
	}
	if c.RotationInterval < 0 || c.RotationInterval > time.Hour {
		return errors.New("rotation_interval must be between 0 and 1h")
	}
	if c.RotationSamples != 0 && (c.RotationSamples < 2 || c.RotationSamples > 50) {
		return errors.New("rotation_samples must be 0 (disabled) or between 2 and 50")
	}
	if c.ProgressInterval < 50*time.Millisecond || c.ProgressInterval > time.Minute {
		return errors.New("progress_interval must be between 50ms and 1m")
	}
	if c.MaxRedirects < 0 || c.MaxRedirects > 10 {
		return errors.New("max_redirects must be between 0 and 10")
	}
	if c.MaxInputBytes < 1 || c.MaxInputBytes > 10<<30 {
		return errors.New("max_input_bytes is outside safe limits")
	}
	if c.MaxInputEntries < 1 || c.MaxInputEntries > 50_000_000 {
		return errors.New("max_input_entries must be between 1 and 50000000")
	}
	if c.MaxResponseBytes < 1024 || c.MaxResponseBytes > 64<<20 {
		return errors.New("max_response_bytes must be between 1KiB and 64MiB")
	}
	if c.IntelligenceBytes < 1024 || c.IntelligenceBytes > 64<<20 {
		return errors.New("intelligence_body_bytes must be between 1KiB and 64MiB")
	}
	if c.ResponseCaptureLimit() > MaxConcurrentCaptureBytes/int64(c.Concurrency) {
		return errors.New("concurrency and response capture limits exceed the 512MiB safety budget")
	}
	if c.MinResponseBytes < 0 || c.MinResponseBytes > c.MaxResponseBytes {
		return errors.New("min_response_bytes must be between 0 and max_response_bytes")
	}
	if math.IsNaN(c.MinThroughputKBPS) || math.IsInf(c.MinThroughputKBPS, 0) || c.MinThroughputKBPS < 0 || c.MinThroughputKBPS > 100_000_000 {
		return errors.New("min_throughput_kbps must be between 0 and 100000000")
	}
	if c.MinThroughputKBPS > 0 && c.MinResponseBytes < 16<<10 {
		return errors.New("min_response_bytes must be at least 16384 when enforcing throughput")
	}
	if c.ExpectedBodySHA != "" {
		if len(c.ExpectedBodySHA) != 64 {
			return errors.New("expected_body_sha256 must contain 64 hexadecimal characters")
		}
		if _, err := hex.DecodeString(c.ExpectedBodySHA); err != nil {
			return errors.New("expected_body_sha256 must contain 64 hexadecimal characters")
		}
	}
	if len(c.RequireText) > 16 || len(c.RejectText) > 16 || len(c.ExpectJSON) > 16 {
		return errors.New("at most 16 rules of each content assertion type are allowed")
	}
	for _, rule := range append(append([]string{}, c.RequireText...), c.RejectText...) {
		if len(rule) < 1 || len(rule) > 256 {
			return errors.New("content assertion strings must contain 1 to 256 bytes")
		}
	}
	for _, rule := range c.ExpectJSON {
		path, _, ok := strings.Cut(rule, "=")
		if !ok || path == "" || len(rule) > 512 {
			return errors.New("JSON assertions must use a non-empty path=value form of at most 512 bytes")
		}
		for _, segment := range strings.Split(path, ".") {
			if segment == "" {
				return errors.New("JSON assertion paths must contain non-empty dot-separated keys")
			}
		}
	}
	if c.AnonymityBaseline != "" {
		if _, err := netip.ParseAddr(c.AnonymityBaseline); err != nil {
			return errors.New("anonymity_baseline_ip must be an IP address")
		}
	}
	if len(c.Targets) == 0 {
		return errors.New("at least one validation target is required")
	}
	if len(c.Targets) > 32 {
		return errors.New("at most 32 validation targets are allowed")
	}
	if c.TargetQuorum < 0 || c.TargetQuorum > len(c.Targets) {
		return errors.New("target_quorum must be between 0 and the number of targets")
	}
	if c.TargetQuorum > 0 && !c.TargetMatrix {
		return errors.New("target_quorum requires target_matrix")
	}
	effectiveRepeats := c.Repeat
	if c.RotationSamples > effectiveRepeats {
		effectiveRepeats = c.RotationSamples
	}
	if c.TargetMatrix && len(c.Targets)*effectiveRepeats > 1000 {
		return errors.New("target matrix exceeds the 1000-attempt per-proxy safety limit")
	}
	if c.Preflight != "off" && c.Preflight != "report" && c.Preflight != "strict" {
		return errors.New("preflight must be off, report, or strict")
	}
	for _, path := range []string{c.CABundle, c.ProxyCABundle} {
		if len(path) > 4096 || strings.ContainsAny(path, "\r\n\x00") {
			return errors.New("CA bundle path is invalid")
		}
	}
	for index, raw := range c.Targets {
		if len(raw) > 2048 {
			return fmt.Errorf("validation target %d URL exceeds 2048 bytes", index+1)
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("validation target %d has an invalid URL", index+1)
		}
		if u.User != nil {
			return fmt.Errorf("validation target %d must not contain credentials", index+1)
		}
		if port := u.Port(); port != "" {
			n, e := strconv.ParseUint(port, 10, 16)
			if e != nil || n == 0 {
				return fmt.Errorf("validation target %d has an invalid port", index+1)
			}
		}
	}
	knownTargets := make(map[string]struct{}, len(c.Targets))
	for _, target := range c.Targets {
		knownTargets[target] = struct{}{}
	}
	for target, rules := range c.TargetRules {
		if _, ok := knownTargets[target]; !ok {
			return errors.New("target_rules contains a target not present in targets")
		}
		if err := validateResponseRules(rules, c.MaxResponseBytes); err != nil {
			return fmt.Errorf("target_rules entry is invalid: %w", err)
		}
	}
	targetNames := make(map[string]struct{}, len(c.Targets))
	for _, target := range c.Targets {
		name := c.TargetLabels[target]
		if name == "" {
			u, _ := url.Parse(target)
			name = strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + "/"
		}
		if _, duplicate := targetNames[name]; duplicate {
			return fmt.Errorf("validation targets require unique origins or explicit target_labels; duplicate %q", name)
		}
		targetNames[name] = struct{}{}
	}
	for target, label := range c.TargetLabels {
		if _, ok := knownTargets[target]; !ok {
			return errors.New("target_labels contains a target not present in targets")
		}
		if len(label) < 1 || len(label) > 64 || strings.IndexFunc(label, unicode.IsControl) >= 0 {
			return errors.New("target labels must contain 1 to 64 safe characters")
		}
	}
	if len(c.AllowedHosts) > 64 {
		return errors.New("at most 64 allowed target hosts are permitted")
	}
	for _, host := range c.AllowedHosts {
		host = strings.TrimSpace(strings.TrimSuffix(host, "."))
		if host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\@?#") {
			return fmt.Errorf("invalid allowed target host %q", host)
		}
	}
	return nil
}

func validateResponseRules(rules ResponseRules, maxResponseBytes int64) error {
	if rules.MinHTTPStatus < 0 || rules.MinHTTPStatus > 599 || rules.MaxHTTPStatus < 0 || rules.MaxHTTPStatus > 599 {
		return errors.New("HTTP status bounds must be between 0 and 599")
	}
	if rules.MinHTTPStatus > 0 && rules.MaxHTTPStatus > 0 && rules.MinHTTPStatus > rules.MaxHTTPStatus {
		return errors.New("minimum HTTP status must not exceed maximum")
	}
	if rules.MinResponseBytes < 0 || rules.MinResponseBytes > maxResponseBytes {
		return errors.New("minimum response size is outside configured limits")
	}
	if math.IsNaN(rules.MinThroughputKBPS) || math.IsInf(rules.MinThroughputKBPS, 0) || rules.MinThroughputKBPS < 0 || rules.MinThroughputKBPS > 100_000_000 {
		return errors.New("minimum throughput is outside configured limits")
	}
	if rules.MinThroughputKBPS > 0 && rules.MinResponseBytes < 16<<10 {
		return errors.New("minimum response size must be at least 16384 when enforcing throughput")
	}
	if len(rules.RequireText) > 16 || len(rules.RejectText) > 16 || len(rules.ExpectJSON) > 16 {
		return errors.New("at most 16 rules of each assertion type are allowed")
	}
	for _, value := range append(append([]string{}, rules.RequireText...), rules.RejectText...) {
		if len(value) < 1 || len(value) > 256 {
			return errors.New("content assertion strings must contain 1 to 256 bytes")
		}
	}
	for _, value := range rules.ExpectJSON {
		path, _, ok := strings.Cut(value, "=")
		if !ok || path == "" || len(value) > 512 {
			return errors.New("JSON assertions must use path=value and contain at most 512 bytes")
		}
	}
	if rules.ExpectedBodySHA != "" {
		if len(rules.ExpectedBodySHA) != 64 {
			return errors.New("expected body SHA-256 must contain 64 hexadecimal characters")
		}
		if _, err := hex.DecodeString(rules.ExpectedBodySHA); err != nil {
			return errors.New("expected body SHA-256 must contain 64 hexadecimal characters")
		}
	}
	return nil
}

func (c Config) MarshalJSON() ([]byte, error) {
	type alias Config
	a := alias(c)
	a.ConnectTimeoutRaw = c.ConnectTimeout.String()
	a.RequestTimeoutRaw = c.RequestTimeout.String()
	a.AutoProbeRaw = c.AutoProbeTimeout.String()
	a.ProgressRaw = c.ProgressInterval.String()
	a.DNSCacheTTLRaw = c.DNSCacheTTL.String()
	a.RetryBackoffRaw = c.RetryBackoff.String()
	a.RotationRaw = c.RotationInterval.String()
	return json.MarshalIndent(a, "", "  ")
}
