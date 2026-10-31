package protocol

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/drag-team/relayprobe/internal/buildinfo"
	"github.com/drag-team/relayprobe/internal/model"
	"github.com/drag-team/relayprobe/internal/policy"
)

type Error struct {
	Stage  model.Stage
	Status model.Status
	Code   string
	Detail string
	Err    error
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Code
}
func (e *Error) Unwrap() error { return e.Err }

type TimedConn struct {
	Conn         net.Conn
	Connect      time.Duration
	ProxyTLS     time.Duration
	Negotiate    time.Duration
	ProxyTLSInfo *model.TLSInfo
	AuthMethod   string
}

type Connector struct {
	ConnectTimeout time.Duration
	AllowRemoteDNS bool
	DialContext    func(context.Context, string, string) (net.Conn, error)
	TLSConfig      *tls.Config
}

func (c Connector) Open(ctx context.Context, proxy model.Proxy, dest policy.Destination) (TimedConn, error) {
	start := time.Now()
	dial := c.DialContext
	if dial == nil {
		d := &net.Dialer{Timeout: c.ConnectTimeout, KeepAlive: -1}
		dial = d.DialContext
	}
	conn, err := dial(ctx, "tcp", proxy.Address())
	connectTime := time.Since(start)
	if err != nil {
		return TimedConn{}, classifyNet(model.StageConnect, "proxy_connect", err)
	}
	conn = watchContext(ctx, conn)
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	if deadline, yes := ctx.Deadline(); yes {
		_ = conn.SetDeadline(deadline)
	}
	var proxyTLSTime time.Duration
	var proxyTLSInfo *model.TLSInfo
	authMethod := "none"
	if proxy.Protocol == model.ProtocolHTTPS {
		proxyTLSStart := time.Now()
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: proxy.Host}
		if c.TLSConfig != nil {
			tlsConfig = c.TLSConfig.Clone()
			if tlsConfig.MinVersion == 0 {
				tlsConfig.MinVersion = tls.VersionTLS12
			}
			tlsConfig.ServerName = proxy.Host
		}
		secure := tls.Client(conn, tlsConfig)
		if err := secure.HandshakeContext(ctx); err != nil {
			return TimedConn{}, &Error{Stage: model.StageProxyTLS, Status: statusFromNet(err), Code: "proxy_tls_handshake", Detail: "TLS handshake or certificate validation with proxy failed", Err: err}
		}
		proxyTLSTime = time.Since(proxyTLSStart)
		proxyTLSInfo = model.TLSInfoFromState(secure.ConnectionState())
		conn = secure
	}
	negStart := time.Now()
	switch proxy.Protocol {
	case model.ProtocolHTTP, model.ProtocolHTTPS:
		if proxy.Credentials != nil {
			authMethod = "basic"
		}
		if dest.URL.Scheme == "https" || !c.AllowRemoteDNS {
			tunnel, tunnelErr := httpConnect(conn, proxy, dest, c.AllowRemoteDNS)
			if tunnelErr != nil {
				return TimedConn{}, tunnelErr
			}
			conn = tunnel
		}
	case model.ProtocolSOCKS4:
		if proxy.Credentials != nil {
			authMethod = "userid"
		}
		if err := socks4Connect(conn, proxy, dest, false); err != nil {
			return TimedConn{}, err
		}
	case model.ProtocolSOCKS4A:
		if proxy.Credentials != nil {
			authMethod = "userid"
		}
		if !c.AllowRemoteDNS {
			return TimedConn{}, &Error{Stage: model.StagePolicy, Status: model.StatusPolicyBlock, Code: "remote_dns_disabled", Detail: "SOCKS4a remote DNS is disabled by destination policy"}
		}
		if err := socks4Connect(conn, proxy, dest, true); err != nil {
			return TimedConn{}, err
		}
	case model.ProtocolSOCKS5:
		var authErr error
		authMethod, authErr = socks5Connect(conn, proxy, dest, c.AllowRemoteDNS)
		if authErr != nil {
			return TimedConn{}, authErr
		}
	default:
		return TimedConn{}, &Error{Stage: model.StageNegotiate, Status: model.StatusInvalid, Code: "unsupported_protocol", Detail: "unsupported proxy protocol"}
	}
	ok = true
	return TimedConn{Conn: conn, Connect: connectTime, ProxyTLS: proxyTLSTime, Negotiate: time.Since(negStart), ProxyTLSInfo: proxyTLSInfo, AuthMethod: authMethod}, nil
}

func statusFromNet(err error) model.Status {
	var classified *Error
	if errors.As(classifyNet(model.StageProxyTLS, "proxy_tls_handshake", err), &classified) {
		return classified.Status
	}
	return model.StatusFailed
}

func httpConnect(conn net.Conn, proxy model.Proxy, dest policy.Destination, remoteDNS bool) (net.Conn, error) {
	tunnelHost := dest.IP.String()
	if remoteDNS {
		tunnelHost = dest.Host
	}
	authority := net.JoinHostPort(tunnelHost, dest.Port)
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n", authority, authority, buildinfo.UserAgent())
	if proxy.Credentials != nil {
		token := base64.StdEncoding.EncodeToString([]byte(proxy.Credentials.Username + ":" + proxy.Credentials.Password))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", token)
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return nil, classifyNet(model.StageTunnel, "connect_write", err)
	}
	resp, tunnel, err := ReadResponseLimited(conn, &http.Request{Method: http.MethodConnect}, 64<<10)
	if err != nil {
		return nil, &Error{Stage: model.StageTunnel, Status: model.StatusFailed, Code: "invalid_connect_response", Detail: "HTTP proxy returned an invalid or oversized CONNECT response", Err: err}
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	if resp.StatusCode == http.StatusProxyAuthRequired {
		return nil, HTTPProxyAuthError(resp, proxy.Credentials != nil)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		status, code := model.StatusFailed, "connect_rejected"
		if resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout {
			status, code = model.StatusInconclusive, "connect_upstream_error"
		}
		return nil, &Error{Stage: model.StageTunnel, Status: status, Code: code, Detail: fmt.Sprintf("HTTP CONNECT rejected with status %d", resp.StatusCode)}
	}
	return tunnel, nil
}

func HTTPProxyAuthError(resp *http.Response, supplied bool) error {
	if !supplied {
		return &Error{Stage: model.StageNegotiate, Status: model.StatusAuthFailed, Code: "proxy_auth_required", Detail: "HTTP proxy requires credentials"}
	}
	schemes := make(map[string]struct{})
	for _, challenge := range resp.Header.Values("Proxy-Authenticate") {
		fields := strings.Fields(challenge)
		if len(fields) > 0 {
			schemes[strings.ToLower(strings.TrimSuffix(fields[0], ","))] = struct{}{}
		}
	}
	if len(schemes) > 0 {
		if _, basic := schemes["basic"]; !basic {
			names := make([]string, 0, len(schemes))
			for name := range schemes {
				names = append(names, name)
			}
			sort.Strings(names)
			return &Error{Stage: model.StageNegotiate, Status: model.StatusAuthFailed, Code: "proxy_auth_unsupported", Detail: "HTTP proxy requires unsupported authentication scheme(s): " + strings.Join(names, ",")}
		}
	}
	return &Error{Stage: model.StageNegotiate, Status: model.StatusAuthFailed, Code: "proxy_auth_rejected", Detail: "HTTP proxy rejected the supplied credentials"}
}

type readerConn struct {
	net.Conn
	r io.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

var errHeaderLimit = errors.New("HTTP response headers exceed limit")

type headerLimitReader struct {
	r         io.Reader
	remaining int
	matched   int
	done      bool
}

func (r *headerLimitReader) Read(data []byte) (int, error) {
	if r.done {
		return r.r.Read(data)
	}
	if r.remaining == 0 {
		return 0, errHeaderLimit
	}
	if len(data) > r.remaining {
		data = data[:r.remaining]
	}
	n, err := r.r.Read(data)
	r.remaining -= n
	terminator := [...]byte{'\r', '\n', '\r', '\n'}
	for _, value := range data[:n] {
		if value == terminator[r.matched] {
			r.matched++
			if r.matched == len(terminator) {
				r.done = true
				break
			}
		} else if value == terminator[0] {
			r.matched = 1
		} else {
			r.matched = 0
		}
	}
	return n, err
}

func ReadResponseLimited(conn net.Conn, req *http.Request, maxHeader int) (*http.Response, net.Conn, error) {
	if maxHeader < 1 {
		maxHeader = 64 << 10
	}
	limited := &headerLimitReader{r: conn, remaining: maxHeader}
	source := bufio.NewReaderSize(limited, min(maxHeader, 4096))
	resp, err := http.ReadResponse(source, req)
	if err != nil {
		return nil, nil, err
	}
	if !limited.done {
		_ = resp.Body.Close()
		return nil, nil, errors.New("HTTP response headers require CRLF line endings")
	}
	return resp, &readerConn{Conn: conn, r: source}, nil
}

func socks4Connect(conn net.Conn, proxy model.Proxy, dest policy.Destination, remote bool) error {
	if proxy.Credentials != nil && proxy.Credentials.Password != "" {
		return &Error{Stage: model.StageNegotiate, Status: model.StatusInvalid, Code: "socks4_password_unsupported", Detail: "SOCKS4 supports a user ID but not password authentication"}
	}
	port, _ := strconv.ParseUint(dest.Port, 10, 16)
	req := []byte{4, 1, byte(port >> 8), byte(port)}
	if remote {
		req = append(req, 0, 0, 0, 1)
	} else {
		if !dest.IP.Is4() {
			return &Error{Stage: model.StageNegotiate, Status: model.StatusFailed, Code: "socks4_ipv6_unsupported", Detail: "SOCKS4 requires an IPv4 destination"}
		}
		ip4 := dest.IP.As4()
		req = append(req, ip4[:]...)
	}
	if proxy.Credentials != nil {
		req = append(req, []byte(proxy.Credentials.Username)...)
	}
	req = append(req, 0)
	if remote {
		req = append(req, []byte(dest.Host)...)
		req = append(req, 0)
	}
	if _, err := conn.Write(req); err != nil {
		return classifyNet(model.StageNegotiate, "socks4_write", err)
	}
	reply := make([]byte, 8)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return classifyNet(model.StageNegotiate, "socks4_read", err)
	}
	if reply[0] != 0 && reply[0] != 4 {
		return &Error{Stage: model.StageNegotiate, Status: model.StatusFailed, Code: "socks4_bad_version", Detail: "invalid SOCKS4 response version"}
	}
	if reply[1] != 90 {
		code := map[byte]string{91: "request_rejected", 92: "ident_unreachable", 93: "ident_mismatch"}[reply[1]]
		if code == "" {
			code = "unknown_reply"
		}
		status := model.StatusFailed
		if reply[1] == 92 || reply[1] == 93 {
			status = model.StatusAuthFailed
		}
		return &Error{Stage: model.StageTunnel, Status: status, Code: "socks4_" + code, Detail: "SOCKS4 proxy rejected CONNECT: " + code}
	}
	return nil
}

func socks5Connect(conn net.Conn, proxy model.Proxy, dest policy.Destination, remoteDNS bool) (string, error) {
	methods := []byte{0}
	if proxy.Credentials != nil {
		methods = append(methods, 2)
	}
	if _, err := conn.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		return "", classifyNet(model.StageNegotiate, "socks5_greeting_write", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return "", classifyNet(model.StageNegotiate, "socks5_greeting_read", err)
	}
	if resp[0] != 5 {
		return "", &Error{Stage: model.StageNegotiate, Status: model.StatusFailed, Code: "socks5_bad_version", Detail: "invalid SOCKS5 response version"}
	}
	authMethod := "none"
	switch resp[1] {
	case 0:
	case 2:
		authMethod = "username_password"
		if proxy.Credentials == nil {
			return "", &Error{Stage: model.StageNegotiate, Status: model.StatusAuthFailed, Code: "socks5_auth_required", Detail: "SOCKS5 proxy requires username/password"}
		}
		user, pass := []byte(proxy.Credentials.Username), []byte(proxy.Credentials.Password)
		auth := append([]byte{1, byte(len(user))}, user...)
		auth = append(auth, byte(len(pass)))
		auth = append(auth, pass...)
		if _, err := conn.Write(auth); err != nil {
			return "", classifyNet(model.StageNegotiate, "socks5_auth_write", err)
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(conn, ar); err != nil {
			return "", classifyNet(model.StageNegotiate, "socks5_auth_read", err)
		}
		if ar[0] != 1 || ar[1] != 0 {
			return "", &Error{Stage: model.StageNegotiate, Status: model.StatusAuthFailed, Code: "socks5_auth_failed", Detail: "SOCKS5 username/password authentication failed"}
		}
	case 0xff:
		return "", &Error{Stage: model.StageNegotiate, Status: model.StatusAuthFailed, Code: "socks5_no_acceptable_auth", Detail: "SOCKS5 proxy accepts none of the offered authentication methods"}
	default:
		return "", &Error{Stage: model.StageNegotiate, Status: model.StatusFailed, Code: "socks5_unsupported_auth", Detail: fmt.Sprintf("SOCKS5 proxy selected unsupported authentication method 0x%02x", resp[1])}
	}
	port, _ := strconv.ParseUint(dest.Port, 10, 16)
	req := []byte{5, 1, 0}
	if remoteDNS {
		if len(dest.Host) == 0 || len(dest.Host) > 255 {
			return "", &Error{Stage: model.StageNegotiate, Status: model.StatusInvalid, Code: "socks5_domain_length", Detail: "SOCKS5 destination hostname is outside protocol limits"}
		}
		req = append(req, 3, byte(len(dest.Host)))
		req = append(req, dest.Host...)
	} else if dest.IP.Is4() {
		a := dest.IP.As4()
		req = append(req, 1)
		req = append(req, a[:]...)
	} else {
		a := dest.IP.As16()
		req = append(req, 4)
		req = append(req, a[:]...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return "", classifyNet(model.StageTunnel, "socks5_connect_write", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", classifyNet(model.StageTunnel, "socks5_connect_read", err)
	}
	if head[0] != 5 {
		return "", &Error{Stage: model.StageTunnel, Status: model.StatusFailed, Code: "socks5_bad_reply", Detail: "invalid SOCKS5 CONNECT response"}
	}
	if head[1] != 0 {
		code := socks5Reply(head[1])
		return "", &Error{Stage: model.StageTunnel, Status: model.StatusInconclusive, Code: "socks5_" + code, Detail: "SOCKS5 destination connection failed: " + code}
	}
	var n int
	switch head[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return "", classifyNet(model.StageTunnel, "socks5_bound_read", err)
		}
		n = int(l[0])
	default:
		return "", &Error{Stage: model.StageTunnel, Status: model.StatusFailed, Code: "socks5_bad_address", Detail: "invalid SOCKS5 bound address type"}
	}
	tail := make([]byte, n+2)
	if _, err := io.ReadFull(conn, tail); err != nil {
		return "", classifyNet(model.StageTunnel, "socks5_bound_read", err)
	}
	return authMethod, nil
}

func socks5Reply(b byte) string {
	code := map[byte]string{1: "general_failure", 2: "ruleset_denied", 3: "network_unreachable", 4: "host_unreachable", 5: "connection_refused", 6: "ttl_expired", 7: "command_unsupported", 8: "address_unsupported"}[b]
	if code == "" {
		return "unknown_reply"
	}
	return code
}

func classifyNet(stage model.Stage, code string, err error) error {
	status := model.StatusFailed
	if errors.Is(err, context.Canceled) {
		status = model.StatusInterrupted
		code = "interrupted"
	} else if errors.Is(err, context.DeadlineExceeded) {
		status = model.StatusTimeout
		code = "deadline_exceeded"
	} else if errors.Is(err, syscall.ECONNREFUSED) {
		code = "connection_refused"
	} else if errors.Is(err, syscall.ECONNRESET) {
		code = "connection_reset"
	} else if errors.Is(err, syscall.EPIPE) {
		code = "broken_pipe"
	} else if errors.Is(err, syscall.ENETUNREACH) {
		code = "network_unreachable"
	} else if errors.Is(err, syscall.EHOSTUNREACH) {
		code = "host_unreachable"
	} else if errors.Is(err, syscall.ETIMEDOUT) {
		status = model.StatusTimeout
		code = "network_timeout"
	} else if errors.Is(err, net.ErrClosed) {
		code = "connection_closed"
	} else if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		code = "unexpected_eof"
	}
	var ne net.Error
	if status == model.StatusFailed && errors.As(err, &ne) && ne.Timeout() {
		status = model.StatusTimeout
		code = "network_timeout"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		code = "proxy_dns"
	}
	return &Error{Stage: stage, Status: status, Code: code, Detail: safeNetMessage(err), Err: err}
}

func safeNetMessage(err error) string {
	if errors.Is(err, context.Canceled) {
		return "operation interrupted"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "operation timed out"
	}
	var op *net.OpError
	if errors.As(err, &op) {
		if op.Timeout() {
			return "network operation timed out"
		}
		return "network operation failed: " + op.Op
	}
	return "network operation failed"
}

func IsIPLiteral(host string) bool {
	_, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil
}

type watchedConn struct {
	net.Conn
	stop chan struct{}
	once sync.Once
}

func watchContext(ctx context.Context, conn net.Conn) net.Conn {
	w := &watchedConn{Conn: conn, stop: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			_ = w.Conn.Close()
		case <-w.stop:
		}
	}()
	return w
}
func (w *watchedConn) Close() error { w.once.Do(func() { close(w.stop) }); return w.Conn.Close() }
