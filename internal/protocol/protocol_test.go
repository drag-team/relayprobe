package protocol

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/drag-team/relayprobe/internal/model"
	"github.com/drag-team/relayprobe/internal/policy"
)

func destination() policy.Destination {
	u, _ := url.Parse("https://target.test/")
	return policy.Destination{URL: u, Host: "target.test", Port: "443", IP: netip.MustParseAddr("1.1.1.1")}
}

func pipeConnector(handler func(net.Conn)) Connector {
	return Connector{ConnectTimeout: time.Second, AllowRemoteDNS: true, DialContext: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { defer server.Close(); handler(server) }()
		return client, nil
	}}
}

func echo(c net.Conn) {
	b := make([]byte, 32)
	for {
		n, err := c.Read(b)
		if n > 0 {
			_, _ = c.Write(b[:n])
		}
		if err != nil {
			return
		}
	}
}

func httpScript(c net.Conn) {
	req, err := http.ReadRequest(bufio.NewReader(c))
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	echo(c)
}

func socks4Script(c net.Conn) {
	br := bufio.NewReader(c)
	h := make([]byte, 8)
	if _, err := io.ReadFull(br, h); err != nil {
		return
	}
	for {
		b, err := br.ReadByte()
		if err != nil {
			return
		}
		if b == 0 {
			break
		}
	}
	if h[4] == 0 && h[5] == 0 && h[6] == 0 {
		for {
			b, err := br.ReadByte()
			if err != nil {
				return
			}
			if b == 0 {
				break
			}
		}
	}
	_, _ = c.Write([]byte{0, 90, h[2], h[3], h[4], h[5], h[6], h[7]})
	echo(c)
}

func socks5Script(user, pass string) func(net.Conn) {
	return func(c net.Conn) {
		br := bufio.NewReader(c)
		h := make([]byte, 2)
		if _, err := io.ReadFull(br, h); err != nil {
			return
		}
		methods := make([]byte, int(h[1]))
		_, _ = io.ReadFull(br, methods)
		method := byte(0)
		if user != "" {
			method = 2
		}
		offered := false
		for _, m := range methods {
			if m == method {
				offered = true
			}
		}
		if !offered {
			_, _ = c.Write([]byte{5, 0xff})
			return
		}
		_, _ = c.Write([]byte{5, method})
		if method == 2 {
			v, _ := br.ReadByte()
			ul, _ := br.ReadByte()
			ub := make([]byte, int(ul))
			_, _ = io.ReadFull(br, ub)
			pl, _ := br.ReadByte()
			pb := make([]byte, int(pl))
			_, _ = io.ReadFull(br, pb)
			status := byte(0)
			if v != 1 || string(ub) != user || string(pb) != pass {
				status = 1
			}
			_, _ = c.Write([]byte{1, status})
			if status != 0 {
				return
			}
		}
		req := make([]byte, 4)
		if _, err := io.ReadFull(br, req); err != nil {
			return
		}
		n := 0
		switch req[3] {
		case 1:
			n = 4
		case 4:
			n = 16
		case 3:
			b, _ := br.ReadByte()
			n = int(b)
		}
		tail := make([]byte, n+2)
		_, _ = io.ReadFull(br, tail)
		_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		echo(c)
	}
}

func TestConnectorsRelay(t *testing.T) {
	tests := []struct {
		name   string
		proto  model.Protocol
		script func(net.Conn)
	}{{"http", model.ProtocolHTTP, httpScript}, {"socks4", model.ProtocolSOCKS4, socks4Script}, {"socks4a", model.ProtocolSOCKS4A, socks4Script}, {"socks5", model.ProtocolSOCKS5, socks5Script("", "")}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			con := pipeConnector(tc.script)
			p := model.Proxy{Protocol: tc.proto, Host: "proxy.test", Port: 1080}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, err := con.Open(ctx, p, destination())
			if err != nil {
				t.Fatal(err)
			}
			defer got.Conn.Close()
			_, _ = got.Conn.Write([]byte("ping"))
			b := make([]byte, 4)
			if _, err := io.ReadFull(got.Conn, b); err != nil || string(b) != "ping" {
				t.Fatalf("relay %q: %v", b, err)
			}
		})
	}
}

func TestSOCKS5Authentication(t *testing.T) {
	p := model.Proxy{Protocol: model.ProtocolSOCKS5, Host: "proxy.test", Port: 1080}
	if _, err := pipeConnector(socks5Script("user", "secret")).Open(context.Background(), p, destination()); err == nil {
		t.Fatal("expected missing credentials failure")
	} else if pe, ok := err.(*Error); !ok || pe.Status != model.StatusAuthFailed {
		t.Fatalf("wrong classification: %v", err)
	}
	p.Credentials = &model.Credentials{Username: "user", Password: "wrong"}
	if _, err := pipeConnector(socks5Script("user", "secret")).Open(context.Background(), p, destination()); err == nil {
		t.Fatal("expected bad credentials failure")
	} else if pe, ok := err.(*Error); !ok || pe.Status != model.StatusAuthFailed {
		t.Fatalf("wrong classification: %v", err)
	}
	p.Credentials.Password = "secret"
	got, err := pipeConnector(socks5Script("user", "secret")).Open(context.Background(), p, destination())
	if err != nil {
		t.Fatal(err)
	}
	got.Conn.Close()
}

func TestHTTPAuthenticationFailure(t *testing.T) {
	script := func(c net.Conn) {
		req, _ := http.ReadRequest(bufio.NewReader(c))
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))
		if req.Header.Get("Proxy-Authorization") != want {
			_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
	}
	p := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080}
	_, err := pipeConnector(script).Open(context.Background(), p, destination())
	if err == nil {
		t.Fatal("expected auth failure")
	}
	p.Credentials = &model.Credentials{Username: "u", Password: "p"}
	got, err := pipeConnector(script).Open(context.Background(), p, destination())
	if err != nil {
		t.Fatal(err)
	}
	got.Conn.Close()
}

func TestHTTPAuthenticationClassification(t *testing.T) {
	response := func(challenge string) *http.Response {
		h := make(http.Header)
		if challenge != "" {
			h.Add("Proxy-Authenticate", challenge)
		}
		return &http.Response{StatusCode: http.StatusProxyAuthRequired, Header: h}
	}
	tests := []struct {
		name      string
		supplied  bool
		challenge string
		code      string
	}{
		{"missing", false, "Basic realm=provider", "proxy_auth_required"},
		{"rejected", true, "Basic realm=provider", "proxy_auth_rejected"},
		{"unsupported", true, "Digest realm=provider", "proxy_auth_unsupported"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var pe *Error
			if !errors.As(HTTPProxyAuthError(response(tc.challenge), tc.supplied), &pe) || pe.Code != tc.code {
				t.Fatalf("got %+v", pe)
			}
			if strings.Contains(pe.Detail, "realm") {
				t.Fatalf("challenge details leaked: %q", pe.Detail)
			}
		})
	}
}

func TestSOCKS4ARemoteDNSBlockedByDefault(t *testing.T) {
	c := pipeConnector(socks4Script)
	c.AllowRemoteDNS = false
	p := model.Proxy{Protocol: model.ProtocolSOCKS4A, Host: "proxy", Port: 1080}
	_, err := c.Open(context.Background(), p, destination())
	pe, ok := err.(*Error)
	if !ok || pe.Code != "remote_dns_disabled" {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestCancellationInterruptsHandshake(t *testing.T) {
	c := pipeConnector(func(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.Open(ctx, model.Proxy{Protocol: model.ProtocolSOCKS5, Host: "proxy", Port: 1080}, destination())
		done <- err
	}()
	time.Sleep(5 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cancellation did not interrupt handshake")
	}
}

func TestMalformedAndRejectedReplies(t *testing.T) {
	p := model.Proxy{Protocol: model.ProtocolSOCKS5, Host: "proxy", Port: 1080}
	bad := pipeConnector(func(c net.Conn) { b := make([]byte, 3); _, _ = io.ReadFull(c, b); _, _ = c.Write([]byte{4, 0}) })
	_, err := bad.Open(context.Background(), p, destination())
	pe, ok := err.(*Error)
	if !ok || pe.Code != "socks5_bad_version" {
		t.Fatalf("unexpected %v", err)
	}
	p.Protocol = model.ProtocolHTTP
	rejected := pipeConnector(func(c net.Conn) {
		_, _ = http.ReadRequest(bufio.NewReader(c))
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
	})
	_, err = rejected.Open(context.Background(), p, destination())
	pe, ok = err.(*Error)
	if !ok || pe.Code != "connect_upstream_error" || pe.Status != model.StatusInconclusive {
		t.Fatalf("unexpected %v", err)
	}
}

func TestConnectPreservesPrefetchedTunnelBytes(t *testing.T) {
	script := func(c net.Conn) {
		_, _ = http.ReadRequest(bufio.NewReader(c))
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\nprefetch")
	}
	p := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80}
	got, err := pipeConnector(script).Open(context.Background(), p, destination())
	if err != nil {
		t.Fatal(err)
	}
	defer got.Conn.Close()
	b := make([]byte, 8)
	if _, err := io.ReadFull(got.Conn, b); err != nil || string(b) != "prefetch" {
		t.Fatalf("got=%q err=%v", b, err)
	}
}

func TestConnectRejectsOversizedHeaders(t *testing.T) {
	script := func(c net.Conn) {
		_, _ = http.ReadRequest(bufio.NewReader(c))
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nX-Large: "+strings.Repeat("x", 70<<10)+"\r\n\r\n")
	}
	p := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80}
	_, err := pipeConnector(script).Open(context.Background(), p, destination())
	pe, ok := err.(*Error)
	if !ok || pe.Code != "invalid_connect_response" {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestProxyDNSClassification(t *testing.T) {
	c := Connector{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.DNSError{Err: "not found", Name: "proxy.invalid"}
	}}
	_, err := c.Open(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.invalid", Port: 80}, destination())
	pe, ok := err.(*Error)
	if !ok || pe.Code != "proxy_dns" {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestNetworkErrorClassification(t *testing.T) {
	tests := []struct {
		err    error
		status model.Status
		code   string
	}{
		{context.Canceled, model.StatusInterrupted, "interrupted"},
		{syscall.ECONNREFUSED, model.StatusFailed, "connection_refused"},
		{syscall.ENETUNREACH, model.StatusFailed, "network_unreachable"},
		{syscall.EHOSTUNREACH, model.StatusFailed, "host_unreachable"},
	}
	for _, tc := range tests {
		var pe *Error
		if !errors.As(classifyNet(model.StageConnect, "proxy_connect", tc.err), &pe) || pe.Status != tc.status || pe.Code != tc.code {
			t.Fatalf("err=%v got=%+v", tc.err, pe)
		}
	}
}

func TestHTTPConnectAuthorityMode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remote bool
		want   string
	}{{"pinned", false, "1.1.1.1:443"}, {"proxy_dns", true, "target.test:443"}} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan string, 1)
			script := func(c net.Conn) {
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				seen <- req.Host
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
			}
			connector := pipeConnector(script)
			connector.AllowRemoteDNS = tc.remote
			p := model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80}
			got, err := connector.Open(context.Background(), p, destination())
			if err != nil {
				t.Fatal(err)
			}
			got.Conn.Close()
			if authority := <-seen; authority != tc.want {
				t.Fatalf("got %q want %q", authority, tc.want)
			}
		})
	}
}

func TestSOCKS5DestinationAddressMode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remote bool
		atyp   byte
		value  string
	}{{"pinned", false, 1, "1.1.1.1"}, {"proxy_dns", true, 3, "target.test"}} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan string, 1)
			script := func(c net.Conn) {
				br := bufio.NewReader(c)
				greeting := make([]byte, 3)
				_, _ = io.ReadFull(br, greeting)
				_, _ = c.Write([]byte{5, 0})
				head := make([]byte, 4)
				_, _ = io.ReadFull(br, head)
				if head[3] != tc.atyp {
					seen <- "wrong-atyp"
					return
				}
				var host string
				if head[3] == 1 {
					b := make([]byte, 4)
					_, _ = io.ReadFull(br, b)
					host = net.IP(b).String()
				} else {
					n, _ := br.ReadByte()
					b := make([]byte, int(n))
					_, _ = io.ReadFull(br, b)
					host = string(b)
				}
				port := make([]byte, 2)
				_, _ = io.ReadFull(br, port)
				seen <- host
				_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
			}
			connector := pipeConnector(script)
			connector.AllowRemoteDNS = tc.remote
			got, err := connector.Open(context.Background(), model.Proxy{Protocol: model.ProtocolSOCKS5, Host: "proxy", Port: 1080}, destination())
			if err != nil {
				t.Fatal(err)
			}
			_ = got.Conn.Close()
			if value := <-seen; value != tc.value {
				t.Fatalf("got %q want %q", value, tc.value)
			}
		})
	}
}
