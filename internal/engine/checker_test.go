package engine

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/drag-team/relayprobe/internal/config"
	"github.com/drag-team/relayprobe/internal/model"
)

type fixedResolver struct {
	ips   []netip.Addr
	calls *atomic.Int64
}

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	if r.calls != nil {
		r.calls.Add(1)
	}
	return r.ips, nil
}

type failingResolver struct{}

func (failingResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errors.New("resolver unavailable")
}

func pipeDial(script func(net.Conn)) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { defer server.Close(); script(server) }()
		return client, nil
	}
}

func baseChecker(target string) *Checker {
	cfg := config.Defaults()
	cfg.Targets = []string{target}
	cfg.AllowedHosts = []string{"target.test"}
	cfg.Repeat = 1
	cfg.RequestTimeout = time.Second
	cfg.ConnectTimeout = 500 * time.Millisecond
	cfg.RetryBackoff = 0
	c := NewChecker(cfg)
	c.Policy.Resolver = fixedResolver{ips: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	return c
}

func TestHTTPValidationAndIntelligence(t *testing.T) {
	c := baseChecker("http://target.test/echo")
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		br := bufio.NewReader(conn)
		connectReq, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if connectReq.Method != "CONNECT" || connectReq.Host != "1.1.1.1:80" {
			t.Errorf("CONNECT host=%q", connectReq.Host)
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Host != "target.test" || req.URL.Path != "/echo" {
			t.Errorf("host=%q url=%q", req.Host, req.URL.String())
		}
		body := `{"origin":"8.8.8.8","headers":{"X-Forwarded-For":"192.0.2.1"}}`
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "+itoa(len(body))+"\r\n\r\n"+body)
	})
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy.test", Port: 8080})
	if r.Status != model.StatusOK || r.Successes != 1 {
		t.Fatalf("%+v", r)
	}
	o := r.Observations[0]
	if o.ExitIP != "8.8.8.8" || o.Anonymity != "apparently_non_anonymous" || len(o.ForwardingEvidence) != 1 {
		t.Fatalf("%+v", o)
	}
}

func TestOptInForwardHTTP(t *testing.T) {
	c := baseChecker("http://target.test/path")
	c.Config.AllowRemoteDNS = true
	c.Connector.AllowRemoteDNS = true
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		if req.Method != "GET" || req.URL.Host != "target.test" {
			t.Errorf("not absolute-form: %s %s", req.Method, req.URL.String())
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	})
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080})
	if r.Status != model.StatusOK {
		t.Fatalf("%+v", r.Observations)
	}
}

func TestHTTPSConnectAndVerifiedTLS(t *testing.T) {
	cert, roots := testCertificate(t)
	c := baseChecker("https://target.test/")
	c.TLSConfig = &tls.Config{RootCAs: roots}
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != "CONNECT" {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		if server.Handshake() != nil {
			return
		}
		r, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			return
		}
		if r.Host != "target.test" {
			t.Errorf("unexpected SNI request host %s", r.Host)
		}
		_, _ = io.WriteString(server, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	})
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 8080})
	if r.Status != model.StatusOK {
		t.Fatalf("%+v", r.Observations)
	}
}

func TestRedirectToUnapprovedHostBlocked(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		br := bufio.NewReader(conn)
		_, _ = http.ReadRequest(br)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, _ = http.ReadRequest(br)
		_, _ = io.WriteString(conn, "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/admin\r\nContent-Length: 0\r\n\r\n")
	})
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80})
	o := r.Observations[0]
	if o.Status != model.StatusPolicyBlock || o.Code != "redirect_blocked" {
		t.Fatalf("%+v", o)
	}
}

func TestConnectTimeoutClassification(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.RequestTimeout = 30 * time.Millisecond
	c.Connector.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80})
	if r.Status != model.StatusTimeout {
		t.Fatalf("%+v", r)
	}
}

func TestDestinationDNSClassification(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Policy.Resolver = failingResolver{}
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80})
	o := r.Observations[0]
	if o.Status != model.StatusInconclusive || o.Stage != model.StageResolve || o.Code != "destination_dns" {
		t.Fatalf("%+v", o)
	}
}

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "target.test"}, DNSNames: []string{"target.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return cert, pool
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 10)
	for n > 0 {
		b = append(b, byte('0'+n%10))
		n /= 10
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

type countingProcessor struct {
	active, max atomic.Int64
	gate        chan struct{}
}

func (p *countingProcessor) Check(ctx context.Context, x model.Proxy) model.Result {
	n := p.active.Add(1)
	for {
		m := p.max.Load()
		if n <= m || p.max.CompareAndSwap(m, n) {
			break
		}
	}
	select {
	case <-p.gate:
	case <-ctx.Done():
	}
	p.active.Add(-1)
	return model.Result{Status: model.StatusOK}
}
func TestEngineBoundsConcurrencyAndCancellation(t *testing.T) {
	p := &countingProcessor{gate: make(chan struct{})}
	jobs := make(chan model.Proxy, 20)
	for i := 0; i < 20; i++ {
		jobs <- model.Proxy{}
	}
	close(jobs)
	ctx, cancel := context.WithCancel(context.Background())
	out := Engine{Workers: 3, QueueSize: 2, Processor: p}.Run(ctx, jobs)
	time.Sleep(10 * time.Millisecond)
	if p.max.Load() != 3 {
		t.Fatalf("max=%d", p.max.Load())
	}
	cancel()
	for range out {
	}
	if p.active.Load() != 0 {
		t.Fatal("workers did not exit")
	}
}

func TestRateLimiter(t *testing.T) {
	c := NewChecker(config.Defaults())
	c.Config.RateLimit = 100
	start := time.Now()
	for i := 0; i < 3; i++ {
		if !c.waitRate(context.Background()) {
			t.Fatal("unexpected cancellation")
		}
	}
	if time.Since(start) < 18*time.Millisecond {
		t.Fatalf("rate limiter ran too quickly: %s", time.Since(start))
	}
}

func TestCanceledRateWaitDoesNotReserveFutureSlots(t *testing.T) {
	c := NewChecker(config.Defaults())
	c.Config.RateLimit = 1
	if !c.waitRate(context.Background()) {
		t.Fatal("initial token failed")
	}
	reserved := c.nextStart
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 20; i++ {
		if c.waitRate(ctx) {
			t.Fatal("canceled waiter received a token")
		}
	}
	if !c.nextStart.Equal(reserved) {
		t.Fatalf("canceled waiters moved next slot: %s -> %s", reserved, c.nextStart)
	}
}

func TestDestinationResolutionCachedAcrossAttempts(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.Repeat = 4
	var calls atomic.Int64
	c.Policy.Resolver = fixedResolver{ips: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, calls: &calls}
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		br := bufio.NewReader(conn)
		_, _ = http.ReadRequest(br)
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
	})
	c.Config.RetryPermanent = true
	_ = c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80})
	if calls.Load() != 1 {
		t.Fatalf("DNS calls=%d want 1", calls.Load())
	}
}

func TestPermanentFailuresStopEarlyUnlessRequested(t *testing.T) {
	for _, retry := range []bool{false, true} {
		c := baseChecker("http://target.test/")
		c.Config.Repeat = 4
		c.Config.RetryPermanent = retry
		c.Connector.DialContext = pipeDial(func(conn net.Conn) {
			_, _ = http.ReadRequest(bufio.NewReader(conn))
			_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		})
		r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80})
		want := 1
		if retry {
			want = 3
		}
		if r.Attempts != want || r.Status != model.StatusAuthFailed {
			t.Fatalf("retry=%v attempts=%d status=%s", retry, r.Attempts, r.Status)
		}
	}
}

func TestStopOnSuccess(t *testing.T) {
	c := baseChecker("http://target.test/")
	c.Config.Repeat = 5
	c.Config.StopOnSuccess = true
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		br := bufio.NewReader(conn)
		_, _ = http.ReadRequest(br)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, _ = http.ReadRequest(br)
		_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	})
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80})
	if r.Attempts != 3 || r.Successes != 3 || r.RequiredSuccesses != 3 || r.Status != model.StatusOK {
		t.Fatalf("%+v", r)
	}
}

func TestReliabilityThresholdAndEarlyImpossibility(t *testing.T) {
	c := baseChecker("http://target.test/private?token=secret")
	c.Config.Repeat = 5
	c.Config.MinSuccessRate = 0.8
	c.Config.RetryPermanent = true
	var calls atomic.Int64
	c.Connector.DialContext = pipeDial(func(conn net.Conn) {
		br := bufio.NewReader(conn)
		_, _ = http.ReadRequest(br)
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			_, _ = http.ReadRequest(br)
			_, _ = io.WriteString(conn, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
	})
	r := c.Check(context.Background(), model.Proxy{Protocol: model.ProtocolHTTP, Host: "proxy", Port: 80})
	if r.Status != model.StatusUnreliable || r.Successes != 1 || r.RequiredSuccesses != 4 || r.Attempts != 3 {
		t.Fatalf("%+v", r)
	}
	for _, ob := range r.Observations {
		if ob.Target != "http://target.test/" || strings.Contains(ob.Target, "secret") {
			t.Fatalf("unsafe target persisted: %q", ob.Target)
		}
	}
}
