package input

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/drag-team/relayprobe/internal/model"
)

func TestParseProxyAndRedaction(t *testing.T) {
	p, err := ParseProxy("socks5://user:p%40ss@[2001:db8::1]:1080", model.ProtocolHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if p.Protocol != model.ProtocolSOCKS5 || p.Host != "2001:db8::1" || p.Credentials.Password != "p@ss" {
		t.Fatalf("unexpected proxy: %#v", p)
	}
	if got := p.SafeURI(); strings.Contains(got, "p@ss") || !strings.Contains(got, "***") {
		t.Fatalf("credential leak: %s", got)
	}
}

func TestCommercialHostPortUserPasswordFormat(t *testing.T) {
	p, err := ParseProxy("1.2.3.4:8080:customer-zone-us:pa@ss", model.ProtocolHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	if p.Protocol != model.ProtocolHTTPS || p.Host != "1.2.3.4" || p.Port != 8080 || p.Credentials == nil || p.Credentials.Username != "customer-zone-us" || p.Credentials.Password != "pa@ss" {
		t.Fatalf("unexpected proxy: %#v", p)
	}
	if p.FullURI() != "https://customer-zone-us:pa%40ss@1.2.3.4:8080" || strings.Contains(p.SafeURI(), "pa@ss") {
		t.Fatalf("unsafe normalization: safe=%q full=%q", p.SafeURI(), p.FullURI())
	}
}

func TestParseRejectsAmbiguousCredentials(t *testing.T) {
	cases := []string{"host:80/path", "http://user@host:80", "http://host:0", "ftp://host:21"}
	for _, s := range cases {
		if _, err := ParseProxy(s, model.ProtocolHTTP); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestUnprefixedEndpointFastPath(t *testing.T) {
	for _, test := range []struct {
		raw  string
		host string
	}{
		{"Proxy.Example.:3128", "proxy.example"},
		{"192.0.2.10:8080", "192.0.2.10"},
		{"[2001:db8::1]:1080", "2001:db8::1"},
	} {
		proxy, err := ParseProxy(test.raw, model.ProtocolSOCKS5)
		if err != nil {
			t.Fatalf("%q: %v", test.raw, err)
		}
		if proxy.Protocol != model.ProtocolSOCKS5 || proxy.Host != test.host {
			t.Fatalf("%q: %+v", test.raw, proxy)
		}
	}
	if _, err := ParseProxy("[fe80::1%25eth0]:1080", model.ProtocolSOCKS5); err == nil {
		t.Fatal("accepted a scoped proxy address")
	}
}

func TestRejectedCredentialIsRedacted(t *testing.T) {
	got := redactRaw("user:verysecret@bad")
	if strings.Contains(got, "verysecret") || !strings.Contains(got, "***") {
		t.Fatalf("leaked: %s", got)
	}
}

func TestRejectedLegacyCredentialsAreRedacted(t *testing.T) {
	got := redactRaw("user:very-secret:proxy.test:8080")
	if strings.Contains(got, "very-secret") {
		t.Fatalf("credential leaked: %q", got)
	}
}

func TestStreamingTextDedupAndLimit(t *testing.T) {
	p := New(Options{Format: FormatText, DefaultProtocol: model.ProtocolHTTP, MaxBytes: 100, Deduplicate: true})
	var got []model.Proxy
	err := p.Emit(strings.NewReader("# c\nexample.com:80\nexample.com:80\nbad\n"), func(x model.Proxy) error { got = append(got, x); return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || p.Stats.Read != 3 || p.Stats.Duplicates != 1 || p.Stats.Rejected != 1 {
		t.Fatalf("got=%d stats=%+v", len(got), p.Stats)
	}
	q := New(Options{Format: FormatText, DefaultProtocol: model.ProtocolHTTP, MaxBytes: 3})
	if err := q.Emit(strings.NewReader("host:80"), func(model.Proxy) error { return nil }, nil); err == nil {
		t.Fatal("expected size error")
	}
}

func TestDedupDistinguishesCredentialVariants(t *testing.T) {
	p := New(Options{Format: FormatText, DefaultProtocol: model.ProtocolHTTP, Deduplicate: true})
	var got []model.Proxy
	input := "proxy.test:8080:user:one\nproxy.test:8080:user:two\nproxy.test:8080:user:one\n"
	if err := p.Emit(strings.NewReader(input), func(proxy model.Proxy) error {
		got = append(got, proxy)
		return nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || p.Stats.Duplicates != 1 {
		t.Fatalf("got=%d stats=%+v", len(got), p.Stats)
	}
}

func TestCSVAndJSON(t *testing.T) {
	for _, tc := range []struct {
		f Format
		s string
	}{{FormatCSV, "host,port\nexample.com,80\n"}, {FormatJSON, `["socks4://127.0.0.1:1080",{"protocol":"http","host":"example.com","port":8080}]`}} {
		p := New(Options{Format: tc.f, DefaultProtocol: model.ProtocolHTTP, MaxBytes: 1000})
		n := 0
		if err := p.Emit(strings.NewReader(tc.s), func(model.Proxy) error { n++; return nil }, nil); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("no records")
		}
	}
}

func TestCommercialCSVColumns(t *testing.T) {
	p := New(Options{Format: FormatCSV, DefaultProtocol: model.ProtocolHTTP, MaxBytes: 1000})
	var got []model.Proxy
	data := "password,ip,protocol,port,username\npa@ss,1.2.3.4,https,8443,customer-zone-us\n"
	if err := p.Emit(strings.NewReader(data), func(proxy model.Proxy) error {
		got = append(got, proxy)
		return nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Protocol != model.ProtocolHTTPS || got[0].Host != "1.2.3.4" || got[0].Port != 8443 || got[0].Credentials == nil || got[0].Credentials.Password != "pa@ss" {
		t.Fatalf("unexpected CSV proxy: %+v", got)
	}
	if !strings.Contains(got[0].SafeURI(), "***:***") || strings.Contains(got[0].SafeURI(), "customer-zone-us") || strings.Contains(got[0].SafeURI(), "pa@ss") {
		t.Fatalf("credential leak: %s", got[0].SafeURI())
	}
}

func TestJSONRejectsTrailingValues(t *testing.T) {
	p := New(Options{Format: FormatJSON, DefaultProtocol: model.ProtocolHTTP})
	err := p.Emit(strings.NewReader(`["proxy.test:80"] true`), func(model.Proxy) error { return nil }, nil)
	if err == nil {
		t.Fatal("accepted trailing JSON value")
	}
}

func TestJSONObjectCredentials(t *testing.T) {
	p := New(Options{Format: FormatJSON, DefaultProtocol: model.ProtocolHTTP})
	var got model.Proxy
	err := p.Emit(strings.NewReader(`[{"protocol":"socks5","host":"proxy.test","port":1080,"username":"user","password":"p@ss"}]`), func(proxy model.Proxy) error {
		got = proxy
		return nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Credentials == nil || got.Credentials.Username != "user" || got.Credentials.Password != "p@ss" || got.Protocol != model.ProtocolSOCKS5 {
		t.Fatalf("proxy=%+v", got)
	}
}

func TestAggregateEntryLimit(t *testing.T) {
	p := New(Options{Format: FormatText, DefaultProtocol: model.ProtocolHTTP, MaxBytes: 1000, MaxEntries: 1})
	err := p.Emit(strings.NewReader("one.test:80\ntwo.test:80\n"), func(model.Proxy) error { return nil }, nil)
	if err == nil || !strings.Contains(err.Error(), "1-entry") || p.Stats.Accepted != 1 {
		t.Fatalf("stats=%+v err=%v", p.Stats, err)
	}
}

func TestAutoFormatAndSourceLabels(t *testing.T) {
	p := New(Options{Format: FormatAuto, DefaultProtocol: model.ProtocolHTTP, MaxBytes: 1000, Deduplicate: true})
	var got []model.Proxy
	if err := p.EmitSource(strings.NewReader("host,port\nproxy.test,8080\n"), FormatAuto, "list.csv", func(x model.Proxy) error {
		got = append(got, x)
		return nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := p.EmitSource(strings.NewReader(` ["socks5://proxy.test:1080"] `), FormatAuto, "stdin", func(x model.Proxy) error {
		got = append(got, x)
		return nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Source != "list.csv" || got[1].Source != "stdin" || got[1].Protocol != model.ProtocolSOCKS5 {
		t.Fatalf("got=%+v", got)
	}
}

func TestGzipAutoFormatAndAggregateLimit(t *testing.T) {
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write([]byte("host,port\nproxy.test,8080\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	reader, closer, err := MaybeDecompress(bytes.NewReader(compressed.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	p := New(Options{Format: FormatAuto, DefaultProtocol: model.ProtocolHTTP, MaxBytes: 100})
	var got []model.Proxy
	if err := p.EmitSource(reader, FormatAuto, "list.csv.gz", func(x model.Proxy) error {
		got = append(got, x)
		return nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Host != "proxy.test" || got[0].Port != 8080 {
		t.Fatalf("got=%+v", got)
	}

	q := New(Options{Format: FormatText, DefaultProtocol: model.ProtocolHTTP, MaxBytes: 15})
	if err := q.EmitSource(strings.NewReader("a.test:80\n"), FormatText, "a.txt", func(model.Proxy) error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	if err := q.EmitSource(strings.NewReader("b.test:80\n"), FormatText, "b.txt", func(model.Proxy) error { return nil }, nil); err == nil || !strings.Contains(err.Error(), "aggregate limit") {
		t.Fatalf("err=%v", err)
	}
}

func TestMaybeDecompressPlainAndMalformed(t *testing.T) {
	reader, closer, err := MaybeDecompress(strings.NewReader("proxy.test:80\n"))
	if err != nil || closer != nil {
		t.Fatalf("closer=%v err=%v", closer, err)
	}
	b, err := io.ReadAll(reader)
	if err != nil || string(b) != "proxy.test:80\n" {
		t.Fatalf("data=%q err=%v", b, err)
	}
	if _, _, err := MaybeDecompress(bytes.NewReader([]byte{0x1f, 0x8b, 0x00})); err == nil {
		t.Fatal("accepted malformed gzip stream")
	}
}

func TestJSONLAndRedactedCredentialRejection(t *testing.T) {
	p := New(Options{Format: FormatJSONL, DefaultProtocol: model.ProtocolHTTP, MaxBytes: 1000})
	var got []model.Proxy
	var rejected []Rejection
	data := "{\"proxy\":\"http://proxy.test:8080\"}\n{\"proxy\":\"http://user:***@proxy.test:8081\"}\n"
	if err := p.Emit(strings.NewReader(data), func(x model.Proxy) error {
		got = append(got, x)
		return nil
	}, func(r Rejection) { rejected = append(rejected, r) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(rejected) != 1 || !strings.Contains(rejected[0].Reason, "redacted") {
		t.Fatalf("got=%+v rejected=%+v", got, rejected)
	}
}

func FuzzParseProxy(f *testing.F) {
	for _, s := range []string{"127.0.0.1:80", "1.2.3.4:8080:user:password", "https://u:p@host:8443", "socks5://u:p@host:1080", "http://[::1]:8080", "user:secret@bad", "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseProxy(s, model.ProtocolHTTP)
		if err == nil {
			if p.Host == "" || p.Port == 0 {
				t.Fatalf("invalid accepted value: %#v", p)
			}
			if p.Credentials != nil {
				safe, parseErr := url.Parse(p.SafeURI())
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				password, ok := safe.User.Password()
				if !ok || password != "***" {
					t.Fatalf("password not redacted: %q", p.SafeURI())
				}
			}
		}
	})
}

func BenchmarkParserText(b *testing.B) {
	data := benchmarkDataset(1000)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p := New(Options{Format: FormatText, DefaultProtocol: model.ProtocolHTTP, MaxBytes: int64(len(data) + 1), Deduplicate: true})
		if err := p.Emit(bytes.NewReader(data), func(model.Proxy) error { return nil }, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParserTextNoDeduplicate(b *testing.B) {
	data := benchmarkDataset(1000)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p := New(Options{Format: FormatText, DefaultProtocol: model.ProtocolHTTP, MaxBytes: int64(len(data) + 1)})
		if err := p.Emit(bytes.NewReader(data), func(model.Proxy) error { return nil }, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParserGzip(b *testing.B) {
	data := benchmarkDataset(1000)
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(data); err != nil {
		b.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		b.Fatal(err)
	}
	payload := append([]byte(nil), compressed.Bytes()...)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reader, closer, err := MaybeDecompress(bytes.NewReader(payload))
		if err != nil {
			b.Fatal(err)
		}
		p := New(Options{Format: FormatAuto, DefaultProtocol: model.ProtocolHTTP, MaxBytes: int64(len(data) + 1), Deduplicate: true})
		if err := p.EmitSource(reader, FormatAuto, "proxies.txt.gz", func(model.Proxy) error { return nil }, nil); err != nil {
			b.Fatal(err)
		}
		if err := closer.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkDataset(count int) []byte {
	var data strings.Builder
	for i := 0; i < count; i++ {
		data.WriteString("proxy")
		data.WriteString(strconv.Itoa(i))
		data.WriteString(".test:8080\n")
	}
	return []byte(data.String())
}
