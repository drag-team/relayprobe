package input

import (
	"net/url"
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

func TestParseRejectsAmbiguousCredentials(t *testing.T) {
	cases := []string{"host:80/path", "http://user@host:80", "http://host:0", "ftp://host:21"}
	for _, s := range cases {
		if _, err := ParseProxy(s, model.ProtocolHTTP); err == nil {
			t.Errorf("accepted %q", s)
		}
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

func TestJSONRejectsTrailingValues(t *testing.T) {
	p := New(Options{Format: FormatJSON, DefaultProtocol: model.ProtocolHTTP})
	err := p.Emit(strings.NewReader(`["proxy.test:80"] true`), func(model.Proxy) error { return nil }, nil)
	if err == nil {
		t.Fatal("accepted trailing JSON value")
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
	for _, s := range []string{"127.0.0.1:80", "socks5://u:p@host:1080", "http://[::1]:8080", "user:secret@bad", "\x00"} {
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
