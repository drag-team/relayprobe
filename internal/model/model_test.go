package model

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialIdentityAndSafeURI(t *testing.T) {
	a := Proxy{Protocol: ProtocolHTTP, Host: "host", Port: 80, Credentials: &Credentials{Username: "u", Password: "one"}}
	b := a
	b.Credentials = &Credentials{Username: "u", Password: "two"}
	if a.Key() == b.Key() {
		t.Fatal("credential variants deduplicated")
	}
	if strings.Contains(a.SafeURI(), "one") || !strings.Contains(a.SafeURI(), "***") {
		t.Fatal("password exposed")
	}
}
func TestProtocolValidation(t *testing.T) {
	if _, err := ParseProtocol("SOCKS5"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseProtocol("ftp"); err == nil {
		t.Fatal("unsupported protocol accepted")
	}
}

func TestCredentialExportIsExplicitOnly(t *testing.T) {
	p := Proxy{Protocol: ProtocolHTTP, Host: "host", Port: 80, Credentials: &Credentials{Username: "u", Password: "p@ss"}}
	if got := p.FullURI(); !strings.Contains(got, "p%40ss") {
		t.Fatalf("bad full URI: %s", got)
	}
	b, err := json.Marshal(Result{Proxy: p.SafeURI(), InputProxy: p.FullURI()})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "p%40ss") {
		t.Fatalf("transient secret marshaled: %s", b)
	}
}

func TestBinaryIdentityMatchesPublicKey(t *testing.T) {
	p := Proxy{Protocol: ProtocolHTTP, Host: "proxy.test", Port: 8080, Credentials: &Credentials{Username: "u", Password: "p"}}
	id := p.Identity()
	if p.Key() != hex.EncodeToString(id[:]) {
		t.Fatal("key and identity differ")
	}
	q := p
	q.Credentials = &Credentials{Username: "u", Password: "different"}
	if p.Identity() == q.Identity() {
		t.Fatal("credentials were not included in identity")
	}
}
