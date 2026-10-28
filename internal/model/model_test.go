package model

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialIdentityAndSafeURI(t *testing.T) {
	a := Proxy{Protocol: ProtocolHTTP, Host: "host", Port: 80, Credentials: &Credentials{Username: "u", Password: "one"}}
	b := a
	b.Credentials = &Credentials{Username: "u", Password: "two"}
	if a.Key() != b.Key() {
		t.Fatal("public endpoint identity must not depend on credentials")
	}
	var secret [32]byte
	copy(secret[:], "test-only-deduplication-key")
	if a.DedupIdentity(secret[:]) == b.DedupIdentity(secret[:]) {
		t.Fatal("credential variants were not distinguished for in-process deduplication")
	}
	if strings.Contains(a.SafeURI(), "one") || strings.Contains(a.SafeURI(), "u") || !strings.Contains(a.SafeURI(), "***:***") {
		t.Fatal("password exposed")
	}
}
func TestProtocolValidation(t *testing.T) {
	if _, err := ParseProtocol("SOCKS5"); err != nil {
		t.Fatal(err)
	}
	if p, err := ParseProtocol("HTTPS"); err != nil || p != ProtocolHTTPS {
		t.Fatalf("HTTPS parse: %q %v", p, err)
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
	if p.Identity() != q.Identity() {
		t.Fatal("public identity leaked credential-dependent information")
	}
	var secret [32]byte
	copy(secret[:], "test-only-deduplication-key")
	if p.DedupIdentity(secret[:]) == q.DedupIdentity(secret[:]) {
		t.Fatal("deduplication identity ignored credentials")
	}
}

func TestDedupIdentityMatchesHMAC(t *testing.T) {
	p := Proxy{Protocol: ProtocolHTTP, Host: "Proxy.Test", Port: 8080, Credentials: &Credentials{Username: "user", Password: "pass"}}
	key := []byte("deduplication-key")
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("http\x00proxy.test\x008080\x00user\x00pass"))
	var expected [16]byte
	copy(expected[:], mac.Sum(nil)[:16])
	if actual := p.DedupIdentity(key); actual != expected {
		t.Fatalf("actual=%x expected=%x", actual, expected)
	}
}
