package policy

import (
	"context"
	"net/netip"
	"testing"
)

type resolver struct{ ips []netip.Addr }

func (r resolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.ips, nil
}
func TestPolicyBlocksUnsafeAndRebindingSet(t *testing.T) {
	p := New(false, []string{"allowed.test"})
	p.Resolver = resolver{[]netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")}}
	if _, err := p.Resolve(context.Background(), "https://allowed.test/"); err == nil {
		t.Fatal("expected mixed resolution block")
	}
}
func TestPolicyAllowlist(t *testing.T) {
	p := New(false, []string{"allowed.test"})
	p.Resolver = resolver{[]netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	if _, err := p.Resolve(context.Background(), "https://other.test/"); err == nil {
		t.Fatal("expected allowlist block")
	}
	if _, err := p.Resolve(context.Background(), "file:///etc/passwd"); err == nil {
		t.Fatal("expected scheme block")
	}
}
func TestUnsafeRanges(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fc00::1", "2001:db8::1"} {
		if !IsUnsafe(netip.MustParseAddr(s)) {
			t.Errorf("not blocked: %s", s)
		}
	}
	if IsUnsafe(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public IP blocked")
	}
}

func TestInvalidDestinationPort(t *testing.T) {
	p := New(false, []string{"allowed.test"})
	p.Resolver = resolver{[]netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	if _, err := p.Resolve(context.Background(), "https://allowed.test:99999/"); err == nil {
		t.Fatal("invalid port accepted")
	}
}
