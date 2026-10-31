package metadata

import (
	"compress/gzip"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/drag-team/netvex/internal/model"
)

func TestLoadAndLongestPrefixLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.csv.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	data := "prefix,country_code,country,city,asn,organization,network_type\n0.0.0.0/0,ZZ,Unknown,,0,Unknown,unknown\n8.8.8.0/24,US,United States,Mountain View,15169,Google,datacenter\n2001:db8::/32,ES,Spain,Madrid,AS64500,Example ISP,residential\n"
	if _, err := zw.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := LoadCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Records() != 3 {
		t.Fatalf("records=%d", p.Records())
	}
	entry, ok := p.Lookup("8.8.8.8")
	if !ok || entry.CountryCode != "US" || entry.ASN != "AS15169" || entry.NetworkType != "datacenter" {
		t.Fatalf("entry=%+v ok=%v", entry, ok)
	}
	entry, ok = p.Lookup("2001:db8::1")
	if !ok || entry.City != "Madrid" || entry.NetworkType != "residential" {
		t.Fatalf("entry=%+v ok=%v", entry, ok)
	}
}

func TestRejectsInvalidMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.csv")
	if err := os.WriteFile(path, []byte("country,asn\nUS,1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCSV(path); err == nil {
		t.Fatal("accepted CSV without prefix")
	}
	if err := os.WriteFile(path, []byte("prefix,country_code\ninvalid,USA\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCSV(path); err == nil {
		t.Fatal("accepted invalid prefix")
	}
	if err := os.WriteFile(path, []byte("prefix,country_code\n192.0.2.0/24,U1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCSV(path); err == nil {
		t.Fatal("accepted non-letter country code")
	}
	if err := os.WriteFile(path, []byte("prefix,PREFIX\n192.0.2.0/24,US\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCSV(path); err == nil {
		t.Fatal("accepted duplicate normalized headers")
	}
}

func BenchmarkLookupIPv4(b *testing.B) {
	p := &Provider{v4: make(map[prefixKey]model.ExitMetadata), v6: make(map[prefixKey]model.ExitMetadata)}
	prefix := netip.MustParsePrefix("8.8.8.0/24")
	p.v4[prefixKey{address: prefix.Addr(), bits: 24}] = model.ExitMetadata{CountryCode: "US", ASN: "AS15169"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := p.Lookup("8.8.8.8"); !ok {
			b.Fatal("lookup failed")
		}
	}
}
