package metadata

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	inputpkg "github.com/drag-team/netvex/internal/input"
	"github.com/drag-team/netvex/internal/model"
)

const (
	MaxDatabaseBytes = 256 << 20
	MaxRecords       = 2_000_000
)

type prefixKey struct {
	address netip.Addr
	bits    uint8
}

type Provider struct {
	v4      map[prefixKey]model.ExitMetadata
	v6      map[prefixKey]model.ExitMetadata
	records int
}

func LoadCSV(path string) (*Provider, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open metadata database: %w", err)
	}
	defer f.Close()
	reader, compressed, err := inputpkg.MaybeDecompress(f)
	if err != nil {
		return nil, err
	}
	if compressed != nil {
		defer compressed.Close()
	}
	limited := &io.LimitedReader{R: reader, N: MaxDatabaseBytes + 1}
	cr := csv.NewReader(limited)
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("read metadata header: %w", err)
	}
	columns := make(map[string]int, len(header))
	for i, name := range header {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || len(name) > 64 || strings.ContainsAny(name, "\r\n\x00") {
			return nil, errors.New("metadata CSV contains an invalid header name")
		}
		if _, exists := columns[name]; exists {
			return nil, fmt.Errorf("metadata CSV contains duplicate column %q", name)
		}
		columns[name] = i
	}
	if _, ok := columns["prefix"]; !ok {
		return nil, errors.New("metadata CSV requires a prefix column")
	}
	p := &Provider{v4: make(map[prefixKey]model.ExitMetadata), v6: make(map[prefixKey]model.ExitMetadata)}
	for line := 2; ; line++ {
		record, readErr := cr.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read metadata record %d: %w", line, readErr)
		}
		if p.records >= MaxRecords {
			return nil, fmt.Errorf("metadata database exceeds %d records", MaxRecords)
		}
		prefix, parseErr := netip.ParsePrefix(field(record, columns, "prefix"))
		if parseErr != nil {
			return nil, fmt.Errorf("metadata record %d has an invalid prefix", line)
		}
		prefix = prefix.Masked()
		prefixBits := prefix.Bits()
		if prefix.Addr().Is4In6() {
			if prefixBits < 96 {
				return nil, fmt.Errorf("metadata record %d has an ambiguous IPv4-mapped prefix", line)
			}
			prefixBits -= 96
		}
		entry := model.ExitMetadata{
			CountryCode:  strings.ToUpper(field(record, columns, "country_code")),
			Country:      field(record, columns, "country"),
			City:         field(record, columns, "city"),
			ASN:          normalizeASN(field(record, columns, "asn")),
			Organization: field(record, columns, "organization"),
			NetworkType:  strings.ToLower(field(record, columns, "network_type")),
		}
		if err := validateEntry(entry); err != nil {
			return nil, fmt.Errorf("metadata record %d: %w", line, err)
		}
		key := prefixKey{address: prefix.Addr().Unmap(), bits: uint8(prefixBits)}
		target := p.v6
		if key.address.Is4() {
			target = p.v4
		}
		if _, exists := target[key]; exists {
			return nil, fmt.Errorf("metadata record %d duplicates prefix %s", line, prefix)
		}
		target[key] = entry
		p.records++
	}
	if MaxDatabaseBytes+1-limited.N > MaxDatabaseBytes {
		return nil, fmt.Errorf("metadata database exceeds %d-byte limit", MaxDatabaseBytes)
	}
	return p, nil
}

func (p *Provider) Lookup(raw string) (model.ExitMetadata, bool) {
	if p == nil {
		return model.ExitMetadata{}, false
	}
	address, err := netip.ParseAddr(raw)
	if err != nil {
		return model.ExitMetadata{}, false
	}
	address = address.Unmap()
	table := p.v6
	if address.Is4() {
		table = p.v4
	}
	for bits := address.BitLen(); bits >= 0; bits-- {
		masked := netip.PrefixFrom(address, bits).Masked().Addr()
		if entry, ok := table[prefixKey{address: masked, bits: uint8(bits)}]; ok {
			return entry, true
		}
	}
	return model.ExitMetadata{}, false
}

func (p *Provider) Records() int {
	if p == nil {
		return 0
	}
	return p.records
}

func field(record []string, columns map[string]int, name string) string {
	index, ok := columns[name]
	if !ok || index >= len(record) {
		return ""
	}
	return strings.TrimSpace(record[index])
}

func normalizeASN(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" || strings.HasPrefix(value, "AS") {
		return value
	}
	if _, err := strconv.ParseUint(value, 10, 32); err == nil {
		return "AS" + value
	}
	return value
}

func validateEntry(entry model.ExitMetadata) error {
	if entry.CountryCode != "" && (len(entry.CountryCode) != 2 || entry.CountryCode[0] < 'A' || entry.CountryCode[0] > 'Z' || entry.CountryCode[1] < 'A' || entry.CountryCode[1] > 'Z') {
		return errors.New("country_code must contain two ASCII letters")
	}
	for name, value := range map[string]string{"country": entry.Country, "city": entry.City, "asn": entry.ASN, "organization": entry.Organization, "network_type": entry.NetworkType} {
		if len(value) > 256 || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("%s is invalid or exceeds 256 bytes", name)
		}
	}
	return nil
}
