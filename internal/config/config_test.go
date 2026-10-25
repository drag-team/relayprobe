package config

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigValidation(t *testing.T) {
	c := Defaults()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Concurrency = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected concurrency error")
	}
	c = Defaults()
	c.RateLimit = 0.01
	if err := c.Validate(); err == nil {
		t.Fatal("accepted unsafe tiny rate")
	}
	c.RateLimit = math.NaN()
	if err := c.Validate(); err == nil {
		t.Fatal("accepted NaN rate")
	}
	c = Defaults()
	c.MinSuccessRate = math.NaN()
	if err := c.Validate(); err == nil {
		t.Fatal("accepted NaN success rate")
	}
}
func TestLoadPrecedenceEnvironment(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "c.json")
	if err := os.WriteFile(p, []byte(`{"concurrency":12,"connect_timeout":"2s","request_timeout":"3s","progress_interval":"1s"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELAYPROBE_CONCURRENCY", "7")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Concurrency != 7 {
		t.Fatalf("got %d", c.Concurrency)
	}
	if c.QueueSize != Defaults().QueueSize || c.DNSCacheTTL != Defaults().DNSCacheTTL {
		t.Fatalf("defaults lost while decoding: %+v", c)
	}
}

func TestLoadRejectsUnknownAndBadEnvironment(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(p, []byte(`{"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("unknown field accepted")
	}
	t.Setenv("RELAYPROBE_CONCURRENCY", "not-a-number")
	if _, err := Load(""); err == nil {
		t.Fatal("bad environment accepted")
	}
}
