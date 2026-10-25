package config

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	c = Defaults()
	c.MinThroughputKBPS = 100
	if err := c.Validate(); err == nil {
		t.Fatal("accepted throughput threshold without a meaningful response size")
	}
	c.MinResponseBytes = 16 << 10
	c.AnonymityBaseline = "not-an-ip"
	if err := c.Validate(); err == nil {
		t.Fatal("accepted invalid anonymity baseline")
	}
	c = Defaults()
	c.ExpectJSON = []string{"missing-separator"}
	if err := c.Validate(); err == nil {
		t.Fatal("accepted invalid JSON assertion")
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

func TestCompleteEnvironmentConfiguration(t *testing.T) {
	values := map[string]string{
		"RELAYPROBE_CONCURRENCY":              "9",
		"RELAYPROBE_QUEUE_SIZE":               "18",
		"RELAYPROBE_PER_TARGET_CONCURRENCY":   "3",
		"RELAYPROBE_REQUESTS_PER_SECOND":      "12.5",
		"RELAYPROBE_REPEAT":                   "4",
		"RELAYPROBE_MIN_SUCCESS_RATE":         "0.75",
		"RELAYPROBE_MAX_REDIRECTS":            "1",
		"RELAYPROBE_MAX_INPUT_BYTES":          "4096",
		"RELAYPROBE_MAX_RESPONSE_BYTES":       "2048",
		"RELAYPROBE_MIN_RESPONSE_BYTES":       "1024",
		"RELAYPROBE_MIN_THROUGHPUT_KBPS":      "0",
		"RELAYPROBE_ALLOW_PRIVATE_TARGETS":    "true",
		"RELAYPROBE_ALLOW_REMOTE_DNS":         "true",
		"RELAYPROBE_RETRY_PERMANENT_FAILURES": "true",
		"RELAYPROBE_STOP_ON_SUCCESS":          "true",
		"RELAYPROBE_SAVE":                     "true",
		"RELAYPROBE_TARGETS":                  "https://one.test/, http://two.test/",
		"RELAYPROBE_ALLOWED_TARGET_HOSTS":     "one.test, two.test",
		"RELAYPROBE_PROGRESS_INTERVAL":        "750ms",
		"RELAYPROBE_ANONYMITY_BASELINE_IP":    "198.51.100.10",
		"RELAYPROBE_METADATA_FILE":            "/tmp/relayprobe-metadata.csv",
		"RELAYPROBE_REQUIRE_TEXT":             "expected marker,application/json",
		"RELAYPROBE_REJECT_TEXT":              "access denied,captcha",
		"RELAYPROBE_EXPECT_JSON":              "status=ok,data.region=eu",
	}
	for name, value := range values {
		t.Setenv(name, value)
	}
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Concurrency != 9 || c.QueueSize != 18 || c.PerTarget != 3 || c.RateLimit != 12.5 || c.Repeat != 4 || c.MinSuccessRate != 0.75 {
		t.Fatalf("numeric environment not applied: %+v", c)
	}
	if c.MaxRedirects != 1 || c.MaxInputBytes != 4096 || c.MaxResponseBytes != 2048 || c.MinResponseBytes != 1024 || c.ProgressInterval != 750*time.Millisecond {
		t.Fatalf("limits not applied: %+v", c)
	}
	if !c.AllowPrivate || !c.AllowRemoteDNS || !c.RetryPermanent || !c.StopOnSuccess || !c.Save {
		t.Fatalf("boolean environment not applied: %+v", c)
	}
	if len(c.Targets) != 2 || c.Targets[1] != "http://two.test/" || len(c.AllowedHosts) != 2 {
		t.Fatalf("lists not applied: targets=%v allowed=%v", c.Targets, c.AllowedHosts)
	}
	if c.AnonymityBaseline != "198.51.100.10" {
		t.Fatalf("baseline=%q", c.AnonymityBaseline)
	}
	if c.MetadataFile != "/tmp/relayprobe-metadata.csv" {
		t.Fatalf("metadata_file=%q", c.MetadataFile)
	}
	if len(c.RequireText) != 2 || len(c.RejectText) != 2 || len(c.ExpectJSON) != 2 {
		t.Fatalf("content rules not applied: require=%v reject=%v json=%v", c.RequireText, c.RejectText, c.ExpectJSON)
	}
}

func TestRejectsInvalidBooleanEnvironment(t *testing.T) {
	t.Setenv("RELAYPROBE_ALLOW_REMOTE_DNS", "sometimes")
	if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "RELAYPROBE_ALLOW_REMOTE_DNS") {
		t.Fatalf("err=%v", err)
	}
}
