package config

import (
	"fmt"
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
	c = Defaults()
	c.IntelligenceBytes = 0
	if err := c.Validate(); err == nil {
		t.Fatal("accepted zero intelligence capture limit")
	}
	c = Defaults()
	c.AutoProbeTimeout = 0
	if err := c.Validate(); err == nil {
		t.Fatal("accepted zero auto probe timeout")
	}
	c = Defaults()
	c.Concurrency = 1024
	c.IntelligenceBytes = 1 << 20
	if err := c.Validate(); err == nil {
		t.Fatal("accepted excessive concurrent capture budget")
	}
}

func TestResponseCaptureLimitIncludesTargetAssertions(t *testing.T) {
	c := Defaults()
	c.IntelligenceBytes = 1024
	if got := c.ResponseCaptureLimit(); got != 1024 {
		t.Fatalf("ordinary capture=%d", got)
	}
	c.TargetRules = map[string]ResponseRules{"https://example.com/": {ExpectJSON: []string{"status=ok"}}}
	if got := c.ResponseCaptureLimit(); got != c.MaxResponseBytes {
		t.Fatalf("assertion capture=%d want=%d", got, c.MaxResponseBytes)
	}
	c.TargetRules = map[string]ResponseRules{"https://example.com/": {RequireText: []string{"access denied"}}}
	if got := c.ResponseCaptureLimit(); got != 1024 {
		t.Fatalf("streaming text assertion capture=%d", got)
	}
	c.TargetRules = map[string]ResponseRules{"https://example.com/": {RequireText: []string{"café"}}}
	if got := c.ResponseCaptureLimit(); got != c.MaxResponseBytes {
		t.Fatalf("Unicode text assertion capture=%d want=%d", got, c.MaxResponseBytes)
	}
}
func TestLoadPrecedenceEnvironment(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "c.json")
	if err := os.WriteFile(p, []byte(`{"concurrency":12,"connect_timeout":"2s","request_timeout":"3s","progress_interval":"1s"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETVEX_CONCURRENCY", "7")
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
	t.Setenv("NETVEX_CONCURRENCY", "not-a-number")
	if _, err := Load(""); err == nil {
		t.Fatal("bad environment accepted")
	}
}

func TestCompleteEnvironmentConfiguration(t *testing.T) {
	values := map[string]string{
		"NETVEX_CONCURRENCY":              "9",
		"NETVEX_QUEUE_SIZE":               "18",
		"NETVEX_PER_TARGET_CONCURRENCY":   "3",
		"NETVEX_REQUESTS_PER_SECOND":      "12.5",
		"NETVEX_REPEAT":                   "4",
		"NETVEX_MIN_SUCCESS_RATE":         "0.75",
		"NETVEX_MAX_REDIRECTS":            "1",
		"NETVEX_MAX_INPUT_BYTES":          "4096",
		"NETVEX_MAX_INPUT_ENTRIES":        "1234",
		"NETVEX_MAX_RESPONSE_BYTES":       "2048",
		"NETVEX_INTELLIGENCE_BODY_BYTES":  "1536",
		"NETVEX_MIN_RESPONSE_BYTES":       "1024",
		"NETVEX_MIN_THROUGHPUT_KBPS":      "0",
		"NETVEX_ALLOW_PRIVATE_TARGETS":    "true",
		"NETVEX_ALLOW_REMOTE_DNS":         "true",
		"NETVEX_RETRY_PERMANENT_FAILURES": "true",
		"NETVEX_STOP_ON_SUCCESS":          "true",
		"NETVEX_SAVE":                     "true",
		"NETVEX_TARGETS":                  "https://one.test/, http://two.test/",
		"NETVEX_ALLOWED_TARGET_HOSTS":     "one.test, two.test",
		"NETVEX_PROGRESS_INTERVAL":        "750ms",
		"NETVEX_AUTO_PROBE_TIMEOUT":       "1500ms",
		"NETVEX_ANONYMITY_BASELINE_IP":    "198.51.100.10",
		"NETVEX_METADATA_FILE":            "/tmp/netvex-metadata.csv",
		"NETVEX_REQUIRE_TEXT":             "expected marker,application/json",
		"NETVEX_REJECT_TEXT":              "access denied,captcha",
		"NETVEX_EXPECT_JSON":              "status=ok,data.region=eu",
		"NETVEX_EXPECTED_BODY_SHA256":     strings.Repeat("a", 64),
		"NETVEX_CA_BUNDLE":                "/tmp/destination-ca.pem",
		"NETVEX_PROXY_CA_BUNDLE":          "/tmp/proxy-ca.pem",
		"NETVEX_TARGET_MATRIX":            "true",
		"NETVEX_TARGET_QUORUM":            "1",
		"NETVEX_ROTATION_SAMPLES":         "3",
		"NETVEX_ROTATION_INTERVAL":        "2s",
		"NETVEX_PREFLIGHT":                "report",
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
	if c.MaxRedirects != 1 || c.MaxInputBytes != 4096 || c.MaxInputEntries != 1234 || c.MaxResponseBytes != 2048 || c.IntelligenceBytes != 1536 || c.MinResponseBytes != 1024 || c.ProgressInterval != 750*time.Millisecond || c.AutoProbeTimeout != 1500*time.Millisecond {
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
	if c.MetadataFile != "/tmp/netvex-metadata.csv" {
		t.Fatalf("metadata_file=%q", c.MetadataFile)
	}
	if len(c.RequireText) != 2 || len(c.RejectText) != 2 || len(c.ExpectJSON) != 2 {
		t.Fatalf("content rules not applied: require=%v reject=%v json=%v", c.RequireText, c.RejectText, c.ExpectJSON)
	}
	if !c.TargetMatrix || c.TargetQuorum != 1 || c.RotationSamples != 3 || c.RotationInterval != 2*time.Second || c.Preflight != "report" {
		t.Fatalf("advanced environment not applied: %+v", c)
	}
	if c.ExpectedBodySHA != strings.Repeat("a", 64) || c.CABundle == "" || c.ProxyCABundle == "" {
		t.Fatalf("TLS or integrity environment not applied: %+v", c)
	}
}

func TestRejectsInvalidBooleanEnvironment(t *testing.T) {
	t.Setenv("NETVEX_ALLOW_REMOTE_DNS", "sometimes")
	if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "NETVEX_ALLOW_REMOTE_DNS") {
		t.Fatalf("err=%v", err)
	}
}

func TestRejectsExcessiveTargetMatrix(t *testing.T) {
	c := Defaults()
	c.TargetMatrix = true
	c.RotationSamples = 50
	c.Targets = make([]string, 21)
	c.AllowedHosts = make([]string, 21)
	for index := range c.Targets {
		c.Targets[index] = fmt.Sprintf("https://target-%d.test/", index)
		c.AllowedHosts[index] = fmt.Sprintf("target-%d.test", index)
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "1000-attempt") {
		t.Fatalf("err=%v", err)
	}
}
