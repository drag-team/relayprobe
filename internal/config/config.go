package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Concurrency       int           `json:"concurrency"`
	QueueSize         int           `json:"queue_size"`
	PerTarget         int           `json:"per_target_concurrency"`
	RateLimit         float64       `json:"requests_per_second"`
	ConnectTimeout    time.Duration `json:"-"`
	RequestTimeout    time.Duration `json:"-"`
	ConnectTimeoutRaw string        `json:"connect_timeout"`
	RequestTimeoutRaw string        `json:"request_timeout"`
	Repeat            int           `json:"repeat"`
	MinSuccessRate    float64       `json:"min_success_rate"`
	Targets           []string      `json:"targets"`
	MaxRedirects      int           `json:"max_redirects"`
	MaxInputBytes     int64         `json:"max_input_bytes"`
	MaxResponseBytes  int64         `json:"max_response_bytes"`
	AllowPrivate      bool          `json:"allow_private_targets"`
	AllowRemoteDNS    bool          `json:"allow_remote_dns"`
	RetryPermanent    bool          `json:"retry_permanent_failures"`
	StopOnSuccess     bool          `json:"stop_on_success"`
	RetryBackoff      time.Duration `json:"-"`
	RetryBackoffRaw   string        `json:"retry_backoff"`
	DNSCacheTTL       time.Duration `json:"-"`
	DNSCacheTTLRaw    string        `json:"dns_cache_ttl"`
	AllowedHosts      []string      `json:"allowed_target_hosts"`
	DataDir           string        `json:"data_dir"`
	Save              bool          `json:"save"`
	ProgressInterval  time.Duration `json:"-"`
	ProgressRaw       string        `json:"progress_interval"`
}

func Defaults() Config {
	return Config{
		Concurrency: 128, QueueSize: 256, PerTarget: 64,
		ConnectTimeout: 5 * time.Second, RequestTimeout: 12 * time.Second,
		ConnectTimeoutRaw: "5s", RequestTimeoutRaw: "12s",
		Repeat: 2, MinSuccessRate: 0.5, Targets: []string{"https://example.com/"}, MaxRedirects: 2,
		MaxInputBytes: 256 << 20, MaxResponseBytes: 1 << 20,
		AllowedHosts: []string{"example.com"},
		DNSCacheTTL:  5 * time.Minute, DNSCacheTTLRaw: "5m",
		RetryBackoff: 100 * time.Millisecond, RetryBackoffRaw: "100ms",
		DataDir: defaultDataDir(), ProgressInterval: 500 * time.Millisecond, ProgressRaw: "500ms",
	}
}

func defaultDataDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "relayprobe")
	}
	return ".relayprobe"
}

type diskConfig Config

func Load(path string) (Config, error) {
	c := Defaults()
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return c, fmt.Errorf("read config: %w", err)
		}
		defer f.Close()
		dec := json.NewDecoder(f)
		dec.DisallowUnknownFields()
		if err := dec.Decode((*diskConfig)(&c)); err != nil {
			return c, fmt.Errorf("parse config: %w", err)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return c, errors.New("parse config: multiple JSON values")
		}
	}
	if err := applyEnv(&c); err != nil {
		return c, err
	}
	if err := c.ParseDurations(); err != nil {
		return c, err
	}
	return c, c.Validate()
}

func applyEnv(c *Config) error {
	for _, item := range []struct {
		name string
		dst  *int
	}{
		{"RELAYPROBE_CONCURRENCY", &c.Concurrency},
		{"RELAYPROBE_QUEUE_SIZE", &c.QueueSize},
		{"RELAYPROBE_PER_TARGET_CONCURRENCY", &c.PerTarget},
		{"RELAYPROBE_REPEAT", &c.Repeat},
		{"RELAYPROBE_MAX_REDIRECTS", &c.MaxRedirects},
	} {
		if err := envInt(item.name, item.dst); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		name string
		dst  *int64
	}{
		{"RELAYPROBE_MAX_INPUT_BYTES", &c.MaxInputBytes},
		{"RELAYPROBE_MAX_RESPONSE_BYTES", &c.MaxResponseBytes},
	} {
		if err := envInt64(item.name, item.dst); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		name string
		dst  *float64
	}{
		{"RELAYPROBE_REQUESTS_PER_SECOND", &c.RateLimit},
		{"RELAYPROBE_MIN_SUCCESS_RATE", &c.MinSuccessRate},
	} {
		if err := envFloat(item.name, item.dst); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		name string
		dst  *bool
	}{
		{"RELAYPROBE_ALLOW_PRIVATE_TARGETS", &c.AllowPrivate},
		{"RELAYPROBE_ALLOW_REMOTE_DNS", &c.AllowRemoteDNS},
		{"RELAYPROBE_RETRY_PERMANENT_FAILURES", &c.RetryPermanent},
		{"RELAYPROBE_STOP_ON_SUCCESS", &c.StopOnSuccess},
		{"RELAYPROBE_SAVE", &c.Save},
	} {
		if err := envBool(item.name, item.dst); err != nil {
			return err
		}
	}
	if v := os.Getenv("RELAYPROBE_CONNECT_TIMEOUT"); v != "" {
		c.ConnectTimeoutRaw = v
	}
	if v := os.Getenv("RELAYPROBE_REQUEST_TIMEOUT"); v != "" {
		c.RequestTimeoutRaw = v
	}
	if v := os.Getenv("RELAYPROBE_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("RELAYPROBE_TARGETS"); v != "" {
		c.Targets = envList(v)
	}
	if v := os.Getenv("RELAYPROBE_ALLOWED_TARGET_HOSTS"); v != "" {
		c.AllowedHosts = envList(v)
	}
	if v := os.Getenv("RELAYPROBE_DNS_CACHE_TTL"); v != "" {
		c.DNSCacheTTLRaw = v
	}
	if v := os.Getenv("RELAYPROBE_RETRY_BACKOFF"); v != "" {
		c.RetryBackoffRaw = v
	}
	if v := os.Getenv("RELAYPROBE_PROGRESS_INTERVAL"); v != "" {
		c.ProgressRaw = v
	}
	return nil
}

func envInt(name string, dst *int) error {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	*dst = n
	return nil
}

func envInt64(name string, dst *int64) error {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	*dst = n
	return nil
}

func envFloat(name string, dst *float64) error {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	*dst = n
	return nil
}

func envBool(name string, dst *bool) error {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	*dst = b
	return nil
}

func envList(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func (c *Config) ParseDurations() error {
	var err error
	if c.ConnectTimeout, err = time.ParseDuration(c.ConnectTimeoutRaw); err != nil {
		return fmt.Errorf("invalid connect_timeout: %w", err)
	}
	if c.RequestTimeout, err = time.ParseDuration(c.RequestTimeoutRaw); err != nil {
		return fmt.Errorf("invalid request_timeout: %w", err)
	}
	if c.ProgressInterval, err = time.ParseDuration(c.ProgressRaw); err != nil {
		return fmt.Errorf("invalid progress_interval: %w", err)
	}
	if c.DNSCacheTTL, err = time.ParseDuration(c.DNSCacheTTLRaw); err != nil {
		return fmt.Errorf("invalid dns_cache_ttl: %w", err)
	}
	if c.RetryBackoff, err = time.ParseDuration(c.RetryBackoffRaw); err != nil {
		return fmt.Errorf("invalid retry_backoff: %w", err)
	}
	return nil
}

func (c Config) Validate() error {
	if c.Concurrency < 1 || c.Concurrency > 4096 {
		return errors.New("concurrency must be between 1 and 4096")
	}
	if c.QueueSize < 1 || c.QueueSize > 65536 {
		return errors.New("queue_size must be between 1 and 65536")
	}
	if c.PerTarget < 1 || c.PerTarget > 4096 {
		return errors.New("per_target_concurrency must be between 1 and 4096")
	}
	if c.Repeat < 1 || c.Repeat > 20 {
		return errors.New("repeat must be between 1 and 20")
	}
	if math.IsNaN(c.MinSuccessRate) || math.IsInf(c.MinSuccessRate, 0) || c.MinSuccessRate <= 0 || c.MinSuccessRate > 1 {
		return errors.New("min_success_rate must be greater than 0 and at most 1")
	}
	if math.IsNaN(c.RateLimit) || math.IsInf(c.RateLimit, 0) || c.RateLimit < 0 || c.RateLimit > 100000 || (c.RateLimit > 0 && c.RateLimit < 0.1) {
		return errors.New("requests_per_second must be 0 (disabled) or between 0.1 and 100000")
	}
	if c.ConnectTimeout < 100*time.Millisecond || c.ConnectTimeout > 2*time.Minute {
		return errors.New("connect_timeout must be between 100ms and 2m")
	}
	if c.RequestTimeout < c.ConnectTimeout || c.RequestTimeout > 5*time.Minute {
		return errors.New("request_timeout must be >= connect_timeout and <= 5m")
	}
	if c.DNSCacheTTL < 0 || c.DNSCacheTTL > 24*time.Hour {
		return errors.New("dns_cache_ttl must be between 0 and 24h")
	}
	if c.RetryBackoff < 0 || c.RetryBackoff > 30*time.Second {
		return errors.New("retry_backoff must be between 0 and 30s")
	}
	if c.ProgressInterval < 50*time.Millisecond || c.ProgressInterval > time.Minute {
		return errors.New("progress_interval must be between 50ms and 1m")
	}
	if c.MaxRedirects < 0 || c.MaxRedirects > 10 {
		return errors.New("max_redirects must be between 0 and 10")
	}
	if c.MaxInputBytes < 1 || c.MaxInputBytes > 10<<30 {
		return errors.New("max_input_bytes is outside safe limits")
	}
	if c.MaxResponseBytes < 1024 || c.MaxResponseBytes > 64<<20 {
		return errors.New("max_response_bytes must be between 1KiB and 64MiB")
	}
	if len(c.Targets) == 0 {
		return errors.New("at least one validation target is required")
	}
	if len(c.Targets) > 32 {
		return errors.New("at most 32 validation targets are allowed")
	}
	for _, raw := range c.Targets {
		if len(raw) > 2048 {
			return errors.New("validation target URL exceeds 2048 bytes")
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("invalid target URL %q", raw)
		}
		if u.User != nil {
			return fmt.Errorf("target URL %q must not contain credentials", raw)
		}
		if port := u.Port(); port != "" {
			n, e := strconv.ParseUint(port, 10, 16)
			if e != nil || n == 0 {
				return fmt.Errorf("target URL %q has an invalid port", raw)
			}
		}
	}
	if len(c.AllowedHosts) > 64 {
		return errors.New("at most 64 allowed target hosts are permitted")
	}
	for _, host := range c.AllowedHosts {
		host = strings.TrimSpace(strings.TrimSuffix(host, "."))
		if host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\@?#") {
			return fmt.Errorf("invalid allowed target host %q", host)
		}
	}
	return nil
}

func (c Config) MarshalJSON() ([]byte, error) {
	type alias Config
	a := alias(c)
	a.ConnectTimeoutRaw = c.ConnectTimeout.String()
	a.RequestTimeoutRaw = c.RequestTimeout.String()
	a.ProgressRaw = c.ProgressInterval.String()
	a.DNSCacheTTLRaw = c.DNSCacheTTL.String()
	a.RetryBackoffRaw = c.RetryBackoff.String()
	return json.MarshalIndent(a, "", "  ")
}
