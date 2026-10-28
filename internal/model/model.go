package model

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Protocol string

const SchemaVersion = 5

const (
	ProtocolAuto    Protocol = "auto"
	ProtocolHTTP    Protocol = "http"
	ProtocolHTTPS   Protocol = "https"
	ProtocolSOCKS4  Protocol = "socks4"
	ProtocolSOCKS4A Protocol = "socks4a"
	ProtocolSOCKS5  Protocol = "socks5"
)

func ParseProtocol(s string) (Protocol, error) {
	p := Protocol(strings.ToLower(strings.TrimSpace(s)))
	switch p {
	case ProtocolAuto, ProtocolHTTP, ProtocolHTTPS, ProtocolSOCKS4, ProtocolSOCKS4A, ProtocolSOCKS5:
		return p, nil
	default:
		return "", fmt.Errorf("unsupported proxy protocol %q", s)
	}
}

type Credentials struct {
	Username string
	Password string
}

type Proxy struct {
	Protocol    Protocol
	Host        string
	Port        uint16
	Credentials *Credentials
	Source      string
	Line        int
}

func (p Proxy) Address() string { return net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))) }

func (p Proxy) SafeURI() string {
	auth := ""
	if p.Credentials != nil {
		auth = "***:***@"
	}
	return fmt.Sprintf("%s://%s%s", p.Protocol, auth, p.Address())
}

func (p Proxy) CredentialFreeURI() string {
	return fmt.Sprintf("%s://%s", p.Protocol, p.Address())
}

func (p Proxy) FullURI() string {
	auth := ""
	if p.Credentials != nil {
		auth = url.UserPassword(p.Credentials.Username, p.Credentials.Password).String() + "@"
	}
	return fmt.Sprintf("%s://%s%s", p.Protocol, auth, p.Address())
}

func (p Proxy) Key() string {
	id := p.EndpointIdentity()
	return hex.EncodeToString(id[:])
}

func (p Proxy) Identity() [12]byte {
	return p.EndpointIdentity()
}

func (p Proxy) EndpointIdentity() [12]byte {
	var identity [320]byte
	if len(p.Protocol)+len(p.Host)+8 > len(identity) {
		h := sha256.Sum256([]byte(strings.ToLower(string(p.Protocol)) + "\x00" + strings.ToLower(p.Host) + "\x00" + strconv.FormatUint(uint64(p.Port), 10)))
		var id [12]byte
		copy(id[:], h[:12])
		return id
	}
	n := copyLowerASCII(identity[:], string(p.Protocol))
	identity[n] = 0
	n++
	n += copyLowerASCII(identity[n:], p.Host)
	identity[n] = 0
	n++
	encoded := strconv.AppendUint(identity[:n], uint64(p.Port), 10)
	h := sha256.Sum256(encoded)
	var id [12]byte
	copy(id[:], h[:12])
	return id
}

func copyLowerASCII(destination []byte, source string) int {
	for index := 0; index < len(source); index++ {
		value := source[index]
		if value >= 'A' && value <= 'Z' {
			value += 'a' - 'A'
		}
		destination[index] = value
	}
	return len(source)
}

type Stage string

const (
	StageInput     Stage = "input"
	StageResolve   Stage = "resolve"
	StageConnect   Stage = "connect"
	StageProxyTLS  Stage = "proxy_tls"
	StageNegotiate Stage = "negotiate"
	StageTunnel    Stage = "tunnel"
	StageTLS       Stage = "tls"
	StageRequest   Stage = "request"
	StageResponse  Stage = "response"
	StagePolicy    Stage = "policy"
	StageComplete  Stage = "complete"
)

type Status string

const (
	StatusOK           Status = "ok"
	StatusFailed       Status = "failed"
	StatusTimeout      Status = "timeout"
	StatusAuthFailed   Status = "auth_failed"
	StatusPolicyBlock  Status = "policy_blocked"
	StatusInvalid      Status = "invalid"
	StatusInconclusive Status = "inconclusive"
	StatusUnreliable   Status = "unreliable"
	StatusInterrupted  Status = "interrupted"
)

type Timings struct {
	DNSMS      float64 `json:"dns_ms,omitempty"`
	ConnectMS  float64 `json:"connect_ms,omitempty"`
	ProxyTLSMS float64 `json:"proxy_tls_ms,omitempty"`
	TunnelMS   float64 `json:"tunnel_ms,omitempty"`
	TLSMS      float64 `json:"tls_ms,omitempty"`
	TTFBMS     float64 `json:"ttfb_ms,omitempty"`
	BodyMS     float64 `json:"body_ms,omitempty"`
	TotalMS    float64 `json:"total_ms"`
}

type Observation struct {
	Attempt             int               `json:"attempt"`
	StartedAt           time.Time         `json:"started_at"`
	Protocol            Protocol          `json:"protocol"`
	Target              string            `json:"target"`
	Status              Status            `json:"status"`
	Stage               Stage             `json:"stage"`
	Code                string            `json:"code,omitempty"`
	Message             string            `json:"message,omitempty"`
	HTTPStatus          int               `json:"http_status,omitempty"`
	BodyBytes           int64             `json:"body_bytes,omitempty"`
	BodySHA256          string            `json:"body_sha256,omitempty"`
	ThroughputKBPS      float64           `json:"throughput_kbps,omitempty"`
	ExitIP              string            `json:"exit_ip,omitempty"`
	Anonymity           string            `json:"anonymity,omitempty"`
	ForwardingEvidence  []string          `json:"forwarding_evidence,omitempty"`
	ProxyAuthentication string            `json:"proxy_authentication,omitempty"`
	ResolvedIP          string            `json:"resolved_ip,omitempty"`
	Timings             Timings           `json:"timings"`
	ResponseHeaders     map[string]string `json:"response_headers,omitempty"`
	Metadata            *ExitMetadata     `json:"metadata,omitempty"`
	ProxyTLS            *TLSInfo          `json:"proxy_tls,omitempty"`
	DestinationTLS      *TLSInfo          `json:"destination_tls,omitempty"`
}

type TLSInfo struct {
	Version            string    `json:"version"`
	CipherSuite        string    `json:"cipher_suite"`
	ALPN               string    `json:"alpn,omitempty"`
	ServerName         string    `json:"server_name,omitempty"`
	PeerCertificateSHA string    `json:"peer_certificate_sha256,omitempty"`
	CertificateExpiry  time.Time `json:"certificate_expiry,omitempty"`
}

func TLSInfoFromState(state tls.ConnectionState) *TLSInfo {
	info := &TLSInfo{
		Version:     TLSVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ALPN:        state.NegotiatedProtocol,
		ServerName:  state.ServerName,
	}
	if len(state.PeerCertificates) > 0 {
		certificate := state.PeerCertificates[0]
		digest := sha256.Sum256(certificate.Raw)
		info.PeerCertificateSHA = hex.EncodeToString(digest[:])
		info.CertificateExpiry = certificate.NotAfter.UTC()
	}
	return info
}

func TLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

type ExitMetadata struct {
	CountryCode  string `json:"country_code,omitempty"`
	Country      string `json:"country,omitempty"`
	City         string `json:"city,omitempty"`
	ASN          string `json:"asn,omitempty"`
	Organization string `json:"organization,omitempty"`
	NetworkType  string `json:"network_type,omitempty"`
}

type Score struct {
	Value       *float64 `json:"value,omitempty"`
	Confidence  string   `json:"confidence"`
	Reason      string   `json:"reason"`
	SuccessRate float64  `json:"success_rate"`
	MedianMS    float64  `json:"median_ms,omitempty"`
	JitterMS    float64  `json:"jitter_ms,omitempty"`
}

type Result struct {
	SchemaVersion     int             `json:"schema_version"`
	ID                string          `json:"id"`
	Proxy             string          `json:"proxy"`
	Endpoint          string          `json:"endpoint"`
	Protocol          Protocol        `json:"protocol"`
	Label             string          `json:"label,omitempty"`
	Status            Status          `json:"status"`
	Attempts          int             `json:"attempts"`
	Successes         int             `json:"successes"`
	RequiredSuccesses int             `json:"required_successes"`
	Observations      []Observation   `json:"observations"`
	TargetResults     []TargetResult  `json:"target_results,omitempty"`
	TargetQuorum      int             `json:"target_quorum,omitempty"`
	Rotation          RotationProfile `json:"rotation"`
	Score             Score           `json:"score"`
	CheckedAt         time.Time       `json:"checked_at"`
	InputProxy        string          `json:"-"`
}

type TargetResult struct {
	Target      string  `json:"target"`
	Status      Status  `json:"status"`
	Attempts    int     `json:"attempts"`
	Successes   int     `json:"successes"`
	Required    int     `json:"required_successes"`
	SuccessRate float64 `json:"success_rate"`
	MedianMS    float64 `json:"median_ms,omitempty"`
	LastCode    string  `json:"last_code,omitempty"`
	Qualified   bool    `json:"qualified"`
}

type RotationProfile struct {
	Classification  string   `json:"classification"`
	ObservedSamples int      `json:"observed_samples"`
	UniqueExitIPs   int      `json:"unique_exit_ips"`
	DominantExitIP  string   `json:"dominant_exit_ip,omitempty"`
	DominantShare   float64  `json:"dominant_share,omitempty"`
	ExitChanges     int      `json:"exit_changes,omitempty"`
	ChangeRate      float64  `json:"change_rate,omitempty"`
	Countries       []string `json:"countries,omitempty"`
	ASNs            []string `json:"asns,omitempty"`
	GeoConsistent   bool     `json:"geo_consistent"`
}

type RunConfiguration struct {
	Profile          string   `json:"profile,omitempty"`
	Protocol         Protocol `json:"protocol"`
	Concurrency      int      `json:"concurrency"`
	QueueSize        int      `json:"queue_size"`
	PerTarget        int      `json:"per_target_concurrency"`
	RateLimit        float64  `json:"requests_per_second"`
	Repeat           int      `json:"repeat"`
	MinSuccessRate   float64  `json:"min_success_rate"`
	ConnectTimeout   string   `json:"connect_timeout"`
	RequestTimeout   string   `json:"request_timeout"`
	RetryBackoff     string   `json:"retry_backoff"`
	StopOnSuccess    bool     `json:"stop_on_success"`
	RetryPermanent   bool     `json:"retry_permanent_failures"`
	AllowRemoteDNS   bool     `json:"allow_remote_dns"`
	MaxResponseBytes int64    `json:"max_response_bytes"`
	MinResponseBytes int64    `json:"min_response_bytes,omitempty"`
	MinThroughput    float64  `json:"min_throughput_kbps,omitempty"`
	ContentRules     int      `json:"content_rules,omitempty"`
	MetadataEnabled  bool     `json:"metadata_enabled,omitempty"`
	TargetMatrix     bool     `json:"target_matrix,omitempty"`
	TargetQuorum     int      `json:"target_quorum,omitempty"`
	RotationSamples  int      `json:"rotation_samples,omitempty"`
	RotationInterval string   `json:"rotation_interval,omitempty"`
	Preflight        string   `json:"preflight,omitempty"`
	AutoConcurrency  bool     `json:"auto_concurrency,omitempty"`
	Scenario         string   `json:"scenario,omitempty"`
	Label            string   `json:"label,omitempty"`
	Deduplicate      bool     `json:"deduplicate"`
	MaxInputEntries  int      `json:"max_input_entries"`
	ValidationTarget []string `json:"validation_targets"`
}

type InputStats struct {
	Read       int `json:"read"`
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
	Rejected   int `json:"rejected"`
	Resumed    int `json:"resumed,omitempty"`
}

type RunSummary struct {
	SchemaVersion int                      `json:"schema_version"`
	Configuration RunConfiguration         `json:"configuration"`
	RunID         string                   `json:"run_id"`
	StartedAt     time.Time                `json:"started_at"`
	FinishedAt    time.Time                `json:"finished_at"`
	Input         InputStats               `json:"input"`
	Processed     int                      `json:"processed"`
	Restored      int                      `json:"restored,omitempty"`
	Attempts      int                      `json:"attempts"`
	Successful    int                      `json:"successful"`
	Failed        int                      `json:"failed"`
	Inconclusive  int                      `json:"inconclusive"`
	Unreliable    int                      `json:"unreliable"`
	Timeouts      int                      `json:"timeouts"`
	DurationMS    float64                  `json:"duration_ms"`
	RatePerSec    float64                  `json:"rate_per_sec"`
	LatencyP50MS  float64                  `json:"latency_p50_ms,omitempty"`
	LatencyP95MS  float64                  `json:"latency_p95_ms,omitempty"`
	LatencyP99MS  float64                  `json:"latency_p99_ms,omitempty"`
	StatusCount   map[Status]int           `json:"status_count"`
	FailureCodes  map[string]int           `json:"failure_codes,omitempty"`
	FailureStages map[Stage]int            `json:"failure_stages,omitempty"`
	Targets       map[string]TargetSummary `json:"targets,omitempty"`
	TargetHealth  map[string]TargetHealth  `json:"target_health,omitempty"`
	Quality       *QualityReport           `json:"quality,omitempty"`
}

type QualityReport struct {
	Passed bool           `json:"passed"`
	Checks []QualityCheck `json:"checks"`
}

type QualityCheck struct {
	Name     string  `json:"name"`
	Passed   bool    `json:"passed"`
	Actual   float64 `json:"actual"`
	Operator string  `json:"operator"`
	Expected float64 `json:"expected"`
}

type TargetHealth struct {
	Status     string  `json:"status"`
	HTTPStatus int     `json:"http_status,omitempty"`
	LatencyMS  float64 `json:"latency_ms,omitempty"`
	Code       string  `json:"code,omitempty"`
	Message    string  `json:"message,omitempty"`
}

type TargetSummary struct {
	Attempts       int     `json:"attempts"`
	Successful     int     `json:"successful"`
	Failed         int     `json:"failed"`
	Inconclusive   int     `json:"inconclusive"`
	Timeouts       int     `json:"timeouts"`
	SuccessRate    float64 `json:"success_rate"`
	AverageTotalMS float64 `json:"average_total_ms,omitempty"`
	TotalMS        float64 `json:"-"`
}
