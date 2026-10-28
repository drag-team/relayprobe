package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/drag-team/relayprobe/internal/buildinfo"
	"github.com/drag-team/relayprobe/internal/config"
	"github.com/drag-team/relayprobe/internal/intel"
	"github.com/drag-team/relayprobe/internal/model"
	"github.com/drag-team/relayprobe/internal/policy"
	"github.com/drag-team/relayprobe/internal/protocol"
	"github.com/drag-team/relayprobe/internal/score"
)

type Checker struct {
	Config      config.Config
	Policy      *policy.Policy
	Connector   protocol.Connector
	mu          sync.Mutex
	targetSem   map[string]chan struct{}
	TLSConfig   *tls.Config
	rateMu      sync.Mutex
	nextStart   time.Time
	resolveMu   sync.Mutex
	resolved    map[string]*resolveEntry
	baseline    netip.Addr
	Metadata    MetadataLookup
	requireText []string
	rejectText  []string
	expectJSON  []jsonExpectation
	Label       string
	targetRules map[string]compiledResponseRules
}

type jsonExpectation struct {
	path     []string
	expected string
}

type compiledResponseRules struct {
	minHTTPStatus     int
	maxHTTPStatus     int
	minResponseBytes  int64
	minThroughputKBPS float64
	requireText       []string
	rejectText        []string
	expectJSON        []jsonExpectation
	expectedBodySHA   string
}

type MetadataLookup interface {
	Lookup(string) (model.ExitMetadata, bool)
}

type resolveEntry struct {
	done    chan struct{}
	dest    policy.Destination
	err     error
	expires time.Time
}

func NewChecker(c config.Config) *Checker {
	baseline, _ := netip.ParseAddr(c.AnonymityBaseline)
	checker := &Checker{Config: c, Policy: policy.New(c.AllowPrivate, c.AllowedHosts), Connector: protocol.Connector{ConnectTimeout: c.ConnectTimeout, AllowRemoteDNS: c.AllowRemoteDNS}, targetSem: make(map[string]chan struct{}), resolved: make(map[string]*resolveEntry), baseline: baseline.Unmap(), targetRules: make(map[string]compiledResponseRules)}
	for _, rule := range c.RequireText {
		checker.requireText = append(checker.requireText, strings.ToLower(rule))
	}
	for _, rule := range c.RejectText {
		checker.rejectText = append(checker.rejectText, strings.ToLower(rule))
	}
	for _, rule := range c.ExpectJSON {
		path, expected, _ := strings.Cut(rule, "=")
		checker.expectJSON = append(checker.expectJSON, jsonExpectation{path: strings.Split(path, "."), expected: expected})
	}
	for target, rules := range c.TargetRules {
		checker.targetRules[target] = compileResponseRules(rules)
	}
	return checker
}

func compileResponseRules(rules config.ResponseRules) compiledResponseRules {
	compiled := compiledResponseRules{
		minHTTPStatus: rules.MinHTTPStatus, maxHTTPStatus: rules.MaxHTTPStatus,
		minResponseBytes: rules.MinResponseBytes, minThroughputKBPS: rules.MinThroughputKBPS,
		expectedBodySHA: strings.ToLower(rules.ExpectedBodySHA),
	}
	for _, rule := range rules.RequireText {
		compiled.requireText = append(compiled.requireText, strings.ToLower(rule))
	}
	for _, rule := range rules.RejectText {
		compiled.rejectText = append(compiled.rejectText, strings.ToLower(rule))
	}
	for _, rule := range rules.ExpectJSON {
		path, expected, _ := strings.Cut(rule, "=")
		compiled.expectJSON = append(compiled.expectJSON, jsonExpectation{path: strings.Split(path, "."), expected: expected})
	}
	return compiled
}

func (c *Checker) rulesFor(target string) compiledResponseRules {
	rules := compiledResponseRules{
		minHTTPStatus: 200, maxHTTPStatus: 399,
		minResponseBytes: c.Config.MinResponseBytes, minThroughputKBPS: c.Config.MinThroughputKBPS,
		requireText: c.requireText, rejectText: c.rejectText, expectJSON: c.expectJSON,
		expectedBodySHA: strings.ToLower(c.Config.ExpectedBodySHA),
	}
	if targetRules, ok := c.targetRules[target]; ok {
		if targetRules.minHTTPStatus > 0 {
			rules.minHTTPStatus = targetRules.minHTTPStatus
		}
		if targetRules.maxHTTPStatus > 0 {
			rules.maxHTTPStatus = targetRules.maxHTTPStatus
		}
		if targetRules.minResponseBytes > 0 {
			rules.minResponseBytes = targetRules.minResponseBytes
		}
		if targetRules.minThroughputKBPS > 0 {
			rules.minThroughputKBPS = targetRules.minThroughputKBPS
		}
		if targetRules.expectedBodySHA != "" {
			rules.expectedBodySHA = targetRules.expectedBodySHA
		}
		rules.requireText = append(append([]string{}, rules.requireText...), targetRules.requireText...)
		rules.rejectText = append(append([]string{}, rules.rejectText...), targetRules.rejectText...)
		rules.expectJSON = append(append([]jsonExpectation{}, rules.expectJSON...), targetRules.expectJSON...)
	}
	return rules
}

func (c *Checker) Check(ctx context.Context, p model.Proxy) model.Result {
	repeats := c.Config.Repeat
	if c.Config.RotationSamples > repeats {
		repeats = c.Config.RotationSamples
	}
	targets := make([]string, 0, repeats*len(c.Config.Targets))
	if c.Config.TargetMatrix {
		for round := 0; round < repeats; round++ {
			targets = append(targets, c.Config.Targets...)
		}
	} else {
		for i := 0; i < repeats; i++ {
			targets = append(targets, c.Config.Targets[i%len(c.Config.Targets)])
		}
	}
	required := int(math.Ceil(float64(repeats) * c.Config.MinSuccessRate))
	quorum := 0
	if c.Config.TargetMatrix {
		quorum = c.Config.TargetQuorum
		if quorum == 0 {
			quorum = len(c.Config.Targets)
		}
		required *= quorum
	}
	r := model.Result{SchemaVersion: model.SchemaVersion, ID: p.Key(), Proxy: p.SafeURI(), Endpoint: p.Address(), Protocol: p.Protocol, Label: c.Label, RequiredSuccesses: required, TargetQuorum: quorum, CheckedAt: time.Now().UTC(), InputProxy: p.FullURI()}
	for i, target := range targets {
		intervalDue := i > 0 && (!c.Config.TargetMatrix || i%len(c.Config.Targets) == 0)
		if intervalDue && !c.waitInterval(ctx) {
			break
		}
		if !c.waitRate(ctx) {
			break
		}
		obs := c.attempt(ctx, p, target, i+1)
		r.Observations = append(r.Observations, obs)
		r.Attempts++
		if obs.Status == model.StatusOK {
			r.Successes++
			r.Protocol = obs.Protocol
		}
		if !c.Config.TargetMatrix && obs.Status == model.StatusOK && c.Config.StopOnSuccess && r.Successes >= required {
			break
		}
		globalPermanent := obs.Status == model.StatusAuthFailed || obs.Status == model.StatusInvalid || (!c.Config.TargetMatrix && obs.Status == model.StatusPolicyBlock)
		if !c.Config.RetryPermanent && globalPermanent {
			break
		}
		if ctx.Err() != nil {
			break
		}
		remaining := len(targets) - (i + 1)
		if !c.Config.TargetMatrix && r.Successes+remaining < required {
			break
		}
		if obs.Status != model.StatusOK && i+1 < len(targets) && !c.waitBackoff(ctx, p, i) {
			break
		}
	}
	expectedPerTarget := 0
	if c.Config.TargetMatrix {
		expectedPerTarget = repeats
	}
	expectedTargets := make([]string, 0, len(c.Config.Targets))
	for _, target := range c.Config.Targets {
		expectedTargets = append(expectedTargets, c.targetName(target))
	}
	r.TargetResults = intel.TargetResults(r.Observations, c.Config.MinSuccessRate, expectedPerTarget, expectedTargets...)
	r.Rotation = intel.Rotation(r.Observations)
	if c.Config.TargetMatrix {
		qualified := 0
		for _, targetResult := range r.TargetResults {
			if targetResult.Qualified {
				qualified++
			}
		}
		if qualified >= quorum {
			r.Status = model.StatusOK
		} else if r.Successes > 0 {
			r.Status = model.StatusUnreliable
		} else if len(r.Observations) > 0 {
			r.Status = r.Observations[len(r.Observations)-1].Status
		} else {
			r.Status = model.StatusInterrupted
		}
	} else {
		if r.Successes >= required {
			r.Status = model.StatusOK
		} else if r.Successes > 0 {
			r.Status = model.StatusUnreliable
		} else if len(r.Observations) > 0 {
			r.Status = r.Observations[len(r.Observations)-1].Status
		} else {
			r.Status = model.StatusInterrupted
		}
	}
	if r.Status == model.StatusOK && p.Protocol == model.ProtocolAuto {
		exportProxy := p
		exportProxy.Protocol = r.Protocol
		r.InputProxy = exportProxy.FullURI()
	}
	r.Score = score.Calculate(r.Observations)
	return r
}

func (c *Checker) waitInterval(ctx context.Context) bool {
	if c.Config.RotationInterval <= 0 {
		return true
	}
	timer := time.NewTimer(c.Config.RotationInterval)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *Checker) waitBackoff(ctx context.Context, p model.Proxy, retry int) bool {
	base := c.Config.RetryBackoff
	if base <= 0 {
		return true
	}
	delay := base
	for n := 1; n < retry && delay < 5*time.Second; n++ {
		delay *= 2
	}
	if delay > 5*time.Second {
		delay = 5 * time.Second
	}
	id := p.Identity()
	factor := 0.75 + float64(id[0])/255*0.5
	delay = time.Duration(float64(delay) * factor)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *Checker) attempt(parent context.Context, p model.Proxy, target string, n int) model.Observation {
	ctx, cancel := context.WithTimeout(parent, c.Config.RequestTimeout)
	defer cancel()
	start := time.Now()
	obs := model.Observation{Attempt: n, StartedAt: start.UTC(), Protocol: p.Protocol, Target: c.targetName(target), Status: model.StatusFailed, Stage: model.StageResolve, Anonymity: "unavailable"}
	dest, err := c.resolve(ctx, target)
	obs.Timings.DNSMS = ms(dest.DNSDuration)
	if err != nil {
		if errors.Is(err, policy.ErrBlocked) {
			return finishError(obs, start, &protocol.Error{Stage: model.StagePolicy, Status: model.StatusPolicyBlock, Code: "destination_blocked", Detail: err.Error(), Err: err})
		}
		return finishError(obs, start, &protocol.Error{Stage: model.StageResolve, Status: model.StatusInconclusive, Code: "destination_dns", Detail: "destination DNS resolution failed", Err: err})
	}
	obs.ResolvedIP = dest.IP.String()
	release := c.acquireTarget(ctx, dest.Host)
	if release == nil {
		return finishError(obs, start, ctx.Err())
	}
	defer release()
	protos := []model.Protocol{p.Protocol}
	if p.Protocol == model.ProtocolAuto {
		protos = []model.Protocol{model.ProtocolHTTP, model.ProtocolHTTPS, model.ProtocolSOCKS5, model.ProtocolSOCKS4}
		if c.Config.AllowRemoteDNS {
			protos = append(protos, model.ProtocolSOCKS4A)
		}
	}
	var best error
	bestProtocol := p.Protocol
	bestObservation := obs
	rules := c.rulesFor(target)
	for _, protoName := range protos {
		candidate := p
		candidate.Protocol = protoName
		obs.Protocol = protoName
		got, e := c.request(ctx, candidate, destinationForProtocol(dest, protoName), rules)
		got.Attempt = n
		got.StartedAt = obs.StartedAt
		got.Target = obs.Target
		got.Timings.DNSMS = obs.Timings.DNSMS
		if e == nil {
			got.Timings.TotalMS = ms(time.Since(start))
			return got
		}
		if best == nil || errorPriority(e) > errorPriority(best) {
			best = e
			bestProtocol = protoName
			bestObservation = got
		}
		if ctx.Err() != nil {
			best = ctx.Err()
			bestProtocol = protoName
			break
		}
	}
	bestObservation.Protocol = bestProtocol
	return finishError(bestObservation, start, best)
}

func targetOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "unavailable"
	}
	u.User = nil
	u.Path, u.RawPath, u.RawQuery, u.Fragment = "/", "", "", ""
	return u.String()
}

func (c *Checker) targetName(raw string) string {
	if name := c.Config.TargetLabels[raw]; name != "" {
		return name
	}
	return targetOrigin(raw)
}

func destinationForProtocol(dest policy.Destination, protoName model.Protocol) policy.Destination {
	if protoName != model.ProtocolSOCKS4 || dest.IP.Is4() {
		return dest
	}
	for _, ip := range dest.Resolved {
		ip = ip.Unmap()
		if ip.Is4() {
			dest.IP = ip
			break
		}
	}
	return dest
}

func (c *Checker) resolve(ctx context.Context, target string) (policy.Destination, error) {
	if c.Config.DNSCacheTTL == 0 {
		return c.Policy.Resolve(ctx, target)
	}
	for {
		c.resolveMu.Lock()
		entry := c.resolved[target]
		if entry != nil && !entry.expires.IsZero() && time.Now().After(entry.expires) {
			delete(c.resolved, target)
			entry = nil
		}
		if entry == nil {
			entry = &resolveEntry{done: make(chan struct{})}
			c.resolved[target] = entry
			c.resolveMu.Unlock()
			dest, err := c.Policy.Resolve(ctx, target)
			c.resolveMu.Lock()
			entry.dest, entry.err = dest, err
			entry.expires = time.Now().Add(c.Config.DNSCacheTTL)
			close(entry.done)
			if err != nil {
				delete(c.resolved, target)
			}
			c.resolveMu.Unlock()
			return dest, err
		}
		done := entry.done
		c.resolveMu.Unlock()
		select {
		case <-done:
			return entry.dest, entry.err
		case <-ctx.Done():
			return policy.Destination{}, ctx.Err()
		}
	}
}

func errorPriority(err error) int {
	var pe *protocol.Error
	if !errors.As(err, &pe) {
		return 0
	}
	switch pe.Status {
	case model.StatusPolicyBlock:
		return 4
	case model.StatusAuthFailed:
		return 3
	case model.StatusTimeout:
		return 2
	default:
		return 1
	}
}

func (c *Checker) waitRate(ctx context.Context) bool {
	if c.Config.RateLimit <= 0 {
		return true
	}
	spacing := time.Duration(float64(time.Second) / c.Config.RateLimit)
	c.rateMu.Lock()
	defer c.rateMu.Unlock()
	if ctx.Err() != nil {
		return false
	}
	wait := time.Until(c.nextStart)
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return false
		}
	}
	c.nextStart = time.Now().Add(spacing)
	return true
}

func (c *Checker) request(ctx context.Context, p model.Proxy, dest policy.Destination, rules compiledResponseRules) (model.Observation, error) {
	return c.requestWithRedirects(ctx, p, dest, c.Config.MaxRedirects, rules)
}

func (c *Checker) requestWithRedirects(ctx context.Context, p model.Proxy, dest policy.Destination, redirectsLeft int, rules compiledResponseRules) (model.Observation, error) {
	obs := model.Observation{Protocol: p.Protocol, ResolvedIP: dest.IP.String(), Status: model.StatusFailed, Stage: model.StageConnect, Anonymity: "unavailable"}
	timed, err := c.Connector.Open(ctx, p, dest)
	if err != nil {
		return obs, err
	}
	defer timed.Conn.Close()
	obs.Timings.ConnectMS = ms(timed.Connect)
	obs.Timings.ProxyTLSMS = ms(timed.ProxyTLS)
	obs.ProxyTLS = timed.ProxyTLSInfo
	obs.ProxyAuthentication = timed.AuthMethod
	obs.Timings.TunnelMS = ms(timed.Negotiate)
	conn := timed.Conn
	if dest.URL.Scheme == "https" {
		tlsStart := time.Now()
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if c.TLSConfig != nil {
			tlsConfig = c.TLSConfig.Clone()
			if tlsConfig.MinVersion == 0 {
				tlsConfig.MinVersion = tls.VersionTLS12
			}
		}
		tlsConfig.ServerName = dest.Host
		tc := tls.Client(conn, tlsConfig)
		if err := tc.HandshakeContext(ctx); err != nil {
			status := statusFor(err)
			if status == model.StatusFailed {
				status = model.StatusInconclusive
			}
			return obs, &protocol.Error{Stage: model.StageTLS, Status: status, Code: "tls_handshake", Detail: "TLS handshake or certificate validation failed", Err: err}
		}
		obs.Timings.TLSMS = ms(time.Since(tlsStart))
		obs.DestinationTLS = model.TLSInfoFromState(tc.ConnectionState())
		conn = tc
	}
	reqURL := *dest.URL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return obs, err
	}
	req.Host = dest.URL.Host
	req.Header.Set("User-Agent", buildinfo.UserAgent())
	req.Header.Set("Accept", "application/json, text/plain;q=0.8, */*;q=0.1")
	req.Header.Set("Accept-Encoding", "identity")
	req.Close = true
	forwardMode := (p.Protocol == model.ProtocolHTTP || p.Protocol == model.ProtocolHTTPS) && dest.URL.Scheme == "http" && c.Config.AllowRemoteDNS
	if forwardMode && p.Credentials != nil {
		req.Header.Set("Proxy-Authorization", "Basic "+basicToken(p.Credentials.Username, p.Credentials.Password))
	}
	writeStart := time.Now()
	if forwardMode {
		err = req.WriteProxy(conn)
	} else {
		err = req.Write(conn)
	}
	if err != nil {
		return obs, &protocol.Error{Stage: model.StageRequest, Status: statusFor(err), Code: "request_write", Detail: "failed to send request", Err: err}
	}
	resp, _, err := protocol.ReadResponseLimited(conn, req, 64<<10)
	if err != nil {
		return obs, &protocol.Error{Stage: model.StageResponse, Status: statusFor(err), Code: "response_read", Detail: "failed to read HTTP response", Err: err}
	}
	obs.Timings.TTFBMS = ms(time.Since(writeStart))
	defer resp.Body.Close()
	obs.HTTPStatus = resp.StatusCode
	obs.ResponseHeaders = selectedHeaders(resp.Header)
	bodyStart := time.Now()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, c.Config.MaxResponseBytes+1))
	bodyDuration := time.Since(bodyStart)
	obs.Timings.BodyMS = ms(bodyDuration)
	obs.BodyBytes = int64(len(body))
	bodyDigest := sha256.Sum256(body)
	obs.BodySHA256 = hex.EncodeToString(bodyDigest[:])
	if obs.BodyBytes > 0 && bodyDuration > 0 {
		obs.ThroughputKBPS = float64(obs.BodyBytes) / 1000 / bodyDuration.Seconds()
	}
	if readErr != nil {
		return obs, &protocol.Error{Stage: model.StageResponse, Status: statusFor(readErr), Code: "body_read", Detail: "failed to read response body", Err: readErr}
	}
	if int64(len(body)) > c.Config.MaxResponseBytes {
		return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "response_too_large", Detail: "response exceeded configured byte limit"}
	}
	if resp.StatusCode == http.StatusProxyAuthRequired {
		return obs, protocol.HTTPProxyAuthError(resp, p.Credentials != nil)
	}
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		if redirectsLeft <= 0 {
			return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "redirect_limit", Detail: "redirect limit exceeded"}
		}
		loc, locErr := dest.URL.Parse(resp.Header.Get("Location"))
		if locErr != nil {
			return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "invalid_redirect", Detail: "destination returned an invalid redirect"}
		}
		return c.followRedirect(ctx, p, loc, redirectsLeft-1, obs, rules)
	}
	if resp.StatusCode < rules.minHTTPStatus || resp.StatusCode > rules.maxHTTPStatus {
		return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusInconclusive, Code: "http_status", Detail: fmt.Sprintf("destination returned HTTP status %d", resp.StatusCode)}
	}
	if len(rules.requireText) > 0 || len(rules.rejectText) > 0 {
		bodyLower := bytes.ToLower(body)
		var headerText strings.Builder
		headerText.Grow(1024)
		for name, values := range resp.Header {
			headerText.WriteByte('\n')
			headerText.WriteString(strings.ToLower(name))
			headerText.WriteByte(':')
			headerText.WriteString(strings.ToLower(strings.Join(values, ",")))
		}
		headersLower := headerText.String()
		for i, required := range rules.requireText {
			if !bytes.Contains(bodyLower, []byte(required)) && !strings.Contains(headersLower, required) {
				return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "required_content_missing", Detail: fmt.Sprintf("response did not satisfy required content rule %d", i+1)}
			}
		}
		for i, rejected := range rules.rejectText {
			if bytes.Contains(bodyLower, []byte(rejected)) || strings.Contains(headersLower, rejected) {
				return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "rejected_content_present", Detail: fmt.Sprintf("response matched rejected content rule %d", i+1)}
			}
		}
	}
	if len(rules.expectJSON) > 0 {
		var document any
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		decodeErr := decoder.Decode(&document)
		var trailing any
		if decodeErr != nil || decoder.Decode(&trailing) != io.EOF {
			return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "expected_json_invalid", Detail: "response is not valid JSON required by configured assertions"}
		}
		for i, expectation := range rules.expectJSON {
			value, found := jsonPath(document, expectation.path)
			if !found || fmt.Sprint(value) != expectation.expected {
				return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "json_assertion_failed", Detail: fmt.Sprintf("response did not satisfy JSON assertion %d", i+1)}
			}
		}
	}
	if rules.expectedBodySHA != "" && obs.BodySHA256 != rules.expectedBodySHA {
		return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "body_integrity_mismatch", Detail: "response body SHA-256 did not match the configured value"}
	}
	if obs.BodyBytes < rules.minResponseBytes {
		return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "response_too_small", Detail: "response body is smaller than the configured measurement size"}
	}
	if rules.minThroughputKBPS > 0 && obs.ThroughputKBPS < rules.minThroughputKBPS {
		return obs, &protocol.Error{Stage: model.StageResponse, Status: model.StatusFailed, Code: "throughput_below_minimum", Detail: "response throughput is below the configured minimum"}
	}
	obs.Status = model.StatusOK
	obs.Stage = model.StageComplete
	obs.ExitIP, obs.Anonymity, obs.ForwardingEvidence = extractIntelligence(body, c.baseline)
	if c.Metadata != nil && obs.ExitIP != "" {
		if metadata, ok := c.Metadata.Lookup(obs.ExitIP); ok {
			obs.Metadata = &metadata
		}
	}
	return obs, nil
}

func (c *Checker) followRedirect(ctx context.Context, p model.Proxy, u *url.URL, left int, prior model.Observation, rules compiledResponseRules) (model.Observation, error) {
	dest, err := c.Policy.Resolve(ctx, u.String())
	if err != nil {
		if errors.Is(err, policy.ErrBlocked) {
			return prior, &protocol.Error{Stage: model.StagePolicy, Status: model.StatusPolicyBlock, Code: "redirect_blocked", Detail: "redirect destination blocked: " + err.Error(), Err: err}
		}
		return prior, &protocol.Error{Stage: model.StageResolve, Status: model.StatusInconclusive, Code: "redirect_dns", Detail: "redirect destination DNS resolution failed", Err: err}
	}
	next, err := c.requestWithRedirects(ctx, p, dest, left, rules)
	if err == nil {
		next.Timings.ConnectMS += prior.Timings.ConnectMS
		next.Timings.ProxyTLSMS += prior.Timings.ProxyTLSMS
		next.Timings.TunnelMS += prior.Timings.TunnelMS
		next.Timings.TLSMS += prior.Timings.TLSMS
		next.Timings.BodyMS += prior.Timings.BodyMS
	}
	return next, err
}

func (c *Checker) acquireTarget(ctx context.Context, host string) func() {
	c.mu.Lock()
	sem := c.targetSem[host]
	if sem == nil {
		limit := c.Config.PerTarget
		if limit > c.Config.Concurrency {
			limit = c.Config.Concurrency
		}
		sem = make(chan struct{}, limit)
		c.targetSem[host] = sem
	}
	c.mu.Unlock()
	select {
	case sem <- struct{}{}:
		return func() { <-sem }
	case <-ctx.Done():
		return nil
	}
}

func finishError(obs model.Observation, start time.Time, err error) model.Observation {
	obs.Timings.TotalMS = ms(time.Since(start))
	if err == nil {
		obs.Status = model.StatusFailed
		obs.Code = "unknown"
		obs.Message = "unknown validation error"
		return obs
	}
	var pe *protocol.Error
	if errors.As(err, &pe) {
		obs.Stage = pe.Stage
		obs.Status = pe.Status
		obs.Code = pe.Code
		obs.Message = pe.Error()
	} else {
		obs.Status = statusFor(err)
		obs.Code = "operation_failed"
		obs.Message = "operation failed"
	}
	return obs
}

func statusFor(err error) model.Status {
	if errors.Is(err, context.Canceled) {
		return model.StatusInterrupted
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return model.StatusTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return model.StatusTimeout
	}
	return model.StatusFailed
}
func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
func basicToken(u, p string) string {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	_ = table
	return encodeBase64([]byte(u + ":" + p))
}
func encodeBase64(src []byte) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := make([]byte, 0, (len(src)+2)/3*4)
	for len(src) >= 3 {
		v := uint(src[0])<<16 | uint(src[1])<<8 | uint(src[2])
		out = append(out, enc[v>>18], enc[(v>>12)&63], enc[(v>>6)&63], enc[v&63])
		src = src[3:]
	}
	if len(src) == 1 {
		v := uint(src[0]) << 16
		out = append(out, enc[v>>18], enc[(v>>12)&63], '=', '=')
	} else if len(src) == 2 {
		v := uint(src[0])<<16 | uint(src[1])<<8
		out = append(out, enc[v>>18], enc[(v>>12)&63], enc[(v>>6)&63], '=')
	}
	return string(out)
}

func selectedHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"Server", "Via", "Content-Type", "Content-Length"} {
		if v := h.Get(k); v != "" {
			if len(v) > 512 {
				v = v[:512]
			}
			out[k] = v
		}
	}
	return out
}

func extractIntelligence(body []byte, baseline netip.Addr) (string, string, []string) {
	var v map[string]any
	if json.Unmarshal(body, &v) != nil {
		return "", "unavailable", nil
	}
	exit := ""
	for _, k := range []string{"ip", "origin", "query"} {
		if s, ok := v[k].(string); ok {
			part := strings.TrimSpace(strings.Split(s, ",")[0])
			if net.ParseIP(part) != nil {
				exit = part
				break
			}
		}
	}
	evidence := []string{}
	baselineForwarded := false
	if headers, ok := v["headers"].(map[string]any); ok {
		for k, val := range headers {
			lk := strings.ToLower(k)
			if lk == "via" || lk == "forwarded" || lk == "x-forwarded-for" || lk == "x-real-ip" || lk == "client-ip" {
				evidence = append(evidence, http.CanonicalHeaderKey(k))
				if baseline.IsValid() && containsIP(fmt.Sprint(val), baseline) {
					baselineForwarded = true
				}
			}
		}
	}
	sort.Strings(evidence)
	anon := "undetermined"
	if exit == "" && len(evidence) == 0 {
		anon = "unavailable"
	} else if baseline.IsValid() {
		exitAddr, _ := netip.ParseAddr(exit)
		switch {
		case baselineForwarded || exitAddr.IsValid() && exitAddr.Unmap() == baseline.Unmap():
			anon = "transparent"
		case len(evidence) > 0:
			anon = "anonymous"
		case exitAddr.IsValid():
			anon = "elite"
		}
	}
	return exit, anon, evidence
}

func containsIP(value string, expected netip.Addr) bool {
	for _, field := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '=' || r == '"'
	}) {
		if addr, err := netip.ParseAddr(strings.Trim(field, "[]")); err == nil && addr.Unmap() == expected.Unmap() {
			return true
		}
		if addrPort, err := netip.ParseAddrPort(field); err == nil && addrPort.Addr().Unmap() == expected.Unmap() {
			return true
		}
	}
	return false
}

func jsonPath(value any, path []string) (any, bool) {
	current := value
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[key]
		if !ok {
			return nil, false
		}
	}
	return current, true
}
