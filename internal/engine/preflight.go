package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/drag-team/netvex/internal/buildinfo"
	"github.com/drag-team/netvex/internal/model"
)

func (c *Checker) Preflight(ctx context.Context) map[string]model.TargetHealth {
	results := make(map[string]model.TargetHealth, len(c.Config.Targets))
	type item struct {
		target string
		health model.TargetHealth
	}
	output := make(chan item, len(c.Config.Targets))
	semaphore := make(chan struct{}, minInt(4, len(c.Config.Targets)))
	for _, target := range c.Config.Targets {
		target := target
		go func() {
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				output <- item{target: c.targetName(target), health: model.TargetHealth{Status: "failed", Code: "interrupted", Message: "preflight interrupted"}}
				return
			}
			output <- item{target: c.targetName(target), health: c.preflightTarget(ctx, target)}
		}()
	}
	for range c.Config.Targets {
		result := <-output
		results[result.target] = result.health
	}
	return results
}

func (c *Checker) preflightTarget(parent context.Context, target string) model.TargetHealth {
	ctx, cancel := context.WithTimeout(parent, c.Config.RequestTimeout)
	defer cancel()
	started := time.Now()
	destination, err := c.Policy.Resolve(ctx, target)
	if err != nil {
		return model.TargetHealth{Status: "failed", Code: "resolve", Message: "target resolution or policy check failed", LatencyMS: ms(time.Since(started))}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: destination.Host}
	if c.TLSConfig != nil {
		tlsConfig = c.TLSConfig.Clone()
		tlsConfig.ServerName = destination.Host
		if tlsConfig.MinVersion == 0 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
	}
	dialer := &net.Dialer{Timeout: c.Config.ConnectTimeout, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(destination.IP.String(), destination.Port))
		},
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   c.Config.ConnectTimeout,
		ResponseHeaderTimeout: c.Config.RequestTimeout,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   c.Config.RequestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, destination.URL.String(), nil)
	if err != nil {
		return model.TargetHealth{Status: "failed", Code: "request", Message: "target request could not be created", LatencyMS: ms(time.Since(started))}
	}
	request.Header.Set("User-Agent", buildinfo.UserAgent())
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Range", "bytes=0-4095")
	response, err := client.Do(request)
	if err != nil {
		return model.TargetHealth{Status: "failed", Code: "request", Message: "direct target request failed", LatencyMS: ms(time.Since(started))}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	health := model.TargetHealth{Status: "ok", HTTPStatus: response.StatusCode, LatencyMS: ms(time.Since(started))}
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		health.Status = "failed"
		health.Code = "http_status"
		health.Message = fmt.Sprintf("target returned HTTP status %d", response.StatusCode)
	}
	return health
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
