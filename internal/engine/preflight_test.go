package engine

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/drag-team/netvex/internal/config"
)

func TestPreflightUsesPinnedApprovedTarget(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local sockets unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Targets = []string{server.URL}
	cfg.AllowedHosts = []string{u.Hostname()}
	cfg.AllowPrivate = true
	checker := NewChecker(cfg)
	health := checker.Preflight(context.Background())[targetOrigin(server.URL)]
	if health.Status != "ok" || health.HTTPStatus != http.StatusNoContent {
		t.Fatalf("health=%+v", health)
	}
}
