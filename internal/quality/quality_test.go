package quality

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drag-team/relayprobe/internal/model"
)

func TestEvaluateAndJUnit(t *testing.T) {
	maximum := 0.2
	summary := model.RunSummary{Processed: 10, Successful: 7, Failed: 3, LatencyP95MS: 200}
	report := Evaluate(Policy{SchemaVersion: 1, MinSuccessRate: .8, MaxFailureRate: &maximum}, summary)
	if report.Passed || len(report.Checks) != 2 {
		t.Fatalf("report=%+v", report)
	}
	summary.Quality = &report
	payload, err := JUnit(summary)
	if err != nil || !strings.Contains(string(payload), `failures="1"`) || !strings.Contains(string(payload), "min_success_rate") {
		t.Fatalf("payload=%s err=%v", payload, err)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown field accepted")
	}
}
