package scenario

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/drag-team/netvex/internal/config"
)

func TestLoadAndApplyScenario(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scenario.json")
	data := `{"schema_version":1,"name":"commerce","repeat":3,"target_matrix":true,"target_quorum":1,"targets":[{"url":"https://shop.test/","min_http_status":200,"max_http_status":299,"require_text":["catalog"]}]}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	document, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	if err := Apply(document, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Repeat != 3 || !cfg.TargetMatrix || cfg.TargetQuorum != 1 || len(cfg.TargetRules) != 1 || cfg.TargetRules["https://shop.test/"].RequireText[0] != "catalog" {
		t.Fatalf("config=%+v", cfg)
	}
}

func TestScenarioRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scenario.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"name":"x","unknown":true,"targets":[{"url":"https://x.test/"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown field accepted")
	}
}
