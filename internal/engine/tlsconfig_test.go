package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/drag-team/netvex/internal/config"
)

func TestConfigureCABundlesRejectsInvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	checker := NewChecker(config.Defaults())
	if err := checker.ConfigureCABundles(path, ""); err == nil {
		t.Fatal("invalid CA bundle accepted")
	}
}
