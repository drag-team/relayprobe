package fsx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceExistingFile(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old")
	newPath := filepath.Join(dir, "new")
	if err := os.WriteFile(oldPath, []byte("new contents"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("old contents"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Replace(oldPath, newPath); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(newPath)
	if err != nil || string(contents) != "new contents" {
		t.Fatalf("contents=%q err=%v", contents, err)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("source remains after replacement: %v", err)
	}
	if err := SyncParent(newPath); err != nil {
		t.Fatal(err)
	}
}
