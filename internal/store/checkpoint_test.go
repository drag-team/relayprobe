package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/drag-team/netvex/internal/model"
)

func TestCheckpointResumeAndPartialRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint.jsonl")
	checkpoint, completed, err := OpenCheckpoint(path, false, false, 1, 100)
	if err != nil || len(completed) != 0 {
		t.Fatalf("open err=%v completed=%v", err, completed)
	}
	if err := checkpoint.Write(model.Result{ID: "one", Status: model.StatusOK}); err != nil {
		t.Fatal(err)
	}
	if err := checkpoint.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString(`{"id":"partial"`)
	_ = file.Close()
	checkpoint, completed, err = OpenCheckpoint(path, true, false, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := completed["one"]; !ok || len(completed) != 1 {
		t.Fatalf("completed=%v", completed)
	}
	if err := checkpoint.Write(model.Result{ID: "two", Status: model.StatusOK}); err != nil {
		t.Fatal(err)
	}
	if err := checkpoint.Close(); err != nil {
		t.Fatal(err)
	}
	ids, err := readCheckpointIDs(path, 100)
	if err != nil || len(ids) != 2 {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
}

func TestCheckpointRejectsUnsafeExistingFiles(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		permissive := filepath.Join(dir, "permissive.jsonl")
		if err := os.WriteFile(permissive, []byte("partial"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(permissive, 0644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := OpenCheckpoint(permissive, true, false, 1, 10); err == nil {
			t.Fatal("permissive checkpoint accepted")
		}
		contents, err := os.ReadFile(permissive)
		if err != nil || string(contents) != "partial" {
			t.Fatalf("unsafe file was modified: %q %v", contents, err)
		}
	}
	target := filepath.Join(dir, "target.jsonl")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symbolic links require an elevated Windows privilege")
		}
		t.Fatal(err)
	}
	if _, _, err := OpenCheckpoint(link, true, false, 1, 10); err == nil {
		t.Fatal("symbolic-link checkpoint accepted")
	}
}

func TestCheckpointRejectsConcurrentWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint.jsonl")
	first, _, err := OpenCheckpoint(path, false, false, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, _, err := OpenCheckpoint(path, true, false, 10, 100); err == nil {
		t.Fatal("concurrent checkpoint writer accepted")
	}
}
