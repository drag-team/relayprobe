package store

import (
	"github.com/drag-team/netvex/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAtomicRunAndRead(t *testing.T) {
	d := t.TempDir()
	w, err := NewRunWriter(d)
	if err != nil {
		t.Fatal(err)
	}
	r := model.Result{ID: "x", Proxy: "http://u:***@host:80", Status: model.StatusOK}
	if err := w.Write(r); err != nil {
		t.Fatal(err)
	}
	s := model.RunSummary{RunID: w.ID, StartedAt: time.Now(), Processed: 1, Successful: 1}
	if err := w.Commit(s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(w.Path()); err != nil {
		t.Fatal(err)
	}
	n := 0
	if err := ReadResults(w.Path(), func(g model.Result) error {
		n++
		if strings.Contains(g.Proxy, "secret") {
			t.Fatal("secret leaked")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("n=%d", n)
	}
	latest, err := ResolveRun(d, "latest")
	if err != nil || latest != w.Path() {
		t.Fatalf("latest=%s err=%v", latest, err)
	}
}

func TestListRunsNewestFirst(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		w, err := NewRunWriter(dir)
		if err != nil {
			t.Fatal(err)
		}
		s := model.RunSummary{SchemaVersion: model.SchemaVersion, RunID: w.ID, StartedAt: time.Now(), Processed: i + 1}
		if err := w.Commit(s); err != nil {
			t.Fatal(err)
		}
	}
	runs, err := ListRuns(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || runs[0].RunID <= runs[1].RunID {
		t.Fatalf("unexpected order: %+v", runs)
	}
	empty, err := ListRuns(filepath.Join(dir, "missing"), 10)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty list: %+v %v", empty, err)
	}
	plan, err := PruneRuns(dir, 1, false)
	if err != nil || len(plan) != 1 {
		t.Fatalf("prune plan=%v err=%v", plan, err)
	}
	if runs, _ := ListRuns(dir, 10); len(runs) != 2 {
		t.Fatal("dry-run removed data")
	}
	removed, err := PruneRuns(dir, 1, true)
	if err != nil || len(removed) != 1 {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
	if runs, _ := ListRuns(dir, 10); len(runs) != 1 {
		t.Fatalf("unexpected retained runs: %+v", runs)
	}
}
