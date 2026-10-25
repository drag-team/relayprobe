package store

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/drag-team/relayprobe/internal/model"
)

type RunWriter struct {
	ID     string
	dir    string
	part   string
	final  string
	f      *os.File
	w      *bufio.Writer
	closed bool
}

func NewRunWriter(dataDir string) (*RunWriter, error) {
	dir := filepath.Join(dataDir, "runs")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create history directory: %w", err)
	}
	id := newID()
	part := filepath.Join(dir, id+".jsonl.part")
	final := filepath.Join(dir, id+".jsonl")
	f, err := os.OpenFile(part, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("create run: %w", err)
	}
	return &RunWriter{ID: id, dir: dir, part: part, final: final, f: f, w: bufio.NewWriterSize(f, 128<<10)}, nil
}

func newID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(b[:])
}

func (r *RunWriter) Write(result model.Result) error {
	if r.closed {
		return errors.New("run writer is closed")
	}
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if _, err = r.w.Write(b); err != nil {
		return err
	}
	return r.w.WriteByte('\n')
}

func (r *RunWriter) Commit(summary model.RunSummary) error {
	if r.closed {
		return errors.New("run writer is closed")
	}
	r.closed = true
	if err := r.w.Flush(); err != nil {
		_ = r.f.Close()
		return err
	}
	if err := r.f.Sync(); err != nil {
		_ = r.f.Close()
		return err
	}
	if err := r.f.Close(); err != nil {
		return err
	}
	if err := os.Rename(r.part, r.final); err != nil {
		return fmt.Errorf("commit run: %w", err)
	}
	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	metaPart := filepath.Join(r.dir, r.ID+".summary.json.part")
	metaFinal := filepath.Join(r.dir, r.ID+".summary.json")
	if err := os.WriteFile(metaPart, append(b, '\n'), 0600); err != nil {
		return err
	}
	if err := os.Rename(metaPart, metaFinal); err != nil {
		return err
	}
	d, err := os.Open(r.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (r *RunWriter) Abort() {
	if r.closed {
		return
	}
	r.closed = true
	_ = r.f.Close()
	_ = os.Remove(r.part)
}
func (r *RunWriter) Path() string { return r.final }

func ResolveRun(dataDir, id string) (string, error) {
	dir := filepath.Join(dataDir, "runs")
	if id == "" || id == "latest" {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return "", fmt.Errorf("list runs: %w", err)
		}
		names := []string{}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
				names = append(names, e.Name())
			}
		}
		if len(names) == 0 {
			return "", errors.New("no saved runs")
		}
		sort.Strings(names)
		return filepath.Join(dir, names[len(names)-1]), nil
	}
	if strings.ContainsAny(id, "/\\") {
		if filepath.Ext(id) == ".jsonl" {
			return id, nil
		}
		return "", errors.New("run path must name a .jsonl file")
	}
	if !strings.HasSuffix(id, ".jsonl") {
		id += ".jsonl"
	}
	return filepath.Join(dir, id), nil
}

func ReadResults(path string, emit func(model.Result) error) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open run: %w", err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64<<10), 4<<20)
	line := 0
	for s.Scan() {
		line++
		var r model.Result
		if err := json.Unmarshal(s.Bytes(), &r); err != nil {
			return fmt.Errorf("decode run line %d: %w", line, err)
		}
		if err := emit(r); err != nil {
			return err
		}
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("read run: %w", err)
	}
	return nil
}

func ReadSummary(path string) (model.RunSummary, error) {
	var s model.RunSummary
	f, err := os.Open(strings.TrimSuffix(path, ".jsonl") + ".summary.json")
	if err != nil {
		return s, err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	if err := dec.Decode(&s); err != nil {
		return s, err
	}
	return s, nil
}

func ListRuns(dataDir string, limit int) ([]model.RunSummary, error) {
	dir := filepath.Join(dataDir, "runs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []model.RunSummary{}, nil
		}
		return nil, fmt.Errorf("list runs: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".summary.json") {
			names = append(names, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if len(names) > limit {
		names = names[:limit]
	}
	runs := make([]model.RunSummary, 0, len(names))
	for _, name := range names {
		resultPath := filepath.Join(dir, strings.TrimSuffix(name, ".summary.json")+".jsonl")
		summary, err := ReadSummary(resultPath)
		if err != nil {
			return nil, fmt.Errorf("read summary %s: %w", name, err)
		}
		runs = append(runs, summary)
	}
	return runs, nil
}

func PruneRuns(dataDir string, keep int, execute bool) ([]string, error) {
	if keep < 0 {
		return nil, errors.New("keep must not be negative")
	}
	dir := filepath.Join(dataDir, "runs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("list runs: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".summary.json") {
			names = append(names, strings.TrimSuffix(entry.Name(), ".summary.json"))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if keep >= len(names) {
		return []string{}, nil
	}
	candidates := append([]string(nil), names[keep:]...)
	if !execute {
		return candidates, nil
	}
	for _, id := range candidates {
		for _, suffix := range []string{".jsonl", ".summary.json"} {
			if err := os.Remove(filepath.Join(dir, id+suffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("remove run %s: %w", id, err)
			}
		}
	}
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return nil, err
	}
	return candidates, nil
}

func StreamCopy(dst io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(dst, f)
	return err
}
