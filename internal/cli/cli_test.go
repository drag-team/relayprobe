package cli

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/drag-team/netvex/internal/config"
	"github.com/drag-team/netvex/internal/model"
	"github.com/drag-team/netvex/internal/store"
)

func run(args []string, in string) (int, string, string) {
	var out, err bytes.Buffer
	c := CLI{Stdout: &out, Stderr: &err, Stdin: strings.NewReader(in)}
	code := c.Run(args)
	return code, out.String(), err.String()
}

func assertPrivateMode(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%v err=%v", info, err)
	}
}
func TestImportAndRedaction(t *testing.T) {
	code, out, diag := run([]string{"import"}, "http://user:secret@host:80\nbad\n")
	if code != ExitOK {
		t.Fatalf("code=%d %s", code, diag)
	}
	if strings.Contains(out, "secret") || !strings.Contains(out, "***") {
		t.Fatalf("leak/output %q", out)
	}
	if !strings.Contains(diag, "rejected=1") {
		t.Fatalf("diag=%q", diag)
	}
}

func TestExplicitStandardInputSource(t *testing.T) {
	code, out, diag := run([]string{"import", "-"}, "1.2.3.4:8080:user:password\n")
	if code != ExitOK || !strings.Contains(out, "http://***:***@1.2.3.4:8080") || !strings.Contains(diag, "accepted=1") {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
	if code, _, _ = run([]string{"import", "-", "-"}, "host:80\n"); code != ExitUsage {
		t.Fatalf("duplicate stdin code=%d", code)
	}
}
func TestExitCodesAndUnknownCommand(t *testing.T) {
	if code, _, diag := run([]string{"wat"}, ""); code != ExitUsage || !strings.Contains(diag, "netvex") {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	if code, _, _ := run([]string{"import"}, "bad\n"); code != ExitNoValidInput {
		t.Fatalf("code %d", code)
	}
	if code, _, _ := run([]string{"check", "--concurrency", "0"}, ""); code != ExitUsage {
		t.Fatalf("explicit zero concurrency code %d", code)
	}
	if code, _, _ := run([]string{"check", "--rate", "NaN"}, ""); code != ExitUsage {
		t.Fatalf("NaN rate code %d", code)
	}
	if code, _, _ := run([]string{"check", "--min-success-rate", "0"}, ""); code != ExitUsage {
		t.Fatalf("zero success rate code %d", code)
	}
}

func TestHelpUsesNetVexIdentity(t *testing.T) {
	code, out, diag := run([]string{"help"}, "")
	if code != ExitOK || !strings.Contains(out, "NetVex") || !strings.Contains(out, "Usage: netvex") || diag != "" {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
}

func TestCheckEndToEndThroughControlledConnectProxy(t *testing.T) {
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local sockets unavailable: %v", err)
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"origin":"8.8.8.8","headers":{}}`)
	}))
	target.Listener = targetListener
	target.Start()
	defer target.Close()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local proxy socket unavailable: %v", err)
	}
	defer listener.Close()
	proxyDone := make(chan struct{})
	go func() {
		defer close(proxyDone)
		client, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer client.Close()
		reader := bufio.NewReader(client)
		request, readErr := http.ReadRequest(reader)
		if readErr != nil || request.Method != http.MethodConnect {
			return
		}
		upstream, dialErr := net.Dial("tcp", request.Host)
		if dialErr != nil {
			return
		}
		defer upstream.Close()
		_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		requestDone := make(chan struct{})
		go func() {
			_, _ = io.Copy(upstream, reader)
			close(requestDone)
		}()
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
		<-requestDone
	}()

	code, stdout, stderr := run([]string{"check", "--profile", "fast", "--protocol", "http", "--format", "jsonl", "--allow-private-targets", "--target", target.URL}, listener.Addr().String()+"\n")
	if code != ExitOK {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	var result model.Result
	if err := json.Unmarshal(bytes.TrimSpace([]byte(stdout)), &result); err != nil {
		t.Fatalf("decode output: %v output=%q", err, stdout)
	}
	if result.Status != model.StatusOK || result.Successes != 1 || len(result.Observations) != 1 || result.Observations[0].ExitIP != "8.8.8.8" || result.Observations[0].BodySHA256 == "" {
		t.Fatalf("result=%+v", result)
	}
	select {
	case <-proxyDone:
	case <-time.After(time.Second):
		t.Fatal("controlled proxy did not terminate")
	}
}

func TestSubcommandHelpIsSuccessful(t *testing.T) {
	for _, cmd := range []string{"check", "import", "results", "runs", "export", "stats", "history", "pool", "shard", "merge", "explore", "config", "doctor", "bench"} {
		code, out, _ := run([]string{cmd, "--help"}, "")
		if code != ExitOK || !strings.Contains(out, "Usage of") {
			t.Fatalf("%s code=%d out=%q", cmd, code, out)
		}
	}
}

func TestShardDistributesNormalizedCredentials(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(input, []byte("1.2.3.4:80:user:pass\nproxy.test:8080\nproxy.test:8080\n"), 0600); err != nil {
		t.Fatal(err)
	}
	code, _, diag := run([]string{"shard", "--shards", "2", "--output-dir", dir, "--prefix", "part", input}, "")
	if code != ExitOK || !strings.Contains(diag, "accepted=2") || !strings.Contains(diag, "duplicates=1") {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	combined := ""
	for i := 1; i <= 2; i++ {
		path := filepath.Join(dir, fmt.Sprintf("part-%04d-of-0002.txt", i))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		combined += string(data)
		assertPrivateMode(t, path)
	}
	if !strings.Contains(combined, "http://user:pass@1.2.3.4:80") || !strings.Contains(combined, "http://proxy.test:8080") {
		t.Fatalf("combined=%q", combined)
	}
}

func TestMergeBestAndRotationFilters(t *testing.T) {
	dir := t.TempDir()
	older := filepath.Join(dir, "older.jsonl")
	newer := filepath.Join(dir, "newer.jsonl")
	low, high := 10.0, 90.0
	base := model.Result{SchemaVersion: model.SchemaVersion, ID: "same", Proxy: "http://host:80", Endpoint: "host:80", Protocol: model.ProtocolHTTP, Status: model.StatusFailed, Score: model.Score{Value: &low}, CheckedAt: time.Now().Add(-time.Hour)}
	best := base
	best.Status, best.Score.Value, best.CheckedAt = model.StatusOK, &high, time.Now()
	best.Label = "pool-a"
	best.Rotation = model.RotationProfile{Classification: "rotating", UniqueExitIPs: 3}
	for path, result := range map[string]model.Result{older: base, newer: best} {
		payload, _ := json.Marshal(result)
		if err := os.WriteFile(path, append(payload, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "merged.jsonl")
	code, _, diag := run([]string{"merge", "--strategy", "best", "--output", out, older, newer}, "")
	if code != ExitOK || !strings.Contains(diag, "merged=1") {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	code, stdout, diag := run([]string{"results", "--run", out, "--format", "jsonl", "--label", "pool-a", "--rotation", "rotating", "--min-unique-exits", "3"}, "")
	if code != ExitOK || !strings.Contains(stdout, `"status":"ok"`) {
		t.Fatalf("code=%d stdout=%q diag=%q", code, stdout, diag)
	}
}

func TestQualityPolicyAndJUnit(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"schema_version":1,"min_successful":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	junit := filepath.Join(dir, "report.xml")
	code, _, diag := run([]string{"check", "--quiet", "--target", "http://127.0.0.1/", "--policy", policyPath, "--junit-output", junit}, "proxy.test:8080\n")
	if code != ExitNoSuccess || !strings.Contains(diag, "quality gate failed") {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	payload, err := os.ReadFile(junit)
	if err != nil || !strings.Contains(string(payload), `failures="1"`) {
		t.Fatalf("junit=%q err=%v", payload, err)
	}
}

func TestResumeIncludesCheckpointResults(t *testing.T) {
	dir := t.TempDir()
	checkpoint := filepath.Join(dir, "checkpoint.jsonl")
	input := "proxy.test:8080\n"
	args := []string{"check", "--quiet", "--target", "http://127.0.0.1/", "--checkpoint", checkpoint}
	if code, _, diag := run(args, input); code != ExitOK {
		t.Fatalf("initial code=%d diag=%q", code, diag)
	}
	summaryPath := filepath.Join(dir, "summary.json")
	code, _, diag := run([]string{"check", "--quiet", "--target", "http://127.0.0.1/", "--resume", checkpoint, "--summary-output", summaryPath}, input)
	if code != ExitOK {
		t.Fatalf("resume code=%d diag=%q", code, diag)
	}
	payload, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatal(err)
	}
	var summary model.RunSummary
	if err := json.Unmarshal(payload, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Processed != 1 || summary.Restored != 1 || summary.Input.Resumed != 1 || summary.Failed != 1 || summary.RatePerSec != 0 {
		t.Fatalf("summary=%+v", summary)
	}
	if code, _, _ := run([]string{"check", "--resume", checkpoint, "--working-output", filepath.Join(dir, "working.txt")}, input); code != ExitUsage {
		t.Fatalf("resume working-output code=%d", code)
	}
}

func TestShellCompletions(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		code, out, diag := run([]string{"completion", shell}, "")
		if code != ExitOK || !strings.Contains(out, "netvex") || !strings.Contains(out, "auto-probe-timeout") || !strings.Contains(out, "intelligence-bytes") || diag != "" {
			t.Fatalf("shell=%s code=%d out=%q diag=%q", shell, code, out, diag)
		}
	}
}

func TestConfigInitDoesNotOverwrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if code, out, diag := run([]string{"config", "init", "--config", p}, ""); code != ExitOK || out != p+"\n" {
		t.Fatalf("%d out=%q diag=%s", code, out, diag)
	}
	assertPrivateMode(t, p)
	if code, _, _ := run([]string{"config", "init", "--config", p}, ""); code != ExitOperational {
		t.Fatalf("overwrite code=%d", code)
	}
	if code, out, diag := run([]string{"config", "init", "--config", p, "--force"}, ""); code != ExitOK || out != p+"\n" {
		t.Fatalf("force code=%d out=%q diag=%s", code, out, diag)
	}
	if code, _, _ := run([]string{"config", "validate", "--config", p}, ""); code != ExitOK {
		t.Fatalf("validate code=%d", code)
	}
}

func TestSavedResultCommands(t *testing.T) {
	d := t.TempDir()
	w, err := store.NewRunWriter(d)
	if err != nil {
		t.Fatal(err)
	}
	v := 80.0
	r := model.Result{ID: "a", Proxy: "http://host:80", Endpoint: "host:80", Protocol: model.ProtocolHTTP, Status: model.StatusOK, Attempts: 2, Successes: 2, Score: model.Score{Value: &v, MedianMS: 20}, Observations: []model.Observation{{Status: model.StatusOK, ExitIP: "8.8.8.8", Anonymity: "elite", ThroughputKBPS: 500, Metadata: &model.ExitMetadata{CountryCode: "US", ASN: "AS15169", NetworkType: "residential"}}}}
	if err = w.Write(r); err != nil {
		t.Fatal(err)
	}
	s := model.RunSummary{RunID: w.ID, StartedAt: time.Now(), FinishedAt: time.Now(), Processed: 1, Successful: 1}
	if err = w.Commit(s); err != nil {
		t.Fatal(err)
	}
	code, out, diag := run([]string{"results", "--data-dir", d, "--run", "latest", "--format", "jsonl", "--exit-ip", "8.8.8.8", "--country", "US", "--asn", "15169", "--network-type", "residential", "--min-score", "75", "--min-throughput-kbps", "100", "--sort", "score"}, "")
	if code != ExitOK || !strings.Contains(out, "host:80") {
		t.Fatalf("%d %s %s", code, out, diag)
	}
	dst := filepath.Join(d, "out.csv")
	if code, _, diag = run([]string{"export", "--data-dir", d, "--run", "latest", "--format", "csv", "--country", "US", "--min-score", "75", "--max-latency", "25", "--output", dst}, ""); code != ExitOK {
		t.Fatalf("export %d %s", code, diag)
	}
	if code, _, _ := run([]string{"export", "--data-dir", d, "--run", "latest", "--format", "csv", "--output", dst}, ""); code != ExitOperational {
		t.Fatalf("overwrite export=%d", code)
	}
	if code, _, _ := run([]string{"export", "--run", w.Path(), "--output", w.Path(), "--force"}, ""); code != ExitUsage {
		t.Fatalf("source overwrite export=%d", code)
	}
	if code, out, diag = run([]string{"stats", "--data-dir", d, "--run", "latest", "--compare", w.ID, "--json"}, ""); code != ExitOK || !strings.Contains(out, "baseline") {
		t.Fatalf("stats %d %s %s", code, out, diag)
	}
}

func TestRunsListsSavedSummaries(t *testing.T) {
	dir := t.TempDir()
	w, err := store.NewRunWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := model.RunSummary{SchemaVersion: model.SchemaVersion, RunID: w.ID, StartedAt: time.Now().UTC(), Processed: 3, Successful: 2, Failed: 1}
	if err := w.Commit(s); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	c := CLI{Stdout: &stdout, Stderr: &stderr, Stdin: strings.NewReader("")}
	if code := c.Run([]string{"runs", "--data-dir", dir}); code != ExitOK {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), w.ID) || !strings.Contains(stdout.String(), "PROCESSED") {
		t.Fatalf("output=%q", stdout.String())
	}
}

func TestRunConfigurationSanitizesTargetSecrets(t *testing.T) {
	cfg := config.Defaults()
	cfg.Targets = []string{"https://target.test/private/token?api_key=secret#fragment"}
	r := runConfiguration(cfg, model.ProtocolHTTP, checkOptions{profile: "fast"})
	if len(r.ValidationTarget) != 1 || r.ValidationTarget[0] != "https://target.test/" {
		t.Fatalf("targets=%v", r.ValidationTarget)
	}
}

func TestSavedRunAggregatesSanitizedTargetHealth(t *testing.T) {
	dir := t.TempDir()
	code, _, diag := run([]string{"check", "--target", "http://127.0.0.1/private?token=secret", "--quiet", "--save", "--data-dir", dir}, "proxy.test:8080\n")
	if code != ExitOK {
		t.Fatalf("code=%d diag=%s", code, diag)
	}
	path, err := store.ResolveRun(dir, "latest")
	if err != nil {
		t.Fatal(err)
	}
	summary, err := store.ReadSummary(path)
	if err != nil {
		t.Fatal(err)
	}
	target, ok := summary.Targets["http://127.0.0.1/"]
	if !ok || target.Attempts != 1 || target.Failed != 1 || strings.Contains(fmt.Sprint(summary), "secret") {
		t.Fatalf("summary=%+v", summary)
	}
}

func TestCredentialInputPermissionWarning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file permissions are represented by ACLs")
	}
	path := filepath.Join(t.TempDir(), "credentials.txt")
	if err := os.WriteFile(path, []byte("http://user:secret@proxy.test:8080\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	code, _, diag := run([]string{"check", "--target", "http://127.0.0.1/", "--quiet", path}, "")
	if code != ExitOK || !strings.Contains(diag, "security warning") || !strings.Contains(diag, "chmod 600") {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
}

func TestPlainOverridesForcedColor(t *testing.T) {
	c := CLI{IsTerminal: true}
	cfg, p, f, color, err := c.loadCheck(checkOptions{protocol: "http", format: "table", inputFormat: "text", color: "always", plain: true, rate: -1, maxRedirects: -1})
	_ = cfg
	_ = p
	_ = f
	if err != nil {
		t.Fatal(err)
	}
	if color {
		t.Fatal("plain mode emitted color")
	}
}

func TestExecutionProfilesAndOverrides(t *testing.T) {
	c := CLI{}
	cfg, _, _, _, err := c.loadCheck(checkOptions{profile: "fast", protocol: "http", format: "table", inputFormat: "text", color: "never", rate: -1, maxRedirects: -1, repeat: 3})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Repeat != 3 || cfg.MinSuccessRate != 1 || !cfg.StopOnSuccess || cfg.RequestTimeout != 8*time.Second || cfg.RetryBackoff != 0 {
		t.Fatalf("unexpected profile: %+v", cfg)
	}
	if _, _, _, _, err := c.loadCheck(checkOptions{profile: "turbo", protocol: "http", format: "table", inputFormat: "text", color: "never", rate: -1, maxRedirects: -1}); err == nil {
		t.Fatal("accepted unknown profile")
	}
}

func TestExplicitFalseBooleanOverridesEnvironmentAndProfile(t *testing.T) {
	t.Setenv("NETVEX_ALLOW_REMOTE_DNS", "true")
	t.Setenv("NETVEX_SAVE", "true")
	o := checkOptions{
		profile: "fast", protocol: "http", format: "table", inputFormat: "text",
		color: "never", rate: -1, maxRedirects: -1,
		explicit: map[string]bool{"allow-remote-dns": true, "save": true, "stop-on-success": true},
	}
	cfg, _, _, _, err := (CLI{}).loadCheck(o)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AllowRemoteDNS || cfg.Save || cfg.StopOnSuccess {
		t.Fatalf("explicit false values did not override configuration: %+v", cfg)
	}
}

func TestContentThroughputAndBaselineOptions(t *testing.T) {
	o := checkOptions{
		protocol: "https", format: "jsonl", inputFormat: "text", color: "never",
		rate: -1, maxRedirects: -1, maxResponseBytes: 2 << 20, intelligenceBytes: 96 << 10, minResponseBytes: 32 << 10, minThroughput: 250,
		requireText: stringsFlag{"expected-json"}, rejectText: stringsFlag{"access denied"},
		expectJSON: stringsFlag{"status=ok"},
		baselineIP: "198.51.100.10", autoProbeTimeout: "1500ms",
	}
	cfg, proto, _, _, err := (CLI{}).loadCheck(o)
	if err != nil {
		t.Fatal(err)
	}
	if proto != model.ProtocolHTTPS || cfg.MaxResponseBytes != 2<<20 || cfg.IntelligenceBytes != 96<<10 || cfg.AutoProbeTimeout != 1500*time.Millisecond || cfg.MinResponseBytes != 32<<10 || cfg.MinThroughputKBPS != 250 || len(cfg.RequireText) != 1 || len(cfg.RejectText) != 1 || len(cfg.ExpectJSON) != 1 || cfg.AnonymityBaseline != "198.51.100.10" {
		t.Fatalf("cfg=%+v proto=%s", cfg, proto)
	}
}

func TestSecureWorkingOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "working.txt")
	out, err := openSecureOutput(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = out.WriteLine("http://user:secret@host:80"); err != nil {
		t.Fatal(err)
	}
	if err = out.Commit(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "http://user:secret@host:80\n" {
		t.Fatalf("%q", b)
	}
	assertPrivateMode(t, path)
	if _, err = openSecureOutput(path, false); err == nil {
		t.Fatal("existing file overwritten")
	}
	if out, err = openSecureOutput(path, true); err != nil {
		t.Fatal(err)
	} else {
		_ = out.Commit()
	}
}

func TestSecureWorkingOutputAbortPreservesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "working.txt")
	if err := os.WriteFile(path, []byte("old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := openSecureOutput(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := out.WriteLine("new"); err != nil {
		t.Fatal(err)
	}
	out.Abort()
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "old\n" {
		t.Fatalf("existing output changed: %q %v", b, err)
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".working.txt.*.tmp"))
	if len(matches) != 0 {
		t.Fatalf("temporary files leaked: %v", matches)
	}
}

func TestNoValidInputDoesNotReplaceWorkingOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "working.txt")
	if err := os.WriteFile(path, []byte("old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	c := CLI{Stdin: strings.NewReader("not-a-proxy\n"), Stdout: &stdout, Stderr: &stderr}
	if code := c.Run([]string{"check", "--working-output", path, "--force", "--quiet"}); code != ExitNoValidInput {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "old\n" {
		t.Fatalf("existing output changed: %q %v", b, err)
	}
}

func TestSummaryOutputRequireCountAndAtomicPreservation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.json")
	args := []string{"check", "--target", "http://127.0.0.1/", "--quiet", "--summary-output", path, "--require-count", "1"}
	code, _, diag := run(args, "proxy.test:8080\n")
	if code != ExitNoSuccess || !strings.Contains(diag, "saved run summary") {
		t.Fatalf("code=%d diag=%q", code, diag)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var summary model.RunSummary
	if err := json.Unmarshal(b, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Processed != 1 || summary.Successful != 0 || summary.StatusCount[model.StatusPolicyBlock] != 1 {
		t.Fatalf("summary=%+v", summary)
	}
	assertPrivateMode(t, path)
	if code, _, _ := run(args, "proxy.test:8080\n"); code != ExitOperational {
		t.Fatalf("existing summary code=%d", code)
	}
	before := append([]byte(nil), b...)
	forceArgs := []string{"check", "--quiet", "--summary-output", path, "--force"}
	if code, _, _ := run(forceArgs, "invalid\n"); code != ExitNoValidInput {
		t.Fatalf("no-input code=%d", code)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("summary changed after incomplete run: err=%v", err)
	}
	if code, _, _ := run([]string{"check", "--require-count=-1"}, ""); code != ExitUsage {
		t.Fatalf("negative require-count code=%d", code)
	}
}

func TestGzipImportAndCanonicalPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxies.csv.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err := zw.Write([]byte("host,port\nproxy.test,8080\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	code, out, diag := run([]string{"import", path}, "")
	if code != ExitOK || out != "http://proxy.test:8080\n" {
		t.Fatalf("code=%d out=%q diag=%q", code, out, diag)
	}
	aliasRoot := t.TempDir()
	alias := filepath.Join(aliasRoot, "data")
	if err := os.Symlink(dir, alias); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symbolic links require an elevated Windows privilege")
		}
		t.Fatal(err)
	}
	plain := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(plain, []byte("proxy.test:80\n"), 0600); err != nil {
		t.Fatal(err)
	}
	same, err := samePath(plain, filepath.Join(alias, "plain.txt"))
	if err != nil || !same {
		t.Fatalf("same=%v err=%v", same, err)
	}
	if _, err := canonicalPath(filepath.Join(alias, "new", "nested", "output.json")); err != nil {
		t.Fatal(err)
	}
}
