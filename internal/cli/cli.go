package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/drag-team/relayprobe/internal/buildinfo"
	"github.com/drag-team/relayprobe/internal/config"
	"github.com/drag-team/relayprobe/internal/engine"
	inputpkg "github.com/drag-team/relayprobe/internal/input"
	metadatapkg "github.com/drag-team/relayprobe/internal/metadata"
	"github.com/drag-team/relayprobe/internal/metrics"
	"github.com/drag-team/relayprobe/internal/model"
	"github.com/drag-team/relayprobe/internal/output"
	"github.com/drag-team/relayprobe/internal/store"
)

const (
	ExitOK           = 0
	ExitUsage        = 2
	ExitOperational  = 3
	ExitNoValidInput = 4
	ExitNoSuccess    = 5
	ExitInterrupted  = 130
)

type CLI struct {
	Stdout, Stderr io.Writer
	Stdin          io.Reader
	IsTerminal     bool
}

func (c CLI) Run(args []string) int {
	if len(args) == 0 {
		return c.help()
	}
	switch args[0] {
	case "help", "--help", "-h":
		return c.help()
	case "version", "--version":
		fmt.Fprintf(c.Stdout, "relayprobe %s commit=%s built=%s go=%s\n", buildinfo.Version, buildinfo.Commit, buildinfo.Date, runtime.Version())
		return ExitOK
	case "check":
		return c.check(args[1:], false)
	case "inspect":
		return c.inspect(args[1:])
	case "import":
		return c.importCmd(args[1:])
	case "results":
		return c.results(args[1:])
	case "runs":
		return c.runs(args[1:])
	case "export":
		return c.export(args[1:])
	case "stats":
		return c.stats(args[1:])
	case "config":
		return c.configCmd(args[1:])
	case "doctor":
		return c.doctor(args[1:])
	case "bench":
		return c.bench(args[1:])
	case "completion":
		return c.completion(args[1:])
	default:
		fmt.Fprintf(c.Stderr, "relayprobe: unknown command %q; run 'relayprobe help'\n", args[0])
		return ExitUsage
	}
}

func (c CLI) help() int {
	fmt.Fprint(c.Stdout, `RelayProbe — proxy validation and intelligence

Usage: relayprobe <command> [options]

Commands:
  check      validate proxy datasets with bounded concurrency
  inspect    deeply inspect one proxy
  import     normalize and validate input without network access
  results    filter a saved run
  runs       list saved validation runs
  export     export a saved run as JSONL, CSV, or TXT
  stats      summarize a saved run
  config     show, validate, or initialize configuration
  doctor     diagnose the local runtime and optional network resolution
  bench      run a controlled scheduler benchmark
  completion generate shell completion for bash, zsh, or fish
  version    show build information

Run 'relayprobe <command> --help' for command options.
Exit codes: 0 completed, 2 usage/config, 3 operational, 4 no valid input,
5 validation threshold not met (--require-success/--require-count), 130 interrupted.
`)
	return ExitOK
}

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

type checkOptions struct {
	configPath, profile, format, inputFormat, protocol, color   string
	concurrency, queueSize, perTarget, repeat                   int
	connectTimeout, requestTimeout, dnsCacheTTL, retryBackoff   string
	progressInterval                                            string
	targets, allowHosts, requireText, rejectText, expectJSON    stringsFlag
	allowPrivate, allowRemoteDNS, save, requireSuccess, verbose bool
	dataDir                                                     string
	maxRedirects                                                int
	requireCount                                                int
	minResponseBytes                                            int64
	rate, minSuccessRate, minThroughput                         float64
	baselineIP, metadataFile                                    string
	plain                                                       bool
	workingOutput                                               string
	summaryOutput                                               string
	forceWorking                                                bool
	noDeduplicate, retryPermanent, stopOnSuccess, quiet         bool
	outputStatus                                                string
	explicit                                                    map[string]bool
}

func (c CLI) newFlagSet(name string) (*flag.FlagSet, *bytesBuffer) {
	b := &bytesBuffer{}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(b)
	return fs, b
}

type bytesBuffer struct{ strings.Builder }

func (c CLI) parseFlags(fs *flag.FlagSet, buf *bytesBuffer, args []string) (bool, int) {
	err := fs.Parse(args)
	if err == nil {
		return true, ExitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(c.Stdout, buf.String())
		return false, ExitOK
	}
	fmt.Fprint(c.Stderr, buf.String())
	return false, ExitUsage
}

func (c CLI) addCheckFlags(fs *flag.FlagSet, o *checkOptions) {
	fs.StringVar(&o.configPath, "config", "", "JSON configuration file")
	fs.StringVar(&o.profile, "profile", "", "execution profile: fast, balanced, thorough")
	fs.StringVar(&o.format, "format", "table", "output: table, jsonl, csv, txt")
	fs.StringVar(&o.inputFormat, "input-format", "auto", "input: auto, text, csv, json, jsonl")
	fs.StringVar(&o.protocol, "protocol", "http", "default protocol: http, https, socks4, socks4a, socks5, auto")
	fs.StringVar(&o.color, "color", "auto", "color: auto, always, never")
	fs.BoolVar(&o.plain, "plain", false, "disable ANSI styling for plain terminal output")
	fs.IntVar(&o.concurrency, "concurrency", 0, "global concurrency (1..4096)")
	fs.IntVar(&o.queueSize, "queue-size", 0, "bounded input/result queue size (1..65536)")
	fs.IntVar(&o.perTarget, "per-target", 0, "per-target concurrency")
	fs.Float64Var(&o.rate, "rate", -1, "maximum validation attempts per second; 0 disables")
	fs.IntVar(&o.repeat, "repeat", 0, "measurements per proxy (1..20)")
	fs.Float64Var(&o.minSuccessRate, "min-success-rate", -1, "minimum successful measurement ratio (0..1]")
	fs.Int64Var(&o.minResponseBytes, "min-response-bytes", -1, "minimum response body size for a successful measurement")
	fs.Float64Var(&o.minThroughput, "min-throughput-kbps", -1, "minimum measured response-body throughput in decimal KB/s")
	fs.Var(&o.requireText, "require-text", "case-insensitive response substring required for success (repeatable)")
	fs.Var(&o.rejectText, "reject-text", "case-insensitive response substring that fails validation (repeatable)")
	fs.Var(&o.expectJSON, "expect-json", "required dot.path=value JSON assertion (repeatable)")
	fs.StringVar(&o.baselineIP, "baseline-ip", "", "local public IP used for evidence-based anonymity classification")
	fs.StringVar(&o.metadataFile, "metadata-file", "", "offline exit-IP metadata CSV or CSV.gz database")
	fs.StringVar(&o.connectTimeout, "connect-timeout", "", "TCP connect timeout")
	fs.StringVar(&o.requestTimeout, "request-timeout", "", "overall attempt timeout")
	fs.StringVar(&o.dnsCacheTTL, "dns-cache-ttl", "", "cache approved target DNS answers (0 disables)")
	fs.StringVar(&o.retryBackoff, "retry-backoff", "", "initial exponential backoff after transient failure")
	fs.StringVar(&o.progressInterval, "progress-interval", "", "verbose progress refresh interval (50ms..1m)")
	fs.Var(&o.targets, "target", "validation URL (repeatable)")
	fs.Var(&o.allowHosts, "allow-host", "additional redirect hostname (repeatable)")
	fs.BoolVar(&o.allowPrivate, "allow-private-targets", false, "allow private/loopback validation destinations (dangerous)")
	fs.BoolVar(&o.allowRemoteDNS, "allow-remote-dns", false, "allow proxy-side DNS for SOCKS4a/SOCKS5 and HTTP CONNECT/forwarding (reduces rebinding protection)")
	fs.BoolVar(&o.retryPermanent, "retry-permanent", false, "repeat authentication, policy, and invalid-protocol failures")
	fs.BoolVar(&o.stopOnSuccess, "stop-on-success", false, "stop remaining measurements once the reliability threshold is reached")
	fs.BoolVar(&o.noDeduplicate, "no-deduplicate", false, "disable exact deduplication to use bounded parser memory")
	fs.BoolVar(&o.quiet, "quiet", false, "suppress per-proxy stdout; summaries and errors remain on stderr")
	fs.StringVar(&o.outputStatus, "output-status", "all", "stdout results: all, ok, failed, timeout, auth_failed, policy_blocked, invalid, inconclusive, unreliable, interrupted")
	fs.StringVar(&o.workingOutput, "working-output", "", "write validated proxies with credentials to a mode-0600 file")
	fs.StringVar(&o.summaryOutput, "summary-output", "", "atomically write the run summary as JSON")
	fs.BoolVar(&o.forceWorking, "force", false, "replace an existing working or summary output file")
	fs.BoolVar(&o.save, "save", false, "persist run results locally")
	fs.StringVar(&o.dataDir, "data-dir", "", "history directory")
	fs.IntVar(&o.maxRedirects, "max-redirects", -1, "safe redirects to follow (0..10)")
	fs.BoolVar(&o.requireSuccess, "require-success", false, "exit 5 when no proxy validates")
	fs.IntVar(&o.requireCount, "require-count", 0, "exit 5 unless at least this many proxies validate")
	fs.BoolVar(&o.verbose, "verbose", false, "show rejected inputs and progress on stderr")
}

func (c CLI) loadCheck(o checkOptions) (config.Config, model.Protocol, output.Format, bool, error) {
	cfg, err := config.Load(o.configPath)
	if err != nil {
		return cfg, "", "", false, err
	}
	if err := applyProfile(&cfg, o.profile); err != nil {
		return cfg, "", "", false, err
	}
	if o.concurrency != 0 {
		cfg.Concurrency = o.concurrency
	}
	if o.queueSize != 0 {
		cfg.QueueSize = o.queueSize
	}
	if o.perTarget != 0 {
		cfg.PerTarget = o.perTarget
	}
	if o.rate != -1 {
		cfg.RateLimit = o.rate
	}
	if o.repeat != 0 {
		cfg.Repeat = o.repeat
	}
	if o.minSuccessRate != -1 && o.minSuccessRate != 0 {
		cfg.MinSuccessRate = o.minSuccessRate
	}
	if o.minResponseBytes > 0 || o.explicit["min-response-bytes"] {
		cfg.MinResponseBytes = o.minResponseBytes
	}
	if o.minThroughput > 0 || o.explicit["min-throughput-kbps"] {
		cfg.MinThroughputKBPS = o.minThroughput
	}
	if len(o.requireText) > 0 {
		cfg.RequireText = append([]string(nil), o.requireText...)
	}
	if len(o.rejectText) > 0 {
		cfg.RejectText = append([]string(nil), o.rejectText...)
	}
	if len(o.expectJSON) > 0 {
		cfg.ExpectJSON = append([]string(nil), o.expectJSON...)
	}
	if o.baselineIP != "" || o.explicit["baseline-ip"] {
		cfg.AnonymityBaseline = o.baselineIP
	}
	if o.metadataFile != "" || o.explicit["metadata-file"] {
		cfg.MetadataFile = o.metadataFile
	}
	if o.connectTimeout != "" {
		cfg.ConnectTimeoutRaw = o.connectTimeout
	}
	if o.requestTimeout != "" {
		cfg.RequestTimeoutRaw = o.requestTimeout
	}
	if o.dnsCacheTTL != "" {
		cfg.DNSCacheTTLRaw = o.dnsCacheTTL
	}
	if o.retryBackoff != "" {
		cfg.RetryBackoffRaw = o.retryBackoff
	}
	if o.progressInterval != "" {
		cfg.ProgressRaw = o.progressInterval
	}
	if len(o.targets) > 0 {
		cfg.Targets = []string(o.targets)
	}
	if o.dataDir != "" {
		cfg.DataDir = o.dataDir
	}
	if o.maxRedirects >= 0 {
		cfg.MaxRedirects = o.maxRedirects
	}
	if o.allowPrivate || o.explicit["allow-private-targets"] {
		cfg.AllowPrivate = o.allowPrivate
	}
	if o.allowRemoteDNS || o.explicit["allow-remote-dns"] {
		cfg.AllowRemoteDNS = o.allowRemoteDNS
	}
	if o.retryPermanent || o.explicit["retry-permanent"] {
		cfg.RetryPermanent = o.retryPermanent
	}
	if o.stopOnSuccess || o.explicit["stop-on-success"] {
		cfg.StopOnSuccess = o.stopOnSuccess
	}
	if o.save || o.explicit["save"] {
		cfg.Save = o.save
	}
	if err := cfg.ParseDurations(); err != nil {
		return cfg, "", "", false, err
	}
	allowed := map[string]struct{}{}
	if len(o.targets) == 0 {
		for _, h := range cfg.AllowedHosts {
			allowed[strings.ToLower(strings.TrimSuffix(h, "."))] = struct{}{}
		}
	}
	for _, t := range cfg.Targets {
		u, e := url.Parse(t)
		if e == nil {
			allowed[strings.ToLower(u.Hostname())] = struct{}{}
		}
	}
	for _, h := range o.allowHosts {
		allowed[strings.ToLower(strings.TrimSuffix(h, "."))] = struct{}{}
	}
	cfg.AllowedHosts = cfg.AllowedHosts[:0]
	for h := range allowed {
		cfg.AllowedHosts = append(cfg.AllowedHosts, h)
	}
	sort.Strings(cfg.AllowedHosts)
	if err := cfg.Validate(); err != nil {
		return cfg, "", "", false, err
	}
	p, err := model.ParseProtocol(o.protocol)
	if err != nil {
		return cfg, "", "", false, err
	}
	f, err := output.ParseFormat(o.format)
	if err != nil {
		return cfg, "", "", false, err
	}
	color := o.color == "always" || (o.color == "auto" && c.IsTerminal && os.Getenv("NO_COLOR") == "")
	if o.plain {
		color = false
	}
	if o.color != "auto" && o.color != "always" && o.color != "never" {
		return cfg, "", "", false, errors.New("color must be auto, always, or never")
	}
	if f != output.FormatTable {
		color = false
	}
	if o.outputStatus == "" {
		o.outputStatus = "all"
	}
	if o.outputStatus != "all" {
		if _, ok := map[string]bool{"ok": true, "failed": true, "timeout": true, "auth_failed": true, "policy_blocked": true, "invalid": true, "inconclusive": true, "unreliable": true, "interrupted": true}[o.outputStatus]; !ok {
			return cfg, "", "", false, errors.New("output-status is invalid")
		}
	}
	return cfg, p, f, color, nil
}

func applyProfile(cfg *config.Config, name string) error {
	switch name {
	case "":
		return nil
	case "fast":
		cfg.Repeat = 1
		cfg.MinSuccessRate = 1
		cfg.StopOnSuccess = true
		cfg.RetryPermanent = false
		cfg.ConnectTimeoutRaw = "3s"
		cfg.RequestTimeoutRaw = "8s"
		cfg.RetryBackoffRaw = "0s"
	case "balanced":
		cfg.Repeat = 2
		cfg.MinSuccessRate = 0.5
		cfg.StopOnSuccess = false
		cfg.RetryPermanent = false
		cfg.ConnectTimeoutRaw = "5s"
		cfg.RequestTimeoutRaw = "12s"
		cfg.RetryBackoffRaw = "100ms"
	case "thorough":
		cfg.Repeat = 5
		cfg.MinSuccessRate = 0.8
		cfg.StopOnSuccess = false
		cfg.RetryPermanent = false
		cfg.ConnectTimeoutRaw = "8s"
		cfg.RequestTimeoutRaw = "20s"
		cfg.RetryBackoffRaw = "250ms"
	default:
		return fmt.Errorf("profile must be fast, balanced, or thorough")
	}
	return nil
}

func (c CLI) check(args []string, forceDetailed bool) int {
	fs, buf := c.newFlagSet("check")
	var o checkOptions
	c.addCheckFlags(fs, &o)
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	if buf.Len() > 0 {
		fmt.Fprint(c.Stdout, buf.String())
		return ExitOK
	}
	invalidZero := ""
	o.explicit = make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		o.explicit[f.Name] = true
		switch f.Name {
		case "concurrency", "queue-size", "per-target", "repeat", "min-success-rate":
			if f.Value.String() == "0" {
				invalidZero = f.Name
			}
		}
	})
	if invalidZero != "" {
		fmt.Fprintf(c.Stderr, "%s must be greater than zero\n", invalidZero)
		return ExitUsage
	}
	if o.requireCount < 0 || o.requireCount > 1_000_000_000 {
		fmt.Fprintln(c.Stderr, "require-count must be between 0 and 1000000000")
		return ExitUsage
	}
	if o.requireSuccess && o.requireCount < 1 {
		o.requireCount = 1
	}
	cfg, proto, outFmt, color, err := c.loadCheck(o)
	if err != nil {
		fmt.Fprintln(c.Stderr, "configuration error:", err)
		return ExitUsage
	}
	format, formatErr := inputpkg.ParseFormat(o.inputFormat)
	if formatErr != nil {
		fmt.Fprintln(c.Stderr, formatErr)
		return ExitUsage
	}
	var metadataProvider *metadatapkg.Provider
	if cfg.MetadataFile != "" {
		metadataProvider, err = metadatapkg.LoadCSV(cfg.MetadataFile)
		if err != nil {
			fmt.Fprintln(c.Stderr, "metadata error:", err)
			return ExitUsage
		}
		if o.verbose {
			fmt.Fprintf(c.Stderr, "loaded %d metadata prefixes\n", metadataProvider.Records())
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	jobs := make(chan model.Proxy, cfg.QueueSize)
	var scheduled atomic.Int64
	var parserFinished atomic.Bool
	parseErr := make(chan error, 1)
	statsCh := make(chan model.InputStats, 1)
	files := fs.Args()
	stdinSources := 0
	for _, name := range files {
		if name == "-" {
			stdinSources++
		}
	}
	if stdinSources > 1 {
		fmt.Fprintln(c.Stderr, "standard input may be specified only once")
		return ExitUsage
	}
	var working *secureOutput
	var summaryOutput *secureOutput
	if o.workingOutput != "" {
		for _, name := range files {
			if name == "-" {
				continue
			}
			same, sameErr := samePath(name, o.workingOutput)
			if sameErr != nil {
				fmt.Fprintln(c.Stderr, "working output error:", sameErr)
				return ExitUsage
			}
			if same {
				fmt.Fprintln(c.Stderr, "working output must not overwrite an input file")
				return ExitUsage
			}
		}
		working, err = openSecureOutput(o.workingOutput, o.forceWorking)
		if err != nil {
			fmt.Fprintln(c.Stderr, "working output error:", err)
			return ExitOperational
		}
		defer working.Abort()
	}
	if o.summaryOutput != "" {
		for _, name := range files {
			if name == "-" {
				continue
			}
			same, sameErr := samePath(name, o.summaryOutput)
			if sameErr != nil {
				fmt.Fprintln(c.Stderr, "summary output error:", sameErr)
				return ExitUsage
			}
			if same {
				fmt.Fprintln(c.Stderr, "summary output must not overwrite an input file")
				return ExitUsage
			}
		}
		if o.workingOutput != "" {
			same, sameErr := samePath(o.workingOutput, o.summaryOutput)
			if sameErr != nil {
				fmt.Fprintln(c.Stderr, "summary output error:", sameErr)
				return ExitUsage
			}
			if same {
				fmt.Fprintln(c.Stderr, "summary output and working output must be different files")
				return ExitUsage
			}
		}
		summaryOutput, err = openSecureOutput(o.summaryOutput, o.forceWorking)
		if err != nil {
			fmt.Fprintln(c.Stderr, "summary output error:", err)
			return ExitOperational
		}
		defer summaryOutput.Abort()
	}
	go func() {
		defer close(jobs)
		defer parserFinished.Store(true)
		parser := inputpkg.New(inputpkg.Options{Format: format, DefaultProtocol: proto, Source: "input", MaxBytes: cfg.MaxInputBytes, Deduplicate: !o.noDeduplicate})
		warnedCredentialFiles := map[string]struct{}{}
		emit := func(p model.Proxy) error {
			if p.Credentials != nil && p.Source != "stdin" {
				if _, warned := warnedCredentialFiles[p.Source]; !warned {
					warnedCredentialFiles[p.Source] = struct{}{}
					if info, statErr := os.Stat(p.Source); statErr == nil && info.Mode().IsRegular() && info.Mode().Perm()&0077 != 0 {
						fmt.Fprintf(c.Stderr, "security warning: credential input %s has mode %04o; use chmod 600\n", p.Source, info.Mode().Perm())
					}
				}
			}
			scheduled.Add(1)
			select {
			case jobs <- p:
				return nil
			case <-ctx.Done():
				scheduled.Add(-1)
				return ctx.Err()
			}
		}
		reject := func(r inputpkg.Rejection) {
			if o.verbose {
				fmt.Fprintf(c.Stderr, "rejected %s:%d: %s (%s)\n", r.Source, r.Line, r.Value, r.Reason)
			}
		}
		var e error
		if len(files) == 0 {
			e = emitInputSource(parser, c.Stdin, format, "stdin", emit, reject)
		} else {
			for _, name := range files {
				if name == "-" {
					e = emitInputSource(parser, c.Stdin, format, "stdin", emit, reject)
					if e != nil {
						break
					}
					continue
				}
				f, openErr := os.Open(name)
				if openErr != nil {
					e = openErr
					break
				}
				e = emitInputSource(parser, f, format, name, emit, reject)
				_ = f.Close()
				if e != nil {
					break
				}
			}
		}
		statsCh <- parser.Stats
		parseErr <- e
	}()
	checker := engine.NewChecker(cfg)
	checker.Metadata = metadataProvider
	runner := engine.Engine{Workers: cfg.Concurrency, QueueSize: cfg.QueueSize, Processor: checker}
	results := runner.Run(ctx, jobs)
	writer := output.New(c.Stdout, outFmt, color)
	var history *store.RunWriter
	if cfg.Save {
		history, err = store.NewRunWriter(cfg.DataDir)
		if err != nil {
			fmt.Fprintln(c.Stderr, "history error:", err)
			return ExitOperational
		}
		defer history.Abort()
	}
	start := time.Now()
	summary := model.RunSummary{SchemaVersion: model.SchemaVersion, Configuration: runConfiguration(cfg, proto, o), StartedAt: start.UTC(), StatusCount: map[model.Status]int{}, FailureCodes: map[string]int{}, FailureStages: map[model.Stage]int{}, Targets: map[string]model.TargetSummary{}}
	latencies := metrics.NewHistogram(1, 300000)
	var progressC <-chan time.Time
	var progressTicker *time.Ticker
	if o.verbose {
		progressTicker = time.NewTicker(cfg.ProgressInterval)
		progressC = progressTicker.C
		defer progressTicker.Stop()
	}
	for results != nil {
		select {
		case <-progressC:
			pending := scheduled.Load() - int64(summary.Processed)
			if pending < 0 {
				pending = 0
			}
			ingest := "streaming"
			if parserFinished.Load() {
				ingest = "done"
			}
			fmt.Fprintf(c.Stderr, "processed=%d scheduled=%d pending=%d ingest=%s ok=%d unreliable=%d failed=%d inconclusive=%d timeouts=%d rate=%.1f/s elapsed=%s\n", summary.Processed, scheduled.Load(), pending, ingest, summary.Successful, summary.Unreliable, summary.Failed, summary.Inconclusive, summary.Timeouts, float64(summary.Processed)/time.Since(start).Seconds(), time.Since(start).Round(100*time.Millisecond))
			continue
		case r, ok := <-results:
			if !ok {
				results = nil
				continue
			}
			showResult := !o.quiet && (o.outputStatus == "all" || o.outputStatus == string(r.Status))
			if forceDetailed && showResult {
				if err := output.WriteDetailed(c.Stdout, r); err != nil {
					if errors.Is(err, syscall.EPIPE) {
						return ExitOK
					}
					fmt.Fprintln(c.Stderr, "output error:", err)
					return ExitOperational
				}
			} else if showResult {
				if err := writer.WriteResult(r); err != nil {
					if errors.Is(err, syscall.EPIPE) {
						return ExitOK
					}
					fmt.Fprintln(c.Stderr, "output error:", err)
					return ExitOperational
				}
			}
			if history != nil {
				if err := history.Write(r); err != nil {
					fmt.Fprintln(c.Stderr, "history error:", err)
					return ExitOperational
				}
			}
			summary.Processed++
			summary.StatusCount[r.Status]++
			if r.Status == model.StatusOK {
				summary.Successful++
				if working != nil {
					if err := working.WriteLine(r.InputProxy); err != nil {
						fmt.Fprintln(c.Stderr, "working output error:", err)
						return ExitOperational
					}
				}
			} else if r.Status == model.StatusInconclusive {
				summary.Inconclusive++
			} else if r.Status == model.StatusUnreliable {
				summary.Unreliable++
			} else {
				summary.Failed++
			}
			for _, ob := range r.Observations {
				target := summary.Targets[ob.Target]
				target.Attempts++
				target.TotalMS += ob.Timings.TotalMS
				if ob.Status == model.StatusOK {
					target.Successful++
				} else if ob.Status == model.StatusInconclusive {
					target.Inconclusive++
				} else {
					target.Failed++
				}
				if ob.Status == model.StatusTimeout {
					summary.Timeouts++
					target.Timeouts++
				}
				if ob.Status == model.StatusOK {
					latencies.Observe(ob.Timings.TotalMS)
				} else {
					if ob.Code != "" {
						summary.FailureCodes[ob.Code]++
					}
					if ob.Stage != "" {
						summary.FailureStages[ob.Stage]++
					}
				}
				summary.Targets[ob.Target] = target
			}
		}
	}
	if err := writer.Flush(); err != nil {
		fmt.Fprintln(c.Stderr, "output error:", err)
		return ExitOperational
	}
	summary.Input = <-statsCh
	if err := <-parseErr; err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(c.Stderr, "input error:", err)
		return ExitOperational
	}
	summary.FinishedAt = time.Now().UTC()
	summary.LatencyP50MS = latencies.Percentile(.50)
	summary.LatencyP95MS = latencies.Percentile(.95)
	summary.LatencyP99MS = latencies.Percentile(.99)
	summary.DurationMS = float64(time.Since(start).Microseconds()) / 1000
	if summary.DurationMS > 0 {
		summary.RatePerSec = float64(summary.Processed) / (summary.DurationMS / 1000)
	}
	for name, target := range summary.Targets {
		if target.Attempts > 0 {
			target.SuccessRate = float64(target.Successful) / float64(target.Attempts)
			target.AverageTotalMS = target.TotalMS / float64(target.Attempts)
		}
		summary.Targets[name] = target
	}
	if ctx.Err() != nil {
		return ExitInterrupted
	}
	if summary.Input.Accepted == 0 {
		return ExitNoValidInput
	}
	if history != nil {
		summary.RunID = history.ID
		if err := history.Commit(summary); err != nil {
			fmt.Fprintln(c.Stderr, "history commit error:", err)
			return ExitOperational
		}
		fmt.Fprintf(c.Stderr, "saved run %s\n", history.ID)
	}
	if summaryOutput != nil {
		if err := summaryOutput.WriteJSON(summary); err != nil {
			fmt.Fprintln(c.Stderr, "summary output error:", err)
			return ExitOperational
		}
		if err := summaryOutput.Commit(); err != nil {
			fmt.Fprintln(c.Stderr, "summary output error:", err)
			return ExitOperational
		}
		fmt.Fprintf(c.Stderr, "saved run summary to %s\n", o.summaryOutput)
	}
	if working != nil {
		if err := working.Commit(); err != nil {
			fmt.Fprintln(c.Stderr, "working output error:", err)
			return ExitOperational
		}
		fmt.Fprintf(c.Stderr, "saved %d validated proxies to %s\n", summary.Successful, o.workingOutput)
	}
	if o.verbose || c.IsTerminal {
		fmt.Fprintf(c.Stderr, "read=%d accepted=%d duplicates=%d rejected=%d processed=%d ok=%d unreliable=%d failed=%d inconclusive=%d elapsed=%s rate=%.1f/s p50=%.0fms p95=%.0fms p99=%.0fms\n", summary.Input.Read, summary.Input.Accepted, summary.Input.Duplicates, summary.Input.Rejected, summary.Processed, summary.Successful, summary.Unreliable, summary.Failed, summary.Inconclusive, time.Since(start).Round(time.Millisecond), summary.RatePerSec, summary.LatencyP50MS, summary.LatencyP95MS, summary.LatencyP99MS)
		if top := topCounts(summary.FailureCodes, 5); top != "" {
			fmt.Fprintln(c.Stderr, "top_failures="+top)
		}
	}
	if summary.Successful < o.requireCount {
		return ExitNoSuccess
	}
	return ExitOK
}

func runConfiguration(cfg config.Config, proto model.Protocol, o checkOptions) model.RunConfiguration {
	targets := make([]string, 0, len(cfg.Targets))
	for _, raw := range cfg.Targets {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		u.RawQuery = ""
		u.Fragment = ""
		u.Path = "/"
		u.RawPath = ""
		targets = append(targets, u.String())
	}
	return model.RunConfiguration{
		Profile: o.profile, Protocol: proto, Concurrency: cfg.Concurrency,
		QueueSize: cfg.QueueSize, PerTarget: cfg.PerTarget, RateLimit: cfg.RateLimit,
		Repeat: cfg.Repeat, MinSuccessRate: cfg.MinSuccessRate, ConnectTimeout: cfg.ConnectTimeout.String(), RequestTimeout: cfg.RequestTimeout.String(),
		RetryBackoff: cfg.RetryBackoff.String(), StopOnSuccess: cfg.StopOnSuccess,
		RetryPermanent: cfg.RetryPermanent, AllowRemoteDNS: cfg.AllowRemoteDNS,
		MinResponseBytes: cfg.MinResponseBytes, MinThroughput: cfg.MinThroughputKBPS,
		ContentRules:    len(cfg.RequireText) + len(cfg.RejectText) + len(cfg.ExpectJSON),
		MetadataEnabled: cfg.MetadataFile != "",
		Deduplicate:     !o.noDeduplicate, ValidationTarget: targets,
	}
}

func (c CLI) runs(args []string) int {
	action := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action, args = args[0], args[1:]
	}
	fs, buf := c.newFlagSet("runs")
	data := fs.String("data-dir", config.Defaults().DataDir, "history directory")
	limit := fs.Int("limit", 50, "maximum runs to list")
	jsonOut := fs.Bool("json", false, "emit a JSON array")
	keep := fs.Int("keep", 20, "newest runs to retain when pruning")
	execute := fs.Bool("execute", false, "apply prune; without this flag only show the plan")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	if action == "prune" {
		if *keep < 0 || *keep > 1_000_000 {
			fmt.Fprintln(c.Stderr, "keep must be between 0 and 1000000")
			return ExitUsage
		}
		ids, err := store.PruneRuns(*data, *keep, *execute)
		if err != nil {
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
		verb := "would_remove"
		if *execute {
			verb = "removed"
		}
		for _, id := range ids {
			fmt.Fprintln(c.Stdout, id)
		}
		fmt.Fprintf(c.Stderr, "%s=%d keep=%d\n", verb, len(ids), *keep)
		return ExitOK
	}
	if action != "list" {
		fmt.Fprintln(c.Stderr, "runs action must be list or prune")
		return ExitUsage
	}
	if *limit < 1 || *limit > 10000 {
		fmt.Fprintln(c.Stderr, "limit must be between 1 and 10000")
		return ExitUsage
	}
	runs, err := store.ListRuns(*data, *limit)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	if *jsonOut {
		enc := json.NewEncoder(c.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(runs); err != nil {
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
		return ExitOK
	}
	fmt.Fprintln(c.Stdout, "RUN                                      STARTED               PROCESSED  OK      UNREL   FAILED  INCONCL  RATE/S")
	for _, run := range runs {
		fmt.Fprintf(c.Stdout, "%-40s %-21s %9d  %6d  %6d  %6d  %7d  %6.1f\n", run.RunID, run.StartedAt.UTC().Format("2006-01-02 15:04:05Z"), run.Processed, run.Successful, run.Unreliable, run.Failed, run.Inconclusive, run.RatePerSec)
	}
	return ExitOK
}

type secureOutput struct {
	f      *os.File
	w      *bufio.Writer
	temp   string
	final  string
	force  bool
	closed bool
}

func openSecureOutput(path string, force bool) (*secureOutput, error) {
	if !force {
		if _, err := os.Lstat(path); err == nil {
			return nil, os.ErrExist
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return nil, err
	}
	if err = f.Chmod(0600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, err
	}
	return &secureOutput{f: f, w: bufio.NewWriterSize(f, 64<<10), temp: f.Name(), final: path, force: force}, nil
}
func (s *secureOutput) WriteLine(value string) error {
	if s == nil || s.closed {
		return errors.New("output is closed")
	}
	if strings.ContainsAny(value, "\r\n") {
		return errors.New("unsafe proxy value")
	}
	_, err := fmt.Fprintln(s.w, value)
	return err
}
func (s *secureOutput) WriteJSON(value any) error {
	if s == nil || s.closed {
		return errors.New("output is closed")
	}
	enc := json.NewEncoder(s.w)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
func (s *secureOutput) WriteBytes(value []byte) error {
	if s == nil || s.closed {
		return errors.New("output is closed")
	}
	_, err := s.w.Write(value)
	return err
}
func (s *secureOutput) Write(value []byte) (int, error) {
	if s == nil || s.closed {
		return 0, errors.New("output is closed")
	}
	return s.w.Write(value)
}
func (s *secureOutput) Commit() error {
	if s == nil || s.closed {
		return errors.New("output is already closed")
	}
	s.closed = true
	if err := s.w.Flush(); err != nil {
		_ = s.f.Close()
		_ = os.Remove(s.temp)
		return err
	}
	if err := s.f.Sync(); err != nil {
		_ = s.f.Close()
		_ = os.Remove(s.temp)
		return err
	}
	if err := s.f.Close(); err != nil {
		_ = os.Remove(s.temp)
		return err
	}
	if s.force {
		if err := os.Rename(s.temp, s.final); err != nil {
			_ = os.Remove(s.temp)
			return err
		}
	} else {
		if err := os.Link(s.temp, s.final); err != nil {
			_ = os.Remove(s.temp)
			return err
		}
		if err := os.Remove(s.temp); err != nil {
			return err
		}
	}
	d, err := os.Open(filepath.Dir(s.final))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *secureOutput) Abort() {
	if s == nil || s.closed {
		return
	}
	s.closed = true
	_ = s.f.Close()
	_ = os.Remove(s.temp)
}
func samePath(a, b string) (bool, error) {
	aa, err := canonicalPath(a)
	if err != nil {
		return false, err
	}
	bb, err := canonicalPath(b)
	if err != nil {
		return false, err
	}
	return aa == bb, nil
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	current := abs
	missing := []string{}
	for {
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
		if !errors.Is(resolveErr, os.ErrNotExist) {
			return "", resolveErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", resolveErr
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func (c CLI) inspect(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(c.Stderr, "usage: relayprobe inspect PROXY [check options]")
		if len(args) > 0 {
			return ExitOK
		}
		return ExitUsage
	}
	proxy := args[0]
	tmp, err := os.CreateTemp("", "relayprobe-inspect-*.txt")
	if err != nil {
		return ExitOperational
	}
	name := tmp.Name()
	defer os.Remove(name)
	_, _ = fmt.Fprintln(tmp, proxy)
	_ = tmp.Close()
	return c.check(append(append([]string{"--format", "jsonl", "--repeat", "3"}, args[1:]...), name), true)
}

func (c CLI) importCmd(args []string) int {
	fs, buf := c.newFlagSet("import")
	inFmt := fs.String("input-format", "auto", "input: auto, text, csv, json, jsonl")
	protoText := fs.String("protocol", "http", "default protocol")
	outFmt := fs.String("format", "txt", "output: txt, jsonl")
	max := fs.Int64("max-bytes", 256<<20, "maximum input bytes")
	noDeduplicate := fs.Bool("no-deduplicate", false, "disable exact deduplication for bounded parser memory")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	if *max < 1 {
		fmt.Fprintln(c.Stderr, "max-bytes must be positive")
		return ExitUsage
	}
	if *outFmt != "txt" && *outFmt != "jsonl" {
		fmt.Fprintln(c.Stderr, "format must be txt or jsonl")
		return ExitUsage
	}
	p, err := model.ParseProtocol(*protoText)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitUsage
	}
	parsedInputFormat, err := inputpkg.ParseFormat(*inFmt)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitUsage
	}
	stdinSources := 0
	for _, name := range fs.Args() {
		if name == "-" {
			stdinSources++
		}
	}
	if stdinSources > 1 {
		fmt.Fprintln(c.Stderr, "standard input may be specified only once")
		return ExitUsage
	}
	parser := inputpkg.New(inputpkg.Options{Format: parsedInputFormat, DefaultProtocol: p, Source: "input", MaxBytes: *max, Deduplicate: !*noDeduplicate})
	emit := func(x model.Proxy) error {
		if *outFmt == "jsonl" {
			b, _ := json.Marshal(map[string]any{"id": x.Key(), "proxy": x.SafeURI(), "endpoint": x.Address(), "protocol": x.Protocol})
			_, err := fmt.Fprintln(c.Stdout, string(b))
			return err
		} else {
			_, err := fmt.Fprintln(c.Stdout, x.SafeURI())
			return err
		}
	}
	var e error
	if len(fs.Args()) == 0 {
		e = emitInputSource(parser, c.Stdin, parsedInputFormat, "stdin", emit, nil)
	} else {
		for _, n := range fs.Args() {
			if n == "-" {
				e = emitInputSource(parser, c.Stdin, parsedInputFormat, "stdin", emit, nil)
				if e != nil {
					break
				}
				continue
			}
			f, er := os.Open(n)
			if er != nil {
				e = er
				break
			}
			e = emitInputSource(parser, f, parsedInputFormat, n, emit, nil)
			_ = f.Close()
			if e != nil {
				break
			}
		}
	}
	if e != nil {
		if errors.Is(e, syscall.EPIPE) {
			return ExitOK
		}
		fmt.Fprintln(c.Stderr, e)
		return ExitOperational
	}
	fmt.Fprintf(c.Stderr, "read=%d accepted=%d duplicates=%d rejected=%d\n", parser.Stats.Read, parser.Stats.Accepted, parser.Stats.Duplicates, parser.Stats.Rejected)
	if parser.Stats.Accepted == 0 {
		return ExitNoValidInput
	}
	return ExitOK
}

func emitInputSource(parser *inputpkg.Parser, reader io.Reader, format inputpkg.Format, source string, emit func(model.Proxy) error, reject func(inputpkg.Rejection)) error {
	reader, compressed, err := inputpkg.MaybeDecompress(reader)
	if err != nil {
		return err
	}
	if compressed != nil {
		defer compressed.Close()
	}
	return parser.EmitSource(reader, format, source, emit, reject)
}

type resultFilter struct {
	status, protocol, search, exitIP, anonymity string
	country, asn, networkType                   string
	maxLatency, minScore, minThroughput         float64
}

func matchResult(r model.Result, f resultFilter) bool {
	if f.status != "" && string(r.Status) != f.status {
		return false
	}
	if f.protocol != "" && string(r.Protocol) != f.protocol {
		return false
	}
	if f.search != "" && !strings.Contains(strings.ToLower(r.Endpoint), strings.ToLower(f.search)) {
		return false
	}
	if f.exitIP != "" || f.anonymity != "" || f.country != "" || f.asn != "" || f.networkType != "" {
		matched := false
		for _, o := range r.Observations {
			metadataMatches := f.country == "" && f.asn == "" && f.networkType == ""
			if o.Metadata != nil {
				metadataMatches = (f.country == "" || strings.EqualFold(o.Metadata.CountryCode, f.country) || strings.EqualFold(o.Metadata.Country, f.country)) &&
					(f.asn == "" || strings.EqualFold(o.Metadata.ASN, normalizeASNFilter(f.asn))) &&
					(f.networkType == "" || strings.EqualFold(o.Metadata.NetworkType, f.networkType))
			}
			if (f.exitIP == "" || o.ExitIP == f.exitIP) && (f.anonymity == "" || o.Anonymity == f.anonymity) && metadataMatches {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if f.maxLatency > 0 && (r.Successes == 0 || r.Score.MedianMS > f.maxLatency) {
		return false
	}
	if f.minScore > 0 && (r.Score.Value == nil || *r.Score.Value < f.minScore) {
		return false
	}
	if f.minThroughput > 0 {
		matched := false
		for _, observation := range r.Observations {
			if observation.Status == model.StatusOK && observation.ThroughputKBPS >= f.minThroughput {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func normalizeASNFilter(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" || strings.HasPrefix(value, "AS") {
		return value
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return value
		}
	}
	return "AS" + value
}

func validateResultFilter(f resultFilter) error {
	if math.IsNaN(f.maxLatency) || math.IsInf(f.maxLatency, 0) || f.maxLatency < 0 {
		return errors.New("max-latency must be a finite non-negative number")
	}
	if math.IsNaN(f.minScore) || math.IsInf(f.minScore, 0) || f.minScore < 0 || f.minScore > 100 {
		return errors.New("min-score must be between 0 and 100")
	}
	if math.IsNaN(f.minThroughput) || math.IsInf(f.minThroughput, 0) || f.minThroughput < 0 {
		return errors.New("min-throughput-kbps must be a finite non-negative number")
	}
	return nil
}

func (c CLI) results(args []string) int {
	fs, buf := c.newFlagSet("results")
	run := fs.String("run", "latest", "run ID or .jsonl path")
	data := fs.String("data-dir", config.Defaults().DataDir, "history directory")
	format := fs.String("format", "table", "output format")
	status := fs.String("status", "", "status filter")
	proto := fs.String("protocol", "", "protocol filter")
	search := fs.String("search", "", "endpoint substring")
	exitIP := fs.String("exit-ip", "", "observed exit IP filter")
	anonymity := fs.String("anonymity", "", "anonymity evidence filter")
	country := fs.String("country", "", "country code or name filter")
	asn := fs.String("asn", "", "ASN filter, for example AS15169 or 15169")
	networkType := fs.String("network-type", "", "metadata network type filter")
	lat := fs.Float64("max-latency", 0, "maximum median milliseconds")
	minScore := fs.Float64("min-score", 0, "minimum score from 0 to 100")
	minThroughput := fs.Float64("min-throughput-kbps", 0, "minimum observed response throughput")
	limit := fs.Int("limit", 1000, "maximum rows")
	sortBy := fs.String("sort", "", "sort by endpoint, status, score, or latency")
	desc := fs.Bool("descending", false, "reverse sort order")
	maxLoad := fs.Int("max-load", 1_000_000, "maximum records loaded for sorting")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	if *limit < 1 || *maxLoad < 1 {
		fmt.Fprintln(c.Stderr, "limit and max-load must be positive")
		return ExitUsage
	}
	filter := resultFilter{status: *status, protocol: *proto, search: *search, exitIP: *exitIP, anonymity: *anonymity, country: *country, asn: *asn, networkType: *networkType, maxLatency: *lat, minScore: *minScore, minThroughput: *minThroughput}
	if err := validateResultFilter(filter); err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitUsage
	}
	path, err := store.ResolveRun(*data, *run)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	of, err := output.ParseFormat(*format)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitUsage
	}
	w := output.New(c.Stdout, of, false)
	n := 0
	if *sortBy == "" {
		err = store.ReadResults(path, func(r model.Result) error {
			if matchResult(r, filter) && n < *limit {
				n++
				return w.WriteResult(r)
			}
			return nil
		})
	} else {
		if *sortBy != "endpoint" && *sortBy != "status" && *sortBy != "score" && *sortBy != "latency" {
			fmt.Fprintln(c.Stderr, "sort must be endpoint, status, score, or latency")
			return ExitUsage
		}
		loaded := make([]model.Result, 0, minInt(*limit, 4096))
		err = store.ReadResults(path, func(r model.Result) error {
			if !matchResult(r, filter) {
				return nil
			}
			if len(loaded) >= *maxLoad {
				return errors.New("sorting load limit exceeded; narrow filters or increase --max-load")
			}
			loaded = append(loaded, r)
			return nil
		})
		if err == nil {
			sort.SliceStable(loaded, func(i, j int) bool {
				if *desc {
					return resultLess(loaded[j], loaded[i], *sortBy)
				}
				return resultLess(loaded[i], loaded[j], *sortBy)
			})
			for _, r := range loaded {
				if n >= *limit {
					break
				}
				if err = w.WriteResult(r); err != nil {
					break
				}
				n++
			}
		}
	}
	if err == nil {
		err = w.Flush()
	}
	if err != nil {
		if errors.Is(err, syscall.EPIPE) {
			return ExitOK
		}
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	return ExitOK
}

func resultLess(a, b model.Result, field string) bool {
	switch field {
	case "endpoint":
		return a.Endpoint < b.Endpoint
	case "status":
		return a.Status < b.Status
	case "latency":
		return a.Score.MedianMS < b.Score.MedianMS
	case "score":
		av, bv := -1.0, -1.0
		if a.Score.Value != nil {
			av = *a.Score.Value
		}
		if b.Score.Value != nil {
			bv = *b.Score.Value
		}
		return av < bv
	}
	return false
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func topCounts(counts map[string]int, limit int) string {
	type item struct {
		name  string
		count int
	}
	items := make([]item, 0, len(counts))
	for name, count := range counts {
		items = append(items, item{name, count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].name < items[j].name
		}
		return items[i].count > items[j].count
	})
	if len(items) > limit {
		items = items[:limit]
	}
	parts := make([]string, len(items))
	for i, x := range items {
		parts[i] = fmt.Sprintf("%s:%d", x.name, x.count)
	}
	return strings.Join(parts, ",")
}

func (c CLI) export(args []string) int {
	fs, buf := c.newFlagSet("export")
	run := fs.String("run", "latest", "run ID or path")
	data := fs.String("data-dir", config.Defaults().DataDir, "history directory")
	format := fs.String("format", "jsonl", "jsonl, csv, txt")
	out := fs.String("output", "-", "output file or -")
	status := fs.String("status", "", "status filter")
	proto := fs.String("protocol", "", "protocol filter")
	search := fs.String("search", "", "endpoint substring")
	exitIP := fs.String("exit-ip", "", "observed exit IP filter")
	anonymity := fs.String("anonymity", "", "anonymity evidence filter")
	country := fs.String("country", "", "country code or name filter")
	asn := fs.String("asn", "", "ASN filter")
	networkType := fs.String("network-type", "", "metadata network type filter")
	lat := fs.Float64("max-latency", 0, "maximum median milliseconds")
	minScore := fs.Float64("min-score", 0, "minimum score from 0 to 100")
	minThroughput := fs.Float64("min-throughput-kbps", 0, "minimum observed response throughput")
	force := fs.Bool("force", false, "replace an existing output file")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	path, err := store.ResolveRun(*data, *run)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	of, err := output.ParseFormat(*format)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitUsage
	}
	filter := resultFilter{status: *status, protocol: *proto, search: *search, exitIP: *exitIP, anonymity: *anonymity, country: *country, asn: *asn, networkType: *networkType, maxLatency: *lat, minScore: *minScore, minThroughput: *minThroughput}
	if err := validateResultFilter(filter); err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitUsage
	}
	var dst io.Writer = c.Stdout
	var fileOutput *secureOutput
	if *out != "-" {
		same, sameErr := samePath(path, *out)
		if sameErr != nil {
			fmt.Fprintln(c.Stderr, sameErr)
			return ExitUsage
		}
		if same {
			fmt.Fprintln(c.Stderr, "export output must not overwrite its source run")
			return ExitUsage
		}
		fileOutput, err = openSecureOutput(*out, *force)
		if err != nil {
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
		defer fileOutput.Abort()
		dst = fileOutput
	}
	w := output.New(dst, of, false)
	err = store.ReadResults(path, func(r model.Result) error {
		if matchResult(r, filter) {
			return w.WriteResult(r)
		}
		return nil
	})
	if err == nil {
		err = w.Flush()
	}
	if err == nil && fileOutput != nil {
		err = fileOutput.Commit()
	}
	if err != nil {
		if errors.Is(err, syscall.EPIPE) {
			return ExitOK
		}
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	return ExitOK
}

func (c CLI) stats(args []string) int {
	fs, buf := c.newFlagSet("stats")
	run := fs.String("run", "latest", "run ID or path")
	data := fs.String("data-dir", config.Defaults().DataDir, "history directory")
	jsonOut := fs.Bool("json", false, "JSON output")
	compare := fs.String("compare", "", "baseline run ID or path")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	path, err := store.ResolveRun(*data, *run)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	s, err := store.ReadSummary(path)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	if *compare != "" {
		basePath, e := store.ResolveRun(*data, *compare)
		if e != nil {
			fmt.Fprintln(c.Stderr, e)
			return ExitOperational
		}
		base, e := store.ReadSummary(basePath)
		if e != nil {
			fmt.Fprintln(c.Stderr, e)
			return ExitOperational
		}
		delta := map[string]any{"successful": s.Successful - base.Successful, "unreliable": s.Unreliable - base.Unreliable, "failed": s.Failed - base.Failed, "inconclusive": s.Inconclusive - base.Inconclusive, "rate_per_sec": s.RatePerSec - base.RatePerSec, "latency_p50_ms": s.LatencyP50MS - base.LatencyP50MS, "latency_p95_ms": s.LatencyP95MS - base.LatencyP95MS, "latency_p99_ms": s.LatencyP99MS - base.LatencyP99MS}
		if *jsonOut {
			b, _ := json.MarshalIndent(map[string]any{"current": s, "baseline": base, "delta": delta}, "", "  ")
			fmt.Fprintln(c.Stdout, string(b))
		} else {
			fmt.Fprintf(c.Stdout, "current=%s baseline=%s ok_delta=%d unreliable_delta=%d failed_delta=%d inconclusive_delta=%d rate_delta=%+.1f/s p50_delta=%+.0fms p95_delta=%+.0fms p99_delta=%+.0fms\n", s.RunID, base.RunID, s.Successful-base.Successful, s.Unreliable-base.Unreliable, s.Failed-base.Failed, s.Inconclusive-base.Inconclusive, s.RatePerSec-base.RatePerSec, s.LatencyP50MS-base.LatencyP50MS, s.LatencyP95MS-base.LatencyP95MS, s.LatencyP99MS-base.LatencyP99MS)
		}
		return ExitOK
	}
	if *jsonOut {
		b, _ := json.MarshalIndent(s, "", "  ")
		fmt.Fprintln(c.Stdout, string(b))
	} else {
		fmt.Fprintf(c.Stdout, "run=%s processed=%d ok=%d unreliable=%d failed=%d inconclusive=%d timeouts=%d rate=%.1f/s duration=%.0fms p50=%.0fms p95=%.0fms p99=%.0fms\n", s.RunID, s.Processed, s.Successful, s.Unreliable, s.Failed, s.Inconclusive, s.Timeouts, s.RatePerSec, s.DurationMS, s.LatencyP50MS, s.LatencyP95MS, s.LatencyP99MS)
		if top := topCounts(s.FailureCodes, 10); top != "" {
			fmt.Fprintln(c.Stdout, "top_failures="+top)
		}
	}
	return ExitOK
}

func (c CLI) configCmd(args []string) int {
	action := "show"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action = args[0]
		args = args[1:]
	}
	fs, buf := c.newFlagSet("config")
	path := fs.String("config", "", "configuration file")
	force := fs.Bool("force", false, "replace an existing file when initializing")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	switch action {
	case "show", "validate":
		cfg, err := config.Load(*path)
		if err != nil {
			fmt.Fprintln(c.Stderr, err)
			return ExitUsage
		}
		if action == "show" {
			b, _ := cfg.MarshalJSON()
			fmt.Fprintln(c.Stdout, string(b))
		} else {
			fmt.Fprintln(c.Stdout, "configuration valid")
		}
		return ExitOK
	case "init":
		if *path == "" {
			*path = filepath.Join(config.Defaults().DataDir, "config.json")
		}
		output, openErr := openSecureOutput(*path, *force)
		if openErr != nil {
			fmt.Fprintln(c.Stderr, openErr)
			return ExitOperational
		}
		defer output.Abort()
		b, _ := config.Defaults().MarshalJSON()
		if err := output.WriteBytes(append(b, '\n')); err != nil {
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
		if err := output.Commit(); err != nil {
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
		fmt.Fprintln(c.Stdout, *path)
		return ExitOK
	default:
		fmt.Fprintln(c.Stderr, "config action must be show, validate, or init")
		return ExitUsage
	}
}

func (c CLI) doctor(args []string) int {
	fs, buf := c.newFlagSet("doctor")
	network := fs.Bool("network", false, "resolve configured targets")
	configPath := fs.String("config", "", "configuration file")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	cfg, err := config.Load(*configPath)
	ok := true
	fmt.Fprintf(c.Stdout, "runtime        OK  %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	var rlim syscall.Rlimit
	if e := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); e == nil {
		fmt.Fprintf(c.Stdout, "resources      OK  cpus=%d nofile_soft=%d nofile_hard=%d\n", runtime.NumCPU(), rlim.Cur, rlim.Max)
		if err == nil && rlim.Cur < uint64(cfg.Concurrency+64) {
			fmt.Fprintf(c.Stdout, "concurrency    WARN nofile_soft=%d may constrain concurrency=%d\n", rlim.Cur, cfg.Concurrency)
		}
	} else {
		fmt.Fprintln(c.Stdout, "resources      WARN", e)
	}
	if err != nil {
		fmt.Fprintln(c.Stdout, "configuration FAIL", err)
		ok = false
	} else {
		fmt.Fprintln(c.Stdout, "configuration OK")
	}
	if d, err := os.MkdirTemp("", "relayprobe-doctor-"); err == nil {
		_ = os.Remove(d)
		fmt.Fprintln(c.Stdout, "temporary I/O  OK")
	} else {
		fmt.Fprintln(c.Stdout, "temporary I/O  FAIL", err)
		ok = false
	}
	if *network && err == nil {
		checker := engine.NewChecker(cfg)
		for _, t := range cfg.Targets {
			ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
			_, e := checker.Policy.Resolve(ctx, t)
			cancel()
			if e != nil {
				fmt.Fprintf(c.Stdout, "resolve %-30s FAIL %v\n", t, e)
				ok = false
			} else {
				fmt.Fprintf(c.Stdout, "resolve %-30s OK\n", t)
			}
		}
	}
	if !ok {
		return ExitOperational
	}
	return ExitOK
}

type benchProcessor struct{ delay time.Duration }

func (c CLI) completion(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(c.Stderr, "usage: relayprobe completion bash|zsh|fish")
		return ExitUsage
	}
	commands := "check inspect import results runs export stats config doctor bench completion version help"
	checkFlags := "--profile --format --input-format --protocol --concurrency --queue-size --per-target --rate --repeat --min-success-rate --min-response-bytes --min-throughput-kbps --require-text --reject-text --expect-json --baseline-ip --metadata-file --connect-timeout --request-timeout --dns-cache-ttl --retry-backoff --progress-interval --target --allow-host --allow-private-targets --allow-remote-dns --retry-permanent --stop-on-success --no-deduplicate --quiet --output-status --working-output --summary-output --force --save --data-dir --max-redirects --require-success --require-count --verbose --plain --color --config --help"
	switch args[0] {
	case "bash":
		fmt.Fprintf(c.Stdout, `_relayprobe() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=( $(compgen -W %q -- "$cur") )
  elif [[ ${COMP_WORDS[1]} == check ]]; then
    COMPREPLY=( $(compgen -W %q -- "$cur") )
  fi
}
complete -F _relayprobe relayprobe
`, commands, checkFlags)
	case "zsh":
		fmt.Fprintf(c.Stdout, `#compdef relayprobe
_relayprobe() {
  local -a commands
  commands=(%s)
  if (( CURRENT == 2 )); then
    _describe 'command' commands
  else
    _arguments '*:option:(%s)'
  fi
}
_relayprobe
`, strings.Join(strings.Fields(commands), " "), strings.Join(strings.Fields(checkFlags), " "))
	case "fish":
		for _, command := range strings.Fields(commands) {
			fmt.Fprintf(c.Stdout, "complete -c relayprobe -f -n '__fish_use_subcommand' -a %s\n", command)
		}
		for _, option := range strings.Fields(checkFlags) {
			if strings.HasPrefix(option, "--") {
				fmt.Fprintf(c.Stdout, "complete -c relayprobe -f -n '__fish_seen_subcommand_from check' -l %s\n", strings.TrimPrefix(option, "--"))
			}
		}
	default:
		fmt.Fprintln(c.Stderr, "shell must be bash, zsh, or fish")
		return ExitUsage
	}
	return ExitOK
}

func (b benchProcessor) Check(ctx context.Context, p model.Proxy) model.Result {
	if b.delay > 0 {
		timer := time.NewTimer(b.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
		}
	}
	v := 100.0
	return model.Result{ID: p.Key(), Proxy: p.SafeURI(), Endpoint: p.Address(), Protocol: p.Protocol, Status: model.StatusOK, Attempts: 1, Successes: 1, Score: model.Score{Value: &v, Confidence: "synthetic"}}
}
func (c CLI) bench(args []string) int {
	fs, buf := c.newFlagSet("bench")
	count := fs.Int("count", 10000, "synthetic proxy count")
	workers := fs.Int("concurrency", 128, "workers")
	delay := fs.Duration("delay", 0, "controlled per-item delay")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	if *count < 1 || *count > 10_000_000 || *workers < 1 || *workers > 4096 {
		fmt.Fprintln(c.Stderr, "count or concurrency outside safe limits")
		return ExitUsage
	}
	if *delay < 0 {
		fmt.Fprintln(c.Stderr, "delay must not be negative")
		return ExitUsage
	}
	ctx := context.Background()
	jobs := make(chan model.Proxy, *workers*2)
	run := engine.Engine{Workers: *workers, QueueSize: *workers * 2, Processor: benchProcessor{*delay}}
	start := time.Now()
	go func() {
		defer close(jobs)
		for i := 0; i < *count; i++ {
			jobs <- model.Proxy{Protocol: model.ProtocolHTTP, Host: "benchmark.invalid", Port: uint16(1000 + i%64000)}
		}
	}()
	n := 0
	for range run.Run(ctx, jobs) {
		n++
	}
	elapsed := time.Since(start)
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	fmt.Fprintf(c.Stdout, "mode=controlled-scheduler count=%d concurrency=%d delay=%s elapsed=%s rate=%.1f/s heap=%d_bytes\n", n, *workers, *delay, elapsed, float64(n)/elapsed.Seconds(), mem.HeapAlloc)
	return ExitOK
}
