package cli

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/drag-team/relayprobe/internal/config"
	inputpkg "github.com/drag-team/relayprobe/internal/input"
	"github.com/drag-team/relayprobe/internal/model"
	"github.com/drag-team/relayprobe/internal/output"
	"github.com/drag-team/relayprobe/internal/store"
)

func (c CLI) shard(args []string) int {
	fs, buf := c.newFlagSet("shard")
	count := fs.Int("shards", 2, "number of output shards (2..1024)")
	outDir := fs.String("output-dir", ".", "output directory")
	prefix := fs.String("prefix", "proxies", "output filename prefix")
	strategy := fs.String("strategy", "hash", "distribution: hash or round-robin")
	inputFormat := fs.String("input-format", "auto", "input: auto, text, csv, json, jsonl")
	protocolText := fs.String("protocol", "http", "default protocol")
	maxBytes := fs.Int64("max-bytes", 256<<20, "maximum aggregate input bytes")
	maxEntries := fs.Int("max-entries", 1_000_000, "maximum aggregate input records")
	noDedup := fs.Bool("no-deduplicate", false, "disable exact deduplication")
	verbose := fs.Bool("verbose", false, "show rejected records on stderr")
	force := fs.Bool("force", false, "replace existing shard files")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	if *count < 2 || *count > 1024 || *maxBytes < 1 || *maxEntries < 1 || *maxEntries > 50_000_000 {
		fmt.Fprintln(c.Stderr, "shards, max-bytes, or max-entries is outside safe bounds")
		return ExitUsage
	}
	if *strategy != "hash" && *strategy != "round-robin" {
		fmt.Fprintln(c.Stderr, "strategy must be hash or round-robin")
		return ExitUsage
	}
	if *prefix == "" || filepath.Base(*prefix) != *prefix || strings.ContainsAny(*prefix, "\x00\r\n") {
		fmt.Fprintln(c.Stderr, "prefix must be a safe filename component")
		return ExitUsage
	}
	protocol, err := model.ParseProtocol(*protocolText)
	if err != nil || protocol == model.ProtocolAuto {
		fmt.Fprintln(c.Stderr, "protocol must be http, https, socks4, socks4a, or socks5")
		return ExitUsage
	}
	format, err := inputpkg.ParseFormat(*inputFormat)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitUsage
	}
	paths := make([]string, *count)
	for i := range paths {
		paths[i] = filepath.Join(*outDir, fmt.Sprintf("%s-%04d-of-%04d.txt", *prefix, i+1, *count))
		for _, inputPath := range fs.Args() {
			if inputPath == "-" {
				continue
			}
			if same, sameErr := samePath(paths[i], inputPath); sameErr != nil {
				fmt.Fprintln(c.Stderr, sameErr)
				return ExitUsage
			} else if same {
				fmt.Fprintln(c.Stderr, "shard output must not overwrite an input file")
				return ExitUsage
			}
		}
	}
	writers := make([]*secureOutput, *count)
	for i, path := range paths {
		writers[i], err = openSecureOutput(path, *force)
		if err != nil {
			for _, writer := range writers {
				if writer != nil {
					writer.Abort()
				}
			}
			fmt.Fprintf(c.Stderr, "open shard %q: %v\n", path, err)
			return ExitOperational
		}
	}
	abort := true
	defer func() {
		if abort {
			for _, writer := range writers {
				writer.Abort()
			}
		}
	}()
	parser := inputpkg.New(inputpkg.Options{Format: format, DefaultProtocol: protocol, Source: "input", MaxBytes: *maxBytes, MaxEntries: *maxEntries, Deduplicate: !*noDedup})
	written := make([]int, *count)
	sequence := uint64(0)
	emit := func(proxy model.Proxy) error {
		index := 0
		if *strategy == "round-robin" {
			index = int(sequence % uint64(*count))
		} else {
			identity := proxy.EndpointIdentity()
			index = int(binary.BigEndian.Uint64(identity[:8]) % uint64(*count))
		}
		sequence++
		written[index]++
		return writers[index].WriteLine(proxy.FullURI())
	}
	reject := func(rejection inputpkg.Rejection) {
		if *verbose {
			fmt.Fprintf(c.Stderr, "rejected %q:%d: %s\n", rejection.Source, rejection.Line, rejection.Reason)
		}
	}
	if err := c.emitFiles(parser, fs.Args(), format, emit, reject); err != nil {
		fmt.Fprintln(c.Stderr, "shard input error:", err)
		return ExitOperational
	}
	if parser.Stats.Accepted == 0 {
		return ExitNoValidInput
	}
	for i, writer := range writers {
		if err := writer.Commit(); err != nil {
			fmt.Fprintf(c.Stderr, "commit shard %q: %v\n", paths[i], err)
			return ExitOperational
		}
	}
	abort = false
	minimum, maximum, empty := written[0], written[0], 0
	for _, records := range written {
		if records < minimum {
			minimum = records
		}
		if records > maximum {
			maximum = records
		}
		if records == 0 {
			empty++
		}
	}
	fmt.Fprintf(c.Stderr, "read=%d accepted=%d duplicates=%d rejected=%d shards=%d shard_min=%d shard_max=%d empty_shards=%d\n", parser.Stats.Read, parser.Stats.Accepted, parser.Stats.Duplicates, parser.Stats.Rejected, *count, minimum, maximum, empty)
	return ExitOK
}

func (c CLI) emitFiles(parser *inputpkg.Parser, paths []string, format inputpkg.Format, emit func(model.Proxy) error, reject func(inputpkg.Rejection)) error {
	if len(paths) == 0 {
		return emitInputSource(parser, c.Stdin, format, "stdin", emit, reject)
	}
	stdinUsed := false
	for _, path := range paths {
		if path == "-" {
			if stdinUsed {
				return errors.New("standard input may be specified only once")
			}
			stdinUsed = true
			if err := emitInputSource(parser, c.Stdin, format, "stdin", emit, reject); err != nil {
				return err
			}
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		err = emitInputSource(parser, file, format, path, emit, reject)
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func (c CLI) merge(args []string) int {
	fs, buf := c.newFlagSet("merge")
	dataDir := fs.String("data-dir", config.Defaults().DataDir, "history directory used for run IDs")
	strategy := fs.String("strategy", "latest", "selection: latest or best")
	formatText := fs.String("format", "jsonl", "output: jsonl, csv, txt, table")
	outputPath := fs.String("output", "-", "output path or -")
	maxLoad := fs.Int("max-load", 1_000_000, "maximum input records")
	force := fs.Bool("force", false, "replace an existing output file")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	if len(fs.Args()) < 1 || *maxLoad < 1 || *maxLoad > 10_000_000 {
		fmt.Fprintln(c.Stderr, "merge requires input runs and max-load must be 1..10000000")
		return ExitUsage
	}
	if *strategy != "latest" && *strategy != "best" {
		fmt.Fprintln(c.Stderr, "strategy must be latest or best")
		return ExitUsage
	}
	format, err := output.ParseFormat(*formatText)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitUsage
	}
	paths := make([]string, 0, len(fs.Args()))
	for _, source := range fs.Args() {
		path := source
		if _, statErr := os.Stat(source); statErr != nil && errors.Is(statErr, os.ErrNotExist) && !strings.ContainsAny(source, "/\\") && *dataDir != "" {
			path, err = store.ResolveRun(*dataDir, source)
			if err != nil {
				fmt.Fprintln(c.Stderr, err)
				return ExitOperational
			}
		}
		if *outputPath != "-" {
			if same, sameErr := samePath(path, *outputPath); sameErr != nil {
				fmt.Fprintln(c.Stderr, sameErr)
				return ExitUsage
			} else if same {
				fmt.Fprintln(c.Stderr, "merge output must not overwrite an input")
				return ExitUsage
			}
		}
		paths = append(paths, path)
	}
	selected := make(map[string]model.Result)
	loaded := 0
	for _, path := range paths {
		if err := store.ReadResults(path, func(candidate model.Result) error {
			loaded++
			if loaded > *maxLoad {
				return errors.New("merge load limit exceeded")
			}
			key := candidate.ID
			if key == "" {
				key = string(candidate.Protocol) + "\x00" + candidate.Endpoint
			}
			current, exists := selected[key]
			if !exists || mergePrefer(candidate, current, *strategy) {
				selected[key] = candidate
			}
			return nil
		}); err != nil {
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
	}
	results := make([]model.Result, 0, len(selected))
	for _, result := range selected {
		results = append(results, result)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Endpoint == results[j].Endpoint {
			return results[i].Protocol < results[j].Protocol
		}
		return results[i].Endpoint < results[j].Endpoint
	})
	var destination io.Writer = c.Stdout
	var file *secureOutput
	if *outputPath != "-" {
		file, err = openSecureOutput(*outputPath, *force)
		if err != nil {
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
		defer file.Abort()
		destination = file
	}
	writer := output.New(destination, format, false)
	for _, result := range results {
		if err := writer.WriteResult(result); err != nil {
			if errors.Is(err, syscall.EPIPE) {
				return ExitOK
			}
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
	}
	if err := writer.Flush(); err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	if file != nil {
		if err := file.Commit(); err != nil {
			fmt.Fprintln(c.Stderr, err)
			return ExitOperational
		}
	}
	fmt.Fprintf(c.Stderr, "merged=%d input_records=%d duplicates=%d\n", len(results), loaded, loaded-len(results))
	return ExitOK
}

func mergePrefer(candidate, current model.Result, strategy string) bool {
	if strategy == "latest" {
		return candidate.CheckedAt.After(current.CheckedAt) || candidate.CheckedAt.Equal(current.CheckedAt)
	}
	rank := func(result model.Result) int {
		switch result.Status {
		case model.StatusOK:
			return 3
		case model.StatusUnreliable:
			return 2
		case model.StatusInconclusive:
			return 1
		default:
			return 0
		}
	}
	if rank(candidate) != rank(current) {
		return rank(candidate) > rank(current)
	}
	candidateScore, currentScore := -1.0, -1.0
	if candidate.Score.Value != nil {
		candidateScore = *candidate.Score.Value
	}
	if current.Score.Value != nil {
		currentScore = *current.Score.Value
	}
	if candidateScore != currentScore {
		return candidateScore > currentScore
	}
	if candidate.Score.SuccessRate != current.Score.SuccessRate {
		return candidate.Score.SuccessRate > current.Score.SuccessRate
	}
	return candidate.CheckedAt.After(current.CheckedAt)
}

func (c CLI) explore(args []string) int {
	fs, buf := c.newFlagSet("explore")
	run := fs.String("run", "latest", "run ID or .jsonl path")
	dataDir := fs.String("data-dir", config.Defaults().DataDir, "history directory")
	pageSize := fs.Int("page-size", 20, "rows per page")
	maxLoad := fs.Int("max-load", 100000, "maximum results loaded")
	if ok, code := c.parseFlags(fs, buf, args); !ok {
		return code
	}
	if !c.IsTerminal {
		fmt.Fprintln(c.Stderr, "explore requires an interactive terminal; use results for automation")
		return ExitUsage
	}
	if *pageSize < 1 || *pageSize > 200 || *maxLoad < 1 || *maxLoad > 1_000_000 {
		fmt.Fprintln(c.Stderr, "page-size or max-load is outside safe bounds")
		return ExitUsage
	}
	path, err := store.ResolveRun(*dataDir, *run)
	if err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	results := make([]model.Result, 0, minInt(*maxLoad, 4096))
	if err := store.ReadResults(path, func(result model.Result) error {
		if len(results) >= *maxLoad {
			return errors.New("explorer load limit exceeded")
		}
		results = append(results, result)
		return nil
	}); err != nil {
		fmt.Fprintln(c.Stderr, err)
		return ExitOperational
	}
	reader := bufio.NewReader(c.Stdin)
	page, query := 0, ""
	for {
		filtered := filterSearch(results, query)
		pages := maxInt(1, (len(filtered)+*pageSize-1) / *pageSize)
		if page >= pages {
			page = pages - 1
		}
		start := page * *pageSize
		end := minInt(start+*pageSize, len(filtered))
		fmt.Fprintf(c.Stdout, "\nRelayProbe results  page %d/%d  matches=%d  search=%q\n", page+1, pages, len(filtered), query)
		fmt.Fprintln(c.Stdout, "STATUS        SCORE   MEDIAN    PROTOCOL  ENDPOINT")
		for _, result := range filtered[start:end] {
			score := "-"
			if result.Score.Value != nil {
				score = fmt.Sprintf("%.1f", *result.Score.Value)
			}
			fmt.Fprintf(c.Stdout, "%-13s %6s  %7.0fms  %-8s  %s\n", result.Status, score, result.Score.MedianMS, result.Protocol, result.Endpoint)
		}
		fmt.Fprint(c.Stdout, "[n]ext [p]revious [/text] search [q]uit > ")
		line, readErr := reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return ExitOperational
		}
		command := strings.TrimSpace(line)
		switch {
		case command == "q" || errors.Is(readErr, io.EOF):
			return ExitOK
		case command == "n" || command == "":
			if page+1 < pages {
				page++
			}
		case command == "p":
			if page > 0 {
				page--
			}
		case strings.HasPrefix(command, "/"):
			query = strings.TrimSpace(strings.TrimPrefix(command, "/"))
			page = 0
		}
	}
}

func filterSearch(results []model.Result, query string) []model.Result {
	if query == "" {
		return results
	}
	query = strings.ToLower(query)
	filtered := make([]model.Result, 0)
	for _, result := range results {
		if strings.Contains(strings.ToLower(result.Endpoint), query) || strings.Contains(strings.ToLower(string(result.Status)), query) || strings.Contains(strings.ToLower(result.Label), query) {
			filtered = append(filtered, result)
		}
	}
	return filtered
}
