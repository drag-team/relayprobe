# Project status

Last verified: 2026-10-25

## Objective and architecture

RelayProbe is an on-demand, terminal-only proxy validation and intelligence
application for authorized datasets. It is a dependency-free Go executable with
a streaming parser, bounded worker engine, destination policy, protocol
connectors, evidence model, local metadata lookup, optional JSONL history, and
human or machine output.

The development line is `0.6.0-dev`; result schema version 4 is current. The
project is in active development and the implemented command surface is usable.
It is not represented as a completed independent security audit.

## Verified capabilities

- HTTP, TLS-encrypted HTTPS proxy, HTTP CONNECT, SOCKS4, SOCKS4a, and SOCKS5
  fixtures, including authentication and failure classification.
- Text, commercial colon format, reordered commercial CSV, JSON, JSONL, gzip,
  multi-source, explicit stdin, deduplication, limits, and credential redaction.
- Bounded concurrency, target pressure, rate, retries, timeouts, cancellation,
  safe redirects, DNS policy, response assertions, and transfer measurements.
- Evidence-based anonymity levels and offline longest-prefix exit metadata.
- Streaming output, secure atomic exports, local history, filtering, summaries,
  completion, diagnostics, and controlled benchmarks.
- Linux amd64 and arm64 static cross-builds.

## Verification record

- `make check`: passed (`go vet`, all unit/integration tests, race detector).
- Parser fuzzing: 317,107 executions in 10 seconds with no failure.
- Package coverage: core packages range from 56.7% to 95.7%; engine 74.5%,
  protocol 75.4%, input 79.2%, policy 85.7%, and metadata 81.1%.
- Controlled 500,000-item scheduler: 786,085 items/s median at concurrency 128
  across three runs on the non-isolated delivery host.
- Offline IPv4 metadata lookup: 408 ns/op median, zero allocations across three
  benchmark samples.

The benchmark conditions and historical results are in
[BENCHMARKS.md](BENCHMARKS.md). Controlled local fixtures are used instead of
unauthorized external proxy infrastructure.

## Known limitations and outstanding work

- No independent third-party security audit has been completed.
- Real-proxy performance is environment and target dependent and is not claimed
  by the controlled scheduler benchmark.
- Anonymity labels require a compatible operator-approved echo target and an
  explicit baseline IP; ordinary websites cannot supply that evidence.
- Country, ASN, and network labels require an operator-supplied local dataset.
- Release archives, checksums, signatures, SBOMs, Ubuntu matrix validation, and
  expanded response/parser fuzz targets remain on the roadmap.

## Resume commands

```sh
git status --short
make check
go test ./internal/input -run '^$' -fuzz '^FuzzParseProxy$' -fuzztime=10s
make build
./bin/relayprobe version
./bin/relayprobe doctor
```

Architectural decisions and threat boundaries are maintained in
[ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).
