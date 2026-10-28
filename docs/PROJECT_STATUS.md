# Project status

Last verified: 2026-10-28

## Objective and architecture

RelayProbe is an on-demand, terminal-only proxy validation and intelligence
application for authorized datasets. It is a dependency-free Go executable with
a streaming parser, bounded worker engine, destination policy, protocol
connectors, evidence model, local metadata lookup, optional JSONL history, and
human or machine output.

The development line is `0.7.0-dev`; the latest published tag is `v0.4.0`, and
result schema version 5 is current. The project is in active development and
the implemented command surface is usable.
It is not represented as a completed independent security audit.

## Verified capabilities

- HTTP, TLS-encrypted HTTPS proxy, HTTP CONNECT, SOCKS4, SOCKS4a, and SOCKS5
  fixtures, including authentication and failure classification.
- Text, commercial colon format, reordered commercial CSV, JSON, JSONL, gzip,
  multi-source, explicit stdin, deduplication, limits, and credential redaction.
- Bounded concurrency, target pressure, rate, retries, timeouts, cancellation,
  safe redirects, DNS policy, response assertions, and transfer measurements.
- Evidence-based anonymity levels and offline longest-prefix exit metadata.
- Target matrices, named declarative scenarios, quorum qualification, direct
  preflight, response hashes, custom CA bundles, and TLS evidence.
- Rotation/sticky classification, pool diversity, and cross-run stability analysis.
- Streaming output, secure atomic exports, resumable checkpoints, deterministic
  sharding, bounded merging, quality gates, JUnit reports, filtering, summaries,
  completion, interactive exploration, diagnostics, and controlled benchmarks.
- Linux amd64 and arm64 static cross-builds.

## Verification record

- `make check`: passed (`go vet`, all unit/integration tests, race detector).
- Parser fuzzing: 282,033 executions in 10 seconds with no failure.
- Package coverage: core packages range from 46.1% to 100%; engine 63.7%,
  protocol 75.8%, input 80.2%, policy 85.7%, and metadata 81.1%.
- Controlled 500,000-item scheduler: 812,682 items/s median at concurrency 128
  across three runs on the non-isolated delivery host.
- Offline IPv4 metadata lookup: 411 ns/op median, zero allocations across three
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
- Country, ASN, and network labels require an operator-supplied local CSV/gzip dataset;
  a native MMDB dependency could not be acquired in the restricted build environment.
- Validation requests use HTTP/1.1 after custom proxy negotiation. Direct
  preflight can negotiate HTTP/2, but end-to-end HTTP/2 proxy validation remains under evaluation.
- Signed releases, SBOMs, Ubuntu matrix validation, and expanded response
  parsing fuzz targets remain on the roadmap.

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
