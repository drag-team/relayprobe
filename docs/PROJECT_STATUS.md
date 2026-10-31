# Project status

Last verified: 2026-10-31

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
- Native Linux amd64/arm64, macOS arm64, and Windows amd64 CI, with static
  release builds for Linux, macOS, Windows, and FreeBSD amd64/arm64.
- Cross-build coverage for OpenBSD, NetBSD, DragonFly BSD, illumos, Solaris,
  and AIX; platform-specific signal and descriptor handling; Windows
  checkpoint locking, case-insensitive path collision checks, and atomic
  Windows replacement.

## Verification record

- `make check`: passed (`go vet`, all unit/integration tests, race detector).
- Parser fuzzing: 239,885 executions in 10 seconds with no failure.
- HTTP response fuzzing: 190,621 executions in 10 seconds covering valid,
  truncated, malformed, and oversized inputs with no failure.
- Package coverage: core packages range from 46.1% to 100%; engine 65.9%,
  protocol 77.1%, input 80.3%, policy 85.7%, and metadata 81.1%.
- Controlled 500,000-item scheduler: 812,682 items/s median at concurrency 128
  across three runs on the non-isolated delivery host.
- Offline IPv4 metadata lookup: 411 ns/op median, zero allocations across three
  benchmark samples.
- A 200,000-record import comparison measured 0.61 s and 15.8 MiB maximum RSS
  for the current parser versus 1.21 s and 18.6 MiB for commit `74427aa`.
- The bounded HTTP response reader measured 6.08 us/op and 5,123 B/op after
  removing duplicate buffering.
- Streaming 1 MiB response evidence with a 64 KiB intelligence capture measured
  4.76 ms/op and 66,140 B/op versus 6.39 ms/op and 2,228,054 B/op for the prior
  `ReadAll` path, using five samples on the same host.
- Streaming search for an absent ASCII assertion over 1 MiB measured 4.77 ms/op
  and 140,068 B/op median versus 4.21 ms/op and 3,276,633 B/op for full-body
  lowercase matching: about 95.7% fewer allocated bytes for a 13% CPU tradeoff
  limited to assertion-enabled checks.

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
- Windows files inherit directory ACLs; RelayProbe does not attempt to replace
  administrator-managed ACL policy with POSIX permission semantics.
- Signed releases, SBOMs, and expanded response parsing fuzz targets remain on
  the roadmap.

## Resume commands

```sh
git status --short
make check
make cross-check
go test ./internal/input -run '^$' -fuzz '^FuzzParseProxy$' -fuzztime=10s
make build
./bin/relayprobe version
./bin/relayprobe doctor
```

Architectural decisions and threat boundaries are maintained in
[ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).
