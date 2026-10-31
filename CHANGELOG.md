# Changelog

All notable changes to RelayProbe are documented in this file. The project uses
[Semantic Versioning](https://semver.org/) and follows the structure of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Streaming multi-pattern response matching for ASCII content assertions,
  avoiding full-body retention and a second lowercase copy while preserving a
  Unicode-compatible bounded path.

- Strict declarative scenarios with named targets, per-target rules, matrix execution, and quorum qualification.
- Direct target preflight with report and strict modes.
- Exit-IP rotation/sticky classification, cross-run stability history, and pool diversity analysis.
- Destination and proxy TLS version, cipher, ALPN, certificate fingerprint, and expiry evidence.
- Custom destination and proxy CA bundles that extend the system trust store.
- Response-body SHA-256 assertions and stored integrity evidence.
- Automatic bounded concurrency recommendations based on CPU and file-descriptor limits.
- Resumable synchronized JSONL checkpoints with incomplete-tail recovery.
- Deterministic credential-preserving dataset sharding and bounded result-run merging.
- Strict JSON quality gates and atomic JUnit XML reports for CI.
- Interactive saved-result exploration with a non-interactive `results` fallback.
- Label, rotation class, and unique-exit filtering and sorting.
- Negotiated proxy authentication-method evidence.
- Hostile HTTP response fuzzing and a repeatable bounded-header parser benchmark.
- Public contribution, security, governance, CI, and release documentation.
- Transparent gzip input for files and standard input, including nested format detection.
- Atomic `--summary-output` JSON for CI and non-persistent automation.
- `--require-count` for minimum validated-proxy thresholds.
- Environment variables for every persistent engine setting.
- Repeatable plain and gzip parser microbenchmarks.
- Commercial `host:port:username:password` input normalization.
- Reordered commercial CSV columns with protocol and credentials.
- TLS-encrypted HTTPS proxy transport with certificate verification.
- Case-insensitive required and rejected response-content assertions.
- Exact dot-path JSON response assertions.
- Response-body byte, duration, and throughput measurements.
- Evidence-based elite, anonymous, and transparent classifications.
- Offline longest-prefix country, city, ASN, organization, and network-type metadata.
- Score, throughput, country, ASN, and network-type result/export filters.
- Explicit `-` standard-input sources for check and import pipelines.
- Canonical version file, documented release locations, and hardened release validation.
- Native Linux ARM64, macOS ARM64, and Windows x64 CI plus multiplatform release archives.
- Windows-native exclusive checkpoint locks and atomic file replacement.
- A bounded, sequential `make cross-check` portability gate for fourteen
  OS/architecture targets.
- Configurable per-candidate protocol auto-detection time budgets and
  port-informed candidate ordering.
- A configurable bounded intelligence-body capture with visibility in
  observations, run configuration, and `doctor` diagnostics.
- A preflight 512 MiB concurrent response-capture safety budget.
- An end-to-end CLI fixture that traverses a controlled local HTTP CONNECT
  proxy and validates the resulting machine-readable evidence.

### Changed

- Result schema advanced to version 5.
- Development version advanced to 0.7.0.
- Persisted IDs now identify only protocol/host/port; credential-sensitive deduplication uses ephemeral process-local seeded fingerprints.
- Plain endpoint parsing uses allocation-minimized host/port and commercial-format fast paths.
- HTTP response parsing uses one bounded buffered reader and preserves prefetched tunnel bytes without copying complete headers.
- Target execution is calculated in constant space instead of materializing per-proxy attempt matrices.
- `--no-deduplicate` now bypasses fingerprint and map initialization completely.
- `--max-response-bytes` exposes the existing bounded response limit directly on the CLI and in run summaries.
- Ordinary output and saved history now redact proxy usernames as well as passwords.
- Saved results are capped at 16 MiB per record and history commits synchronize metadata before publication.
- Configuration, scenarios, quality policies, CA bundles, checkpoints, and history reads have explicit size or record limits.
- Input cardinality is bounded independently of byte size, with a one-million-record default.
- Target matrices are rejected when they exceed 1,000 planned attempts per proxy.
- JSON proxy objects now preserve explicitly supplied username/password fields.
- Input byte limits are aggregate across sources and apply after decompression.
- Output/input collision checks resolve symbolic-link aliases.
- Explicit false CLI booleans now override profiles, environment, and files.
- Configuration initialization now uses atomic synchronized replacement.
- CSV exports include exit, anonymity, transfer, and metadata fields.
- Failed response assertions retain protocol timing and body evidence.
- File exports now use synchronized atomic replacement.
- Platform-specific signal, descriptor-limit, directory-sync, and path
  comparison behavior replaces Unix-only assumptions.
- Observation storage preallocates only the common bounded attempt window,
  reducing repeat-test growth without reserving full large matrices.
- Response byte counts, SHA-256, and throughput now use pooled streaming reads;
  full response retention occurs only for JSON or Unicode content assertions.
- Network failures now distinguish reset connections, broken pipes, closed
  connections, unexpected EOF, and operating-system timeouts.
- Shell completion options are generated from the actual check flag set so new
  flags cannot silently drift out of completion scripts.

### Fixed

- Overall expiration during protocol auto-detection now remains a classified
  timeout instead of degrading to a generic `operation_failed` result.

### Security

- Target names and pool labels reject terminal control characters.
- Scenario target names distinguish same-origin paths without persisting sensitive URL paths or queries.
- Checkpoint, working, summary, JUnit, and input collision checks use canonical paths.
- Existing checkpoints must be owner-only regular files; symbolic links are rejected before any repair or truncation.
- Checkpoints use an exclusive non-blocking file lock to prevent concurrent writers from interleaving results.
- Doctor output sanitizes target paths and queries and validates configured CA and metadata files.
- Compressed inputs cannot bypass the configured decompressed-byte budget.
- Incomplete runs preserve existing summary files rather than replacing them.
- Forwarding evidence no longer persists header values that may contain a local IP.
- Metadata enrichment is offline by default and sends no exit IPs to a provider.
- Redirects without `Location` are rejected explicitly; intermediate redirect and authentication bodies are not downloaded.
- Verbose rejected-input and credential-file diagnostics quote terminal control characters.

## [0.4.0] - 2026-10-25

### Added

- Configurable minimum success ratios and explicit `unreliable` results.
- Per-target attempt, success, failure, timeout, and latency summaries.
- Preview-first local history retention with `runs prune`.
- Bash, Zsh, and Fish completion generation.
- Streamed automatic TXT, CSV, JSON, JSONL, and NDJSON input detection.

### Changed

- Reliability qualification is independent of the latency score.
- Early termination avoids measurements that cannot change qualification.
- Result schema advanced to version 3.
- Documentation and build automation were prepared for public distribution.

### Security

- Persisted target data is reduced to scheme and authority.
- Redirect resolution remains outside the configured-target DNS cache.
- Credential-bearing working lists use atomic mode-0600 replacement.

## [0.3.0] - 2026-10-24

### Added

- DNS lookup collapse and bounded approved-answer caching.
- Rate limiting, bounded queues, retry backoff, and permanent-failure controls.
- Credential-preserving atomic `--working-output` exports.

### Changed

- Deduplication keys use compact binary identities.
- JSONL output is encoded incrementally.

## [0.2.0] - 2026-10-24

### Added

- HTTP, HTTPS CONNECT, SOCKS4, SOCKS4a, and SOCKS5 validation.
- Optional local JSONL run history, filters, statistics, and exports.
- Controlled scheduler benchmarks and fixed-memory latency histograms.

## [0.1.0] - 2026-10-24

### Added

- Initial terminal-only validation engine and destination security policy.

[Unreleased]: https://github.com/drag-team/relayprobe/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/drag-team/relayprobe/releases/tag/v0.4.0
[0.3.0]: https://github.com/drag-team/relayprobe/releases/tag/v0.3.0
[0.2.0]: https://github.com/drag-team/relayprobe/releases/tag/v0.2.0
[0.1.0]: https://github.com/drag-team/relayprobe/releases/tag/v0.1.0
