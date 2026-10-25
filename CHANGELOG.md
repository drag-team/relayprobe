# Changelog

All notable changes to RelayProbe are documented in this file. The project uses
[Semantic Versioning](https://semver.org/) and follows the structure of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

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

### Changed

- Input byte limits are aggregate across sources and apply after decompression.
- Output/input collision checks resolve symbolic-link aliases.
- Explicit false CLI booleans now override profiles, environment, and files.
- Configuration initialization now uses atomic synchronized replacement.
- CSV exports include exit, anonymity, transfer, and metadata fields.
- Failed response assertions retain protocol timing and body evidence.
- File exports now use synchronized atomic replacement.
- Result schema advanced to version 4.
- Development version advanced to 0.6.0.

### Security

- Compressed inputs cannot bypass the configured decompressed-byte budget.
- Incomplete runs preserve existing summary files rather than replacing them.
- Forwarding evidence no longer persists header values that may contain a local IP.
- Metadata enrichment is offline by default and sends no exit IPs to a provider.

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
