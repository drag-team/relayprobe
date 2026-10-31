# NetVex

[![CI](https://github.com/drag-team/netvex/actions/workflows/ci.yml/badge.svg)](https://github.com/drag-team/netvex/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/drag-team/netvex?sort=semver)](https://github.com/drag-team/netvex/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go version](https://img.shields.io/badge/Go-1.24%2B-00ADD8.svg)](go.mod)

NetVex is a fast, terminal-only proxy validation and intelligence tool for
authorized datasets. It validates complete requests rather than treating an
open port as proof that a proxy works. HTTP, TLS-encrypted HTTPS proxies, HTTPS
destinations through CONNECT, SOCKS4, SOCKS4a, and SOCKS5 are supported by one
bounded, streaming engine.

NetVex is an on-demand CLI. It has no web interface, listening service,
daemon, telemetry, or root requirement.

## Highlights

- Protocol-aware negotiation, authentication, TLS, response, and timeout checks.
- Safe destination resolution with private-network, metadata, rebinding, and redirect controls.
- Bounded workers, queues, target concurrency, request rate, response size, and retries.
- Bounded fallback across policy-approved destination addresses to reduce
  dual-stack and multi-origin false negatives.
- Streaming TXT, CSV, JSON, JSONL, NDJSON, and gzip input with exact optional deduplication.
- Repeat measurements, reliability thresholds, latency distributions, and explainable scores.
- Multi-target scenarios with per-target assertions, quorum qualification, and direct preflight.
- Exit-IP rotation, sticky-session, pool-diversity, and cross-run stability analysis.
- Response assertions, body throughput measurement, and evidence-based anonymity levels.
- Streaming response hashing with bounded intelligence capture and explicit memory diagnostics.
- Resumable checkpoints, deterministic dataset sharding, and result-run merging.
- JSON quality gates and JUnit XML reports for CI policy enforcement.
- Optional offline country, city, ASN, organization, and network-type metadata.
- JSONL, CSV, TXT, and human-readable output with clean stdout/stderr separation.
- Atomic credential-bearing working lists and optional local run history.
- TTY-aware color, plain output, shell completion, signal handling, and stable exit codes.
- Single static Go binary with no runtime dependencies on Linux, macOS, Windows, and FreeBSD.

## Install

NetVex requires Go 1.24 or newer when building from source.

Stable Linux archives for amd64, 386, ARMv7, ARM64, and RISC-V 64 plus macOS,
Windows, and FreeBSD amd64/arm64 archives and their SHA-256 files are published on the
[GitHub Releases page](https://github.com/drag-team/netvex/releases).
Source development on `main` may be newer than the latest release. See
[versioning and releases](docs/VERSIONING.md) for the exact policy and use
`netvex version` to identify any installed executable.

```sh
git clone https://github.com/drag-team/netvex.git
cd netvex
make check
make install
netvex version
```

`make install` writes to `$HOME/.local/bin` by default. Override the destination
with `make install PREFIX=/custom/prefix`. A system-wide installation is not
required.

On macOS and FreeBSD, the source workflow is the same. On Windows, download the
ZIP release or build `netvex.exe` with `go build -trimpath ./cmd/netvex`.
PowerShell, Command Prompt, and non-interactive pipelines can invoke the same
CLI; shell completion generation remains intended for Bash, Zsh, and Fish.

Support is continuously exercised as follows:

| Platform | Native CI | Release artifacts |
|---|---:|---:|
| Ubuntu x64 and ARM64 | Yes | Yes |
| Linux 386, ARMv7, and RISC-V 64 | Cross-compiled | Yes |
| macOS ARM64 | Yes | Yes, x64 and ARM64 |
| Windows x64 | Yes | Yes, x64 and ARM64 |
| FreeBSD | Cross-compiled | Yes, x64 and ARM64 |
| OpenBSD and NetBSD | Cross-compiled | Source build |
| DragonFly BSD, illumos, Solaris, and AIX | Cross-compiled | Source build |

To build without installing:

```sh
make build
./bin/netvex version
```

## Quick start

Validate HTTP proxies from `proxies.txt` and atomically save the working entries,
including their credentials, to a private `a.txt` file (mode 0600 on POSIX):

```sh
netvex check --protocol http --profile fast --allow-remote-dns --quiet --working-output a.txt --force proxies.txt
```

`--allow-remote-dns` is useful for commercial gateways that require the target
hostname in CONNECT or classic HTTP forwarding. It delegates destination DNS to
the supplied proxy and therefore weakens the default DNS-rebinding protection.
Remove it when the provider accepts an IP-pinned CONNECT target.

Common workflows:

```sh
netvex check proxies.txt
netvex check --format jsonl --concurrency 128 proxies.txt > results.jsonl
netvex check --concurrency auto --preflight report --checkpoint run.jsonl proxies.txt
netvex check --resume run.jsonl proxies.txt
netvex check --working-output working.txt --keep-partial proxies.txt
netvex check --scenario examples/scenario.json --policy examples/quality-policy.json --junit-output netvex.xml proxies.txt
netvex check --format txt --output-status ok proxies.txt > working-redacted.txt
netvex check --quiet --summary-output summary.json --require-count 10 proxies.txt
netvex check --reject-text "access denied" --reject-text "cf-turnstile" proxies.txt
netvex check --expect-json status=ok --expect-json data.region=us-east proxies.txt
netvex check --target https://download.example/payload.bin --min-response-bytes 262144 --min-throughput-kbps 500 proxies.txt
netvex check --baseline-ip 198.51.100.10 --metadata-file ip-metadata.csv.gz --save proxies.txt
netvex inspect socks5://127.0.0.1:1080 --target https://example.com/
netvex import --protocol socks5 raw.txt > normalized.txt
netvex check --input-format json --repeat 5 --save proxies.json
netvex results --run latest --status ok --sort score --descending
netvex export --run latest --status ok --format csv --output working.csv
netvex stats --run latest --json
netvex history --runs 20
netvex pool --run latest
netvex explore --run latest
netvex shard --shards 4 --output-dir shards proxies.txt
netvex merge --strategy best --output combined.jsonl run-a.jsonl run-b.jsonl
netvex runs --limit 20
netvex runs prune --keep 50
netvex runs prune --keep 50 --execute
netvex doctor
netvex bench --count 100000 --concurrency 128
```

Run `netvex help` or `netvex <command> --help` for the complete command
reference.

## Input

Unprefixed endpoints use the protocol selected by `--protocol`, which defaults
to HTTP. Supported text forms include:

```text
192.0.2.10:8080
proxy.example:3128
http://proxy.example:3128
https://secure-proxy.example:8443
socks4://proxy.example:1080
socks4a://proxy.example:1080
socks5://example-user:example-password@proxy.example:1080
192.0.2.10:8080:example-user:example-password
```

Text files accept blank lines, full-line comments beginning with `#` or `;`,
and trailing ` # comment` fields. CSV accepts a `proxy` column or named
`host`/`ip`, `port`, `protocol`, `username`, and `password` columns in any order.
JSON accepts a streamed array of URI strings or objects containing `proxy`, or
`protocol`, `host`, and `port`. JSONL and NDJSON accept the same values one per
line.

Gzip input is detected by its magic bytes on files and standard input. Automatic
format detection understands names such as `proxies.csv.gz` and
`proxies.jsonl.gz`; explicit `--input-format` remains available for streams
without a useful filename. With no input paths NetVex reads standard input;
`-` can also select standard input explicitly among file arguments.

URI credentials must be percent-encoded where necessary. Supply credentials in
a mode-0600 file or protected standard input instead of shell arguments. Normal
output and saved history redact usernames and passwords. A redacted `***` password cannot be
re-imported as a credential.

The commercial `host:port:username:password` form is accepted for IPv4 and
hostnames when the second field is a valid port. Colons inside credentials are
not representable in that form; use an authenticated URI with percent-encoding
instead. Bracketed IPv6 must use URI or `host:port` syntax.

Input is capped at 256 MiB and 1,000,000 records by default across the complete invocation and
individual text records at 1 MiB. For gzip sources, the aggregate cap applies to
decompressed bytes. Parsing, validation, persistence, and ordinary output are streamed.
`--no-deduplicate` bypasses fingerprint calculation and avoids retaining endpoint
hashes when constant parser memory is more important than duplicate suppression.

## Validation model

A result is `ok` only after NetVex receives a valid HTTP response through
the proxy. It separately records resolution, TCP connection, proxy negotiation,
tunnel creation, TLS, request, response, and completion stages. Destination-side
DNS, TLS, upstream, and HTTP failures can be `inconclusive` rather than falsely
classifying the proxy as dead.

The default target is `https://example.com/`. Repeated attempts rotate through
configured targets. HTTP proxies use CONNECT by default, even for an HTTP
target, and receive a previously approved numeric address. HTTPS retains the
hostname only for SNI and certificate verification. SOCKS4a, SOCKS5 remote DNS,
hostname CONNECT, and absolute-form HTTP forwarding require
`--allow-remote-dns`.

`https://` in a proxy URI means TLS is established and certificate-verified to
the proxy itself before HTTP forwarding or CONNECT negotiation. This is distinct
from using an HTTP proxy to reach an HTTPS destination. NetVex never exposes
an option to skip proxy or destination certificate verification.

The execution profiles are:

| Profile | Attempts | Minimum success | Behavior |
|---|---:|---:|---|
| `fast` | 1 | 100% | Short timeouts, no retry delay, stops on success |
| `balanced` | 2 | 50% | Production default |
| `thorough` | 5 | 80% | Longer timeouts and stronger reliability evidence |

A proxy with some successful requests below the required ratio is `unreliable`,
not `ok`, and is excluded from `--working-output`. Permanent authentication,
policy, and invalid-protocol failures stop retries unless `--retry-permanent`
is set.

## Performance controls

`--concurrency`, `--queue-size`, `--per-target`, and `--rate` independently
control global workers, backpressure, destination pressure, and attempt start
rate. Defaults are conservative for an ordinary VPS; increasing concurrency
does not necessarily improve throughput. `--connect-timeout`,
`--request-timeout`, `--auto-probe-timeout`, `--repeat`, `--retry-backoff`, and
`--dns-cache-ttl` control failure cost and repeat behavior. Automatic protocol
detection gives each candidate a fair bounded share of the overall timeout and
prioritizes likely protocols for common HTTP, HTTPS, and SOCKS ports.

`--max-response-bytes` bounds each downloaded response body and defaults to
1 MiB. Lower it for high-concurrency reachability checks; raise it deliberately
for controlled throughput targets. Redirect and proxy-authentication response
bodies are not downloaded because their content is not part of final-target
qualification.

Response hashes, byte counts, and throughput are calculated while streaming.
By default, at most 64 KiB per response is retained for exit-IP/anonymity JSON
inspection; `--intelligence-bytes` changes that cap. Text and JSON assertions
use bounded processing: ASCII text signatures are matched incrementally without
retaining the complete body, while JSON and Unicode text assertions retain the
complete bounded body because they require structured or Unicode-aware inspection.
`netvex doctor` reports the resulting per-worker capture and theoretical
concurrent upper bound. Configuration validation rejects combinations whose
worst-case retained response data exceeds the 512 MiB safety budget; reduce
concurrency or capture size instead of risking process-wide memory exhaustion.

`--concurrency auto` derives a bounded recommendation from CPU count and the
current file-descriptor limit, capped at 1024. `netvex doctor` reports that
recommendation. It is a safe starting point, not an adaptive claim that more
workers will improve a particular network.

`--verbose` prints periodic, real execution counters to stderr. Redirected and
machine-readable stdout never receives ANSI sequences or progress messages.

## Response assertions and throughput

`--require-text VALUE` requires every configured case-insensitive substring to
appear in the final response headers or body. `--reject-text VALUE` fails a
measurement when any substring appears. Both options are repeatable and operate
on bounded response data.
They can detect provider-specific block pages, challenge markers, unexpected
HTML, or missing JSON fields without adding a bypass mechanism.

`--expect-json dot.path=value` performs exact scalar checks on a JSON response.
Every configured assertion must resolve and match. Rules are reported by index,
so potentially sensitive expected values do not enter diagnostics.

NetVex records response body bytes, body-read time, and decimal KB/s.
`--min-response-bytes` verifies that the controlled target returned a meaningful
payload; `--min-throughput-kbps` qualifies the measured transfer rate. Enforcing
throughput requires a response of at least 16 KiB. Use a stable, authorized,
non-compressing payload target between 250 KiB and 1 MiB for useful comparisons.

## Scoring and evidence

Raw attempt observations are retained separately from derived scores. With at
least two measurements, the default score combines:

- 65% successful-request rate;
- 25% exponential median-latency component with a 1500 ms decay constant;
- 10% exponential p95-minus-median jitter component with a 1000 ms decay.

Confidence is low below five measurements, medium at five, and high at ten.
Fewer than two measurements are reported as `insufficient`, avoiding false
precision.

Compatible JSON echo targets may provide observable exit IP and request-header
evidence. With an explicit `--baseline-ip`, NetVex reports `elite` when the
exit differs and no proxy header is observed, `anonymous` when proxy evidence is
present without the baseline IP, and `transparent` when the baseline IP is
exposed or equals the observed exit. Without a baseline the result remains
`undetermined`; ordinary websites without echo evidence remain `unavailable`.
Forwarding evidence stores header names, not potentially sensitive values.

`--metadata-file` loads a local CIDR CSV or CSV.gz database and performs
longest-prefix matching without third-party requests. Metadata can include
country, city, ASN, organization, and an operator-supplied network type such as
`residential`, `datacenter`, `mobile`, or `isp`. NetVex does not infer network
type from organization names. See [metadata](docs/METADATA.md).

`--rotation-samples N` takes enough successful observations to distinguish a
stable exit from rotating, sticky, or mixed behavior. `history` aggregates
availability and status changes across saved runs; `pool` measures unique exits,
IPv4 /24 or IPv6 /48 subnets, ASNs, countries, and ASN concentration. These are
observed samples, not guarantees about a provider's complete inventory.

## Scenarios and target health

A scenario is a strict, versioned JSON document containing named targets and
target-specific HTTP status, content, JSON, size, throughput, and body-hash
rules. Matrix mode tests every target for every round and qualifies a proxy only
when the configured target quorum passes. Names let several paths on one origin
remain distinguishable without persisting sensitive target paths or queries.

```sh
netvex check --scenario examples/scenario.json --preflight strict proxies.txt
```

Preflight checks target health directly before proxy work. `report` records
failures and continues; `strict` stops before validation. Direct requests still
use the destination policy, pinned approved addresses, normal TLS verification,
bounded reads, and no environment proxy.

## Configuration

Precedence is command-line flags, `NETVEX_*` environment variables, a JSON
configuration file, then built-in defaults.

```sh
netvex config show
netvex config init
netvex config validate --config ~/.config/netvex/config.json
```

Environment configuration covers every persistent engine setting:

| Area | Variables |
|---|---|
| Concurrency | `NETVEX_CONCURRENCY`, `NETVEX_QUEUE_SIZE`, `NETVEX_PER_TARGET_CONCURRENCY`, `NETVEX_REQUESTS_PER_SECOND` |
| Measurements | `NETVEX_REPEAT`, `NETVEX_MIN_SUCCESS_RATE`, `NETVEX_STOP_ON_SUCCESS`, `NETVEX_RETRY_PERMANENT_FAILURES`, `NETVEX_ROTATION_SAMPLES`, `NETVEX_ROTATION_INTERVAL` |
| Time | `NETVEX_CONNECT_TIMEOUT`, `NETVEX_REQUEST_TIMEOUT`, `NETVEX_AUTO_PROBE_TIMEOUT`, `NETVEX_DNS_CACHE_TTL`, `NETVEX_RETRY_BACKOFF`, `NETVEX_PROGRESS_INTERVAL` |
| Destinations | `NETVEX_TARGETS`, `NETVEX_ALLOWED_TARGET_HOSTS`, `NETVEX_MAX_REDIRECTS`, `NETVEX_ALLOW_PRIVATE_TARGETS`, `NETVEX_ALLOW_REMOTE_DNS`, `NETVEX_TARGET_MATRIX`, `NETVEX_TARGET_QUORUM`, `NETVEX_PREFLIGHT` |
| Response qualification | `NETVEX_MIN_RESPONSE_BYTES`, `NETVEX_MIN_THROUGHPUT_KBPS`, `NETVEX_REQUIRE_TEXT`, `NETVEX_REJECT_TEXT`, `NETVEX_EXPECT_JSON`, `NETVEX_EXPECTED_BODY_SHA256`, `NETVEX_ANONYMITY_BASELINE_IP` |
| TLS trust | `NETVEX_CA_BUNDLE`, `NETVEX_PROXY_CA_BUNDLE` |
| Resource limits | `NETVEX_MAX_INPUT_BYTES`, `NETVEX_MAX_INPUT_ENTRIES`, `NETVEX_MAX_RESPONSE_BYTES`, `NETVEX_INTELLIGENCE_BODY_BYTES` |
| Persistence and metadata | `NETVEX_DATA_DIR`, `NETVEX_SAVE`, `NETVEX_METADATA_FILE` |

List values are comma-separated. Boolean values use Go boolean syntax such as
`true` or `false`. Invalid environment values stop execution before network
activity. A boolean inherited from the environment or configuration file can be
disabled explicitly, for example with `--allow-remote-dns=false`.

Target hostnames form an exact allowlist. Additional redirect hostnames require
`--allow-host`. Private, loopback, link-local, carrier-grade NAT, cloud metadata,
documentation, multicast, unspecified, and reserved destinations remain blocked
unless the deliberate `--allow-private-targets` exception is used.

## Persistence and exports

`--save` stores private JSONL runs under the platform configuration directory
(`~/.config/netvex/runs` on typical Linux systems). POSIX files use mode
0600. Results are flushed, synchronized, and atomically renamed. Passwords and
sensitive target URL components are never persisted. Retention cleanup is
preview-only until `runs prune --execute` is supplied.

`--summary-output PATH` writes the final schema-versioned run summary as
indented JSON without enabling history. The file is mode 0600, synchronized,
and atomically committed only after a complete run. Existing files require
`--force`. `--require-count N` returns exit code 5 when fewer than `N` proxies
validate, after committing the completed summary and other requested outputs.

`--working-output` is deliberately different: it creates a reusable normalized
list with credentials, mode 0600. It commits only after a complete run, refuses
to replace a file without `--force`, and cannot overwrite an input path. Treat
the resulting file as a secret.

`--keep-partial` changes only the interruption policy for `--working-output`.
After `Ctrl-C`, NetVex atomically publishes proxies that already qualified as
`ok`; without it, the previous output remains untouched. Checkpoints remain the
preferred mechanism when a run will be resumed.

`--checkpoint PATH` appends each completed redacted result and synchronizes at a
bounded interval. `--resume PATH` repairs an incomplete final line, reloads
completed endpoint IDs, and skips them. Resume identity is deliberately
credential-free: credential variants sharing one protocol, host, and port are
treated as the same endpoint across sessions. Use separate checkpoints when
testing alternate credentials for one endpoint. Restored results are included
in cumulative summaries and quality checks; throughput reports only new work.
Because checkpoints are redacted, `--resume` cannot be combined with a new
credential-bearing `--working-output`.

Quality policies use strict schema-versioned JSON. A failed policy commits the
completed outputs and returns exit 5. `--junit-output` creates an atomic mode-0600
report for CI. See [the example policy](examples/quality-policy.json).

Saved results can be filtered or exported using status, protocol, endpoint,
exit IP, anonymity, maximum latency, minimum score, minimum throughput, country,
ASN, network type, pool label, rotation class, and unique-exit count. File
exports are mode 0600 and atomically committed.

```sh
netvex export --run latest --status ok --max-latency 400 --min-score 75 --country US --network-type residential --format txt --output us-residential.txt
```

## Status and exit codes

Statuses are `ok`, `failed`, `timeout`, `auth_failed`, `policy_blocked`,
`invalid`, `inconclusive`, `unreliable`, and `interrupted`.

| Code | Meaning |
|---:|---|
| 0 | Run completed; individual proxy failures are result data |
| 2 | Invalid command, option, or configuration |
| 3 | Operational failure |
| 4 | No valid input |
| 5 | A success threshold or quality policy was not met |
| 130 | Interrupted by signal |

## Shell completion

```sh
netvex completion bash > ~/.local/share/bash-completion/completions/netvex
netvex completion zsh > ~/.local/share/zsh/site-functions/_netvex
netvex completion fish > ~/.config/fish/completions/netvex.fish
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY.md)
- [Data schemas](docs/SCHEMAS.md)
- [Validation scenarios](docs/SCENARIOS.md)
- [Automation, checkpoints, sharding, and quality gates](docs/AUTOMATION.md)
- [Offline metadata](docs/METADATA.md)
- [Benchmarks](docs/BENCHMARKS.md)
- [Project status](docs/PROJECT_STATUS.md)
- [Versioning and releases](docs/VERSIONING.md)
- [Repository metadata](docs/REPOSITORY.md)
- [Release process](docs/RELEASING.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)
- [Roadmap](ROADMAP.md)

## Scope and limitations

NetVex validates only explicitly supplied, authorized proxy endpoints. It
does not discover public proxies, scan networks, evade controls, or bypass rate
limits. SOCKS4 supports IPv4 destinations; SOCKS4a remote resolution is opt-in.
History is a local single-user JSONL store rather than a multi-user database.
Windows output files inherit the destination directory ACL; NetVex does not
rewrite Windows ACLs. Native MMDB and end-to-end HTTP/2 proxy requests are not
currently implemented; metadata uses the documented offline CSV/gzip format
and validation requests use HTTP/1.1 after protocol negotiation. Direct
preflight may negotiate HTTP/2.
Real network throughput depends primarily on proxy latency, target behavior,
timeouts, file descriptor limits, and local network conditions.

## License

NetVex is licensed under the [Apache License 2.0](LICENSE).
