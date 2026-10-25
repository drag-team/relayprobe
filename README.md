# RelayProbe

[![CI](https://github.com/drag-team/relayprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/drag-team/relayprobe/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go version](https://img.shields.io/badge/Go-1.24%2B-00ADD8.svg)](go.mod)

RelayProbe is a fast, terminal-only proxy validation and intelligence tool for
authorized datasets. It validates complete requests rather than treating an
open port as proof that a proxy works. HTTP, HTTPS through CONNECT, SOCKS4,
SOCKS4a, and SOCKS5 are supported by one bounded, streaming engine.

RelayProbe is an on-demand CLI. It has no web interface, listening service,
daemon, telemetry, or root requirement.

## Highlights

- Protocol-aware negotiation, authentication, TLS, response, and timeout checks.
- Safe destination resolution with private-network, metadata, rebinding, and redirect controls.
- Bounded workers, queues, target concurrency, request rate, response size, and retries.
- Streaming TXT, CSV, JSON, JSONL, NDJSON, and gzip input with exact optional deduplication.
- Repeat measurements, reliability thresholds, latency distributions, and explainable scores.
- JSONL, CSV, TXT, and human-readable output with clean stdout/stderr separation.
- Atomic credential-bearing working lists and optional local run history.
- TTY-aware color, plain output, shell completion, signal handling, and stable exit codes.
- Single static Go binary with no runtime dependencies.

## Install

RelayProbe requires Go 1.24 or newer when building from source.

```sh
git clone https://github.com/drag-team/relayprobe.git
cd relayprobe
make check
make install
relayprobe version
```

`make install` writes to `$HOME/.local/bin` by default. Override the destination
with `make install PREFIX=/custom/prefix`. A system-wide installation is not
required.

To build without installing:

```sh
make build
./bin/relayprobe version
```

## Quick start

Validate HTTP proxies from `proxies.txt` and atomically save the working entries,
including their credentials, to a mode-0600 `a.txt` file:

```sh
relayprobe check --protocol http --profile fast --allow-remote-dns --quiet --working-output a.txt --force proxies.txt
```

`--allow-remote-dns` is useful for commercial gateways that require the target
hostname in CONNECT or classic HTTP forwarding. It delegates destination DNS to
the supplied proxy and therefore weakens the default DNS-rebinding protection.
Remove it when the provider accepts an IP-pinned CONNECT target.

Common workflows:

```sh
relayprobe check proxies.txt
relayprobe check --format jsonl --concurrency 128 proxies.txt > results.jsonl
relayprobe check --format txt --output-status ok proxies.txt > working-redacted.txt
relayprobe check --quiet --summary-output summary.json --require-count 10 proxies.txt
relayprobe inspect socks5://127.0.0.1:1080 --target https://example.com/
relayprobe import --protocol socks5 raw.txt > normalized.txt
relayprobe check --input-format json --repeat 5 --save proxies.json
relayprobe results --run latest --status ok --sort score --descending
relayprobe export --run latest --status ok --format csv --output working.csv
relayprobe stats --run latest --json
relayprobe runs --limit 20
relayprobe runs prune --keep 50
relayprobe runs prune --keep 50 --execute
relayprobe doctor
relayprobe bench --count 100000 --concurrency 128
```

Run `relayprobe help` or `relayprobe <command> --help` for the complete command
reference.

## Input

Unprefixed endpoints use the protocol selected by `--protocol`, which defaults
to HTTP. Supported text forms include:

```text
192.0.2.10:8080
proxy.example:3128
http://proxy.example:3128
socks4://proxy.example:1080
socks4a://proxy.example:1080
socks5://example-user:example-password@proxy.example:1080
```

Text files accept blank lines, full-line comments beginning with `#` or `;`,
and trailing ` # comment` fields. CSV accepts a `proxy` column or `host,port`.
JSON accepts a streamed array of URI strings or objects containing `proxy`, or
`protocol`, `host`, and `port`. JSONL and NDJSON accept the same values one per
line.

Gzip input is detected by its magic bytes on files and standard input. Automatic
format detection understands names such as `proxies.csv.gz` and
`proxies.jsonl.gz`; explicit `--input-format` remains available for streams
without a useful filename.

URI credentials must be percent-encoded where necessary. Supply credentials in
a mode-0600 file or protected standard input instead of shell arguments. Normal
output and saved history redact passwords. A redacted `***` password cannot be
re-imported as a credential.

Input is capped at 256 MiB by default across the complete invocation and
individual text records at 1 MiB. For gzip sources, the aggregate cap applies to
decompressed bytes. Parsing, validation, persistence, and ordinary output are streamed.
`--no-deduplicate` avoids retaining endpoint hashes when constant parser memory
is more important than duplicate suppression.

## Validation model

A result is `ok` only after RelayProbe receives a valid HTTP response through
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
`--request-timeout`, `--repeat`, `--retry-backoff`, and `--dns-cache-ttl`
control failure cost and repeat behavior.

`--verbose` prints periodic, real execution counters to stderr. Redirected and
machine-readable stdout never receives ANSI sequences or progress messages.

## Scoring and evidence

Raw attempt observations are retained separately from derived scores. With at
least two measurements, the default score combines:

- 65% successful-request rate;
- 25% exponential median-latency component with a 1500 ms decay constant;
- 10% exponential p95-minus-median jitter component with a 1000 ms decay.

Confidence is low below five measurements, medium at five, and high at ten.
Fewer than two measurements are reported as `insufficient`, avoiding false
precision.

Compatible JSON echo targets may provide observable exit IP and forwarded-header
evidence. `apparently_non_anonymous` means explicit forwarding evidence was
observed. Absence of evidence does not prove anonymity. Geolocation and ASN
lookups are intentionally not bundled because they add external data disclosure
and potentially stale third-party claims.

## Configuration

Precedence is command-line flags, `RELAYPROBE_*` environment variables, a JSON
configuration file, then built-in defaults.

```sh
relayprobe config show
relayprobe config init
relayprobe config validate --config ~/.config/relayprobe/config.json
```

Environment configuration covers every persistent engine setting:

| Area | Variables |
|---|---|
| Concurrency | `RELAYPROBE_CONCURRENCY`, `RELAYPROBE_QUEUE_SIZE`, `RELAYPROBE_PER_TARGET_CONCURRENCY`, `RELAYPROBE_REQUESTS_PER_SECOND` |
| Measurements | `RELAYPROBE_REPEAT`, `RELAYPROBE_MIN_SUCCESS_RATE`, `RELAYPROBE_STOP_ON_SUCCESS`, `RELAYPROBE_RETRY_PERMANENT_FAILURES` |
| Time | `RELAYPROBE_CONNECT_TIMEOUT`, `RELAYPROBE_REQUEST_TIMEOUT`, `RELAYPROBE_DNS_CACHE_TTL`, `RELAYPROBE_RETRY_BACKOFF`, `RELAYPROBE_PROGRESS_INTERVAL` |
| Destinations | `RELAYPROBE_TARGETS`, `RELAYPROBE_ALLOWED_TARGET_HOSTS`, `RELAYPROBE_MAX_REDIRECTS`, `RELAYPROBE_ALLOW_PRIVATE_TARGETS`, `RELAYPROBE_ALLOW_REMOTE_DNS` |
| Resource limits | `RELAYPROBE_MAX_INPUT_BYTES`, `RELAYPROBE_MAX_RESPONSE_BYTES` |
| Persistence | `RELAYPROBE_DATA_DIR`, `RELAYPROBE_SAVE` |

List values are comma-separated. Boolean values use Go boolean syntax such as
`true` or `false`. Invalid environment values stop execution before network
activity. A boolean inherited from the environment or configuration file can be
disabled explicitly, for example with `--allow-remote-dns=false`.

Target hostnames form an exact allowlist. Additional redirect hostnames require
`--allow-host`. Private, loopback, link-local, carrier-grade NAT, cloud metadata,
documentation, multicast, unspecified, and reserved destinations remain blocked
unless the deliberate `--allow-private-targets` exception is used.

## Persistence and exports

`--save` stores mode-0600 JSONL runs under `~/.config/relayprobe/runs`. Results
are flushed, synchronized, and atomically renamed. Passwords and sensitive
target URL components are never persisted. Retention cleanup is preview-only
until `runs prune --execute` is supplied.

`--summary-output PATH` writes the final schema-versioned run summary as
indented JSON without enabling history. The file is mode 0600, synchronized,
and atomically committed only after a complete run. Existing files require
`--force`. `--require-count N` returns exit code 5 when fewer than `N` proxies
validate, after committing the completed summary and other requested outputs.

`--working-output` is deliberately different: it creates a reusable normalized
list with credentials, mode 0600. It commits only after a complete run, refuses
to replace a file without `--force`, and cannot overwrite an input path. Treat
the resulting file as a secret.

## Status and exit codes

Statuses are `ok`, `failed`, `timeout`, `auth_failed`, `policy_blocked`,
`invalid`, `inconclusive`, `unreliable`, and `interrupted`.

| Code | Meaning |
|---:|---|
| 0 | Run completed; individual proxy failures are result data |
| 2 | Invalid command, option, or configuration |
| 3 | Operational failure |
| 4 | No valid input |
| 5 | The `--require-success` or `--require-count` threshold was not met |
| 130 | Interrupted by signal |

## Shell completion

```sh
relayprobe completion bash > ~/.local/share/bash-completion/completions/relayprobe
relayprobe completion zsh > ~/.local/share/zsh/site-functions/_relayprobe
relayprobe completion fish > ~/.config/fish/completions/relayprobe.fish
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY.md)
- [Data schemas](docs/SCHEMAS.md)
- [Benchmarks](docs/BENCHMARKS.md)
- [Release process](docs/RELEASING.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)
- [Roadmap](ROADMAP.md)

## Scope and limitations

RelayProbe validates only explicitly supplied, authorized proxy endpoints. It
does not discover public proxies, scan networks, evade controls, or bypass rate
limits. SOCKS4 supports IPv4 destinations; SOCKS4a remote resolution is opt-in.
History is a local single-user JSONL store rather than a multi-user database.
Real network throughput depends primarily on proxy latency, target behavior,
timeouts, file descriptor limits, and local network conditions.

## License

RelayProbe is licensed under the [Apache License 2.0](LICENSE).
