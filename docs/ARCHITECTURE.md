# Architecture

RelayProbe is a Go single-process, on-demand CLI. It has no daemon, browser UI,
HTTP service, plugin execution, or downloaded code path.

Data flow:

```text
text / CSV / JSON / gzip / scenario
        |
 streaming parser + hash deduplication
        |
 bounded job queue
        |
 fixed worker pool -- per-target semaphore
        |
 preflight + cached destination policy -> protocol adapter -> TLS/HTTP validation
        |
 raw observations -> target quorum + rotation + score + bounded histogram
        |
 stdout / checkpoint / quality gate / atomic optional JSONL history
```

Packages are divided by responsibility: `input`, `config`, `scenario`, `policy`,
`protocol`, `engine`, `intel`, `metadata`, `score`, `metrics`, `history`,
`quality`, `output`, `store`, and `cli`.
Interactive and non-interactive commands use the same engine and models.

The global worker count, configurable job/result queues, and per-target semaphores are all
bounded. Each worker checks repeats serially for one proxy, limiting connection
multiplication. An optional cancellation-aware, lock-serialized rate gate
limits global attempt starts without pre-reserving future slots or creating a
timer goroutine per worker. Context deadlines reach
dialing, negotiation, TLS, reads, and writes. SIGINT/SIGTERM close active
connections, cancel production and workers, and return exit 130.

Concurrent destination resolutions are collapsed and safe answers are cached
for a bounded TTL. Failed lookups are not cached. Permanent policy,
authentication, and invalid-protocol observations stop repeats unless the
operator explicitly requests them; successful runs can also stop at the first
success. This avoids predictable connection multiplication while preserving an
exhaustive mode.

Deduplication retains keyed 128-bit in-process identities so credential variants
remain distinct without exposing a credential-derived public ID. Persisted IDs
are 96-bit endpoint hashes over protocol, host, and port. JSONL output writes
directly through a streaming encoder. These keep
allocation and resident-memory growth low on large datasets; exact
deduplication can be disabled for constant parser state.

Gzip is detected from stream magic bytes rather than trusted file extensions.
The byte and record-count budgets are shared across every input source and
enforced on the decompressed stream, so additional files, tiny records, and
compression cannot multiply the configured parser limits. Filename suffixes
are used only to select the nested data format.

Destination hostnames are exact-allowlisted, every returned address is checked,
and the selected safe address is placed in CONNECT/SOCKS requests. HTTPS keeps
the original hostname only for SNI and certificate validation. Each redirect is
resolved and checked again. This design prevents the validation target from
becoming an implicit internal-network access primitive under default settings.
Only the bounded configured-target set is DNS-cached. Remote-controlled
redirects are deliberately re-resolved and never inserted into the cache.
SOCKS4 selects an approved IPv4 answer even if the resolver returned IPv6
first. Auto detection includes SOCKS4a only when remote DNS was deliberately
enabled.

HTTPS proxy transport wraps the proxy TCP connection in TLS 1.2 or newer with
normal hostname and certificate verification. CONNECT or absolute-form HTTP is
then performed inside that protected transport. Proxy TLS and destination TLS
have separate stages and timings.

Raw attempt observations are stored independently from the score. Score changes
therefore do not destroy evidence. Latency summary quantiles use a fixed-memory
1 ms histogram capped at the five-minute maximum attempt duration.

Credential-bearing working lists and standalone JSON summaries share the same
same-directory temporary-file, flush, synchronization, and atomic-commit path.
Canonical path comparison resolves symbolic-link aliases before an output can
replace an input.

Checkpoints append redacted results, periodically flush and synchronize, repair
an incomplete final line on resume, and bound the number of restored IDs.
Dataset sharding is streaming and deterministic by endpoint hash; merging is
bounded by an explicit record limit. Multi-file shard publication prepares all
temporary files first, although the final set cannot be transactionally renamed
as one filesystem operation.

Optional metadata is loaded before workers start into IPv4 and IPv6 prefix maps.
Lookup checks at most 33 IPv4 or 129 IPv6 prefix lengths and never performs a
network request. Content qualification operates only on the already bounded
response body. Transfer rate uses body bytes divided by body-read duration and
is kept separate from TTFB and total latency.

Qualification uses a configurable minimum success ratio. The checker computes
the required success count before starting, stops when that count is reached in
first-success mode, and also stops when it becomes impossible to reach. Partial
success below the requirement is retained as `unreliable` evidence rather than
being promoted to a working proxy.

Matrix scenarios repeat each named target and qualify target-local reliability
before applying a quorum. Rotation intervals apply between rounds, not between
destinations in one round. Direct preflight is independently bounded to four
concurrent destinations and never inherits environment proxy settings.

The local JSONL history remains optional. Cross-run analysis streams bounded
records into endpoint trends; pool analysis deliberately loads only up to its
operator-selected limit to calculate exit/subnet/ASN diversity. No background
service or network metadata lookup is introduced.
