# Architecture

RelayProbe is a Go single-process, on-demand CLI. It has no daemon, browser UI,
HTTP service, plugin execution, or downloaded code path.

Data flow:

```text
text / CSV / JSON / gzip
        |
 streaming parser + hash deduplication
        |
 bounded job queue
        |
 fixed worker pool -- per-target semaphore
        |
 cached destination policy -> protocol adapter -> TLS/HTTP validation
        |
 raw observations -> derived score + bounded histogram
        |
 stdout formatter / atomic optional JSONL history
```

Packages are divided by responsibility: `input`, `config`, `policy`,
`protocol`, `engine`, `score`, `metrics`, `output`, `store`, and `cli`.
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

Deduplication retains compact 96-bit binary identities instead of hexadecimal
strings. JSONL output writes directly through a streaming encoder. These keep
allocation and resident-memory growth low on large datasets; exact
deduplication can be disabled for constant parser state.

Gzip is detected from stream magic bytes rather than trusted file extensions.
The byte budget is shared across every input source and enforced on the
decompressed stream, so additional files and compression cannot multiply the
configured parser limit. Filename suffixes are used only to select the nested
data format.

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

Raw attempt observations are stored independently from the score. Score changes
therefore do not destroy evidence. Latency summary quantiles use a fixed-memory
1 ms histogram capped at the five-minute maximum attempt duration.

Credential-bearing working lists and standalone JSON summaries share the same
same-directory temporary-file, flush, synchronization, and atomic-commit path.
Canonical path comparison resolves symbolic-link aliases before an output can
replace an input.

Qualification uses a configurable minimum success ratio. The checker computes
the required success count before starting, stops when that count is reached in
first-success mode, and also stops when it becomes impossible to reach. Partial
success below the requirement is retained as `unreliable` evidence rather than
being promoted to a working proxy.
