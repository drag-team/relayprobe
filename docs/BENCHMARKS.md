# Benchmark method and results

`relayprobe bench` measures bounded scheduler, queue, result, and model overhead
without network access. `--delay` adds a controlled per-item wait. It does not
claim real proxy throughput, because that is dominated by remote latency and
timeouts.

Reproduce with:

```sh
for c in 1 16 64 128 256; do
  ./bin/relayprobe bench --count 100000 --concurrency "$c"
done
/usr/bin/time -v ./bin/relayprobe bench --count 1000000 --concurrency 128
go test -bench . -benchmem ./internal/engine
```

RelayProbe 0.2.0 delivery-host results (Ubuntu 26.04.1, Linux 7.0, 4 vCPU
Haswell-class KVM, Go 1.26.8, 2026-10-24) are the median of three runs with
500,000 zero-delay items. The host was not isolated, so normal VPS scheduling
noise remains:

| Concurrency | Items/s | Elapsed |
|---:|---:|---:|
| 1 | 260,892 | 1.916 s |
| 16 | 586,842 | 0.852 s |
| 64 | 539,200 | 0.927 s |
| 128 | 721,254 | 0.693 s |
| 256 | 684,640 | 0.730 s |

At one million items and concurrency 128, GNU `time` reported 13,020 KiB
maximum RSS; observed scheduler throughput ranged from 542k to 760k items/s
under changing host load. The Go microbenchmark (three runs) reported 1-worker
2.06–2.14 us/op, 16-worker 1.33–1.36 us/op, and 128-worker 1.01–1.03 us/op,
all at 32 B/op and 3 allocations/op. These are scheduler measurements, not
network claims. They also show why RelayProbe does not blindly recommend the
largest concurrency setting.

A separate streamed-input check normalized 200,000 distinct entries in 1.10 s
with 29,536 KiB maximum RSS. Deduplication intentionally retains one hash per
distinct input, so memory is bounded by the input byte limit rather than
strictly constant. Version 0.2.0 adds `--no-deduplicate` for constant parser
state on datasets where duplicate checks are acceptable.

Version 0.3.0 changed deduplication keys from allocated hexadecimal strings to
compact binary values and streams JSONL encoding directly. On a generated file
of 500,000 distinct proxies, measured twice on the same non-isolated host:

| Mode | Elapsed | Max RSS |
|---|---:|---:|
| v0.2.0 exact dedup | 2.87–2.98 s | 66–69 MiB |
| v0.3.0 exact dedup | 2.44–2.60 s | 33–34 MiB |
| v0.3.0 no dedup | 2.17 s | 13.3 MiB |

Output was redirected to `/dev/null`; the input and executable conditions were
otherwise identical. The exact-dedup memory reduction was approximately 50%.

After the v0.3.0 changes, three additional 500,000-item scheduler runs at
concurrency 128 measured 756,062–817,518 items/s, with a median of 813,349
items/s. Host scheduling remained uncontrolled, so this is recorded as a
regression baseline rather than a network-throughput promise.

The public-release verification of RelayProbe 0.4.0 on 2026-10-25 measured
816,643 items/s median under the same 500,000-item, 128-worker scheduler
benchmark (range 791,160–852,932 items/s). A one-million-item run measured
850,592 items/s, 1.17 seconds wall time, and 13,116 KiB maximum RSS. Reliability
threshold calculation and target aggregation remained low-overhead in this
controlled measurement.

Compare builds using the same executable, count, concurrency, delay, Go
version, and host load. Never benchmark against unauthorized proxies.

The 0.5.0 development parser benchmark uses 1,000 distinct text records per
operation on the same four-vCPU host. Three samples produced these medians:

| Input | Time/op | Decompressed throughput | Allocations/op |
|---|---:|---:|---:|
| Plain text | 2.39 ms | 7.91 MB/s | 7,006 |
| Gzip text | 2.48 ms | 7.62 MB/s | 7,027 |

Gzip detection and decompression added 21 allocations per 1,000-record batch
and approximately 3.7% median time in this small-input test. Reproduce with
`go test -run '^$' -bench '^BenchmarkParser' -benchmem -count=3 ./internal/input`.
The throughput column counts decompressed bytes and is not a network result.

The RelayProbe 0.6.0 development scheduler measured 786,085 items/s median
across three 500,000-item runs at concurrency 128 on the same non-isolated host
(range 779,540–855,874 items/s). This remains an engine-overhead baseline, not a
network proxy rate.

The offline IPv4 longest-prefix metadata lookup benchmark measured a median of
408 ns/op across three samples, with zero allocations per lookup. Reproduce with
`go test -run '^$' -bench '^BenchmarkLookupIPv4$' -benchmem -count=3 ./internal/metadata`.

The RelayProbe 0.7.0 development engine measured 812,682 items/s median across
three 500,000-item runs at concurrency 128 on 2026-10-26 (range
789,790–869,883 items/s). The corresponding scheduler microbenchmarks measured
1,962 ns/op with one worker, 1,245 ns/op with 16 workers, and 1,029 ns/op with
128 workers at the median; all retained 32 B/op and 3 allocations/op.

Ephemeral HMAC deduplication was implemented with a bounded stack fast path.
The 1,000-record parser benchmark then measured 3.81 ms/op median for plain text
(4.96 MB/s) and 3.81 ms/op median for gzip (4.96 MB/s), with 5,007 and 5,028
allocations respectively. The host was not isolated and the gzip samples had
visible scheduler variance, so these figures are regression evidence rather
than performance guarantees.

On 2026-10-28, the 0.7.0 development parser was profiled and changed to use
direct endpoint parsing, allocation-free hostname validation, `net/netip`, and
two process-local `hash/maphash` seeds compressed into a 96-bit fingerprint.
Five to seven samples on the same Go 1.26.8 four-vCPU host produced:

| Mode | Median time/1,000 | Throughput | Bytes/op | Allocations/op |
|---|---:|---:|---:|---:|
| Before, text | 3.03 ms | 6.24 MB/s | 345,190 | 5,007 |
| Current, exact dedup | 0.89 ms | 21.3 MB/s | 148,876 | 1,026 |
| Current, no dedup | 0.47 ms | 40.5 MB/s | 89,712 | 1,004 |
| Current, gzip dedup | 1.01 ms | 18.7 MB/s | 203,511 | 1,047 |

An executable-level import of the same 200,000-entry, 5,088,895-byte text file
was alternated five times between commit `74427aa` and the current tree. Output
was redirected to `/dev/null`; medians were 1.21 s and 19,032 KiB maximum RSS
before, versus 0.61 s and 16,200 KiB currently. This measures parsing,
deduplication, normalization, and output formatting together.

The HTTP response parser benchmark uses a fixed in-memory HTTP/1.1 response.
Replacing duplicated header buffers with one limit-enforcing reader reduced the
median from 10.03 us/op, 13,486 B/op, and 23 allocations to 6.08 us/op,
5,123 B/op, and 18 allocations. Reproduce the current measurements with:

```sh
go test -run '^$' -bench '^BenchmarkParser' -benchmem -count=5 ./internal/input
go test -run '^$' -bench '^BenchmarkReadResponseLimited$' -benchmem -count=5 ./internal/protocol
```

### Streaming response evidence

On 2026-10-30, a 1 MiB in-memory response was measured before and after moving
body hashing and byte accounting to a streaming reader. Five samples on the
same four-vCPU Go 1.26.8 host produced these medians:

| Mode | Time/op | Throughput | Bytes/op | Allocations/op |
|---|---:|---:|---:|---:|
| Previous `ReadAll` plus SHA-256 | 6.39 ms | 164 MB/s | 2,228,054 | 26 |
| Streaming, 64 KiB intelligence capture | 4.76 ms | 220 MB/s | 66,140 | 10 |
| Streaming, complete 1 MiB assertion capture | 5.24 ms | 200 MB/s | 1,056,284 | 11 |

The ordinary bounded-capture path used about 97% fewer allocated bytes and was
about 25% faster in this controlled benchmark. Network performance remains
dominated by the proxy and target.

An additional worst-case assertion benchmark searched for an absent ASCII
signature in a 1 MiB response. Five samples produced medians of 4.21 ms and
3,276,633 B/op for the former full-body lowercase path, versus 4.77 ms and
140,068 B/op for the streaming matcher. The matcher therefore used about 95.7%
fewer allocated bytes at a 13% median CPU-time cost confined to checks that
enable text assertions. Matching signatures may finish scanning earlier.

Reproduce both measurements with:

```sh
go test -run '^$' -bench '^BenchmarkReadBodyEvidence$' -benchmem -count=5 ./internal/engine
```
