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
