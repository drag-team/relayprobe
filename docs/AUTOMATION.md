# Automation and distributed datasets

RelayProbe keeps machine results on stdout and diagnostics on stderr. JSONL is
the lossless streaming format; CSV is flat; TXT contains redacted proxy URIs.
Exit 5 means validation completed but a requested success or quality threshold
was not met.

## Quality gates

`--policy` loads strict schema-versioned JSON. Supported thresholds are
`min_processed`, `min_successful`, `min_success_rate`, `max_failure_rate`,
`max_inconclusive_rate`, `max_timeout_rate`, `max_p95_ms`, `min_rate_per_sec`,
`require_preflight`, and `target_min_success_rate`. Rates use 0..1 fractions.
Timeout rate uses raw attempts; proxy success, failure, and inconclusive rates
use processed endpoints.

```sh
relayprobe check --scenario examples/scenario.json \
  --policy examples/quality-policy.json \
  --summary-output summary.json --junit-output relayprobe.xml proxies.txt
```

Reports and summaries are mode 0600, synchronized, and atomically published.

## Checkpoint and resume

```sh
relayprobe check --checkpoint run.checkpoint.jsonl proxies.txt
relayprobe check --resume run.checkpoint.jsonl proxies.txt
```

Each completed result is appended before ordinary output and synchronized every
100 records by default. Resume removes a torn final record and rejects malformed
complete records. Existing checkpoint results are streamed into final output,
statistics, quality evaluation, and optional saved history before newly completed
results. The checkpoint is therefore the authoritative cumulative run; inputs
should describe the same dataset when resuming. `--checkpoint-sync 1` maximizes durability at higher I/O cost.
Endpoint IDs exclude credentials, so use separate checkpoints for alternate
credentials on one protocol/host/port.
Only one process may own a checkpoint at a time; concurrent writers fail with
an operational error. Existing checkpoints must be owner-only regular files,
and symbolic links are rejected without being followed.

## Shard and merge

```sh
relayprobe shard --shards 8 --strategy hash --output-dir shards proxies.txt
relayprobe merge --strategy best --format jsonl --output combined.jsonl shard-*.jsonl
```

Hash sharding is deterministic by endpoint and keeps credential variants on one
shard. Round-robin is available when equal record counts matter more. Shard files
contain full credentials and are mode 0600. `merge` bounds input records with
`--max-load` and selects either the newest or strongest result per public
endpoint ID. It never merges credential-bearing working lists.

Check, import, and shard enforce both aggregate byte and record limits. The
defaults are 256 MiB decompressed and 1,000,000 records; use
`--max-input-bytes`/`--max-input-entries` for check and
`--max-bytes`/`--max-entries` for import or shard.

`results`, `export`, `history`, `pool`, and `stats` are the non-interactive
interfaces for CI. `explore` intentionally refuses non-TTY execution.
