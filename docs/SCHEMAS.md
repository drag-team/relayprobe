# Data schemas

Machine formats are UTF-8. JSONL contains one complete result object per line;
CSV has a stable header row. Times use RFC 3339 UTC and durations use
milliseconds as floating-point values.

The current `schema_version` is 5. Readers should tolerate unknown fields and
missing fields from older runs. Version 5 adds credential-free endpoint IDs,
target matrices, rotation profiles, TLS evidence, body hashes, labels, target
health, quality reports, and attempt totals. Version 4 added proxy-TLS and body timings,
response size and throughput, offline exit metadata, and the revised anonymity
vocabulary. Version 3 added reliability requirements, the `unreliable`
status/count, and per-target health summaries. Validation targets in results and
summaries are reduced to scheme/authority origins so path, fragment, or query
tokens are never persisted. Scenario target names may replace origins in raw
observations and target summaries.

Result fields:

| Field | Meaning |
|---|---|
| `id` | Truncated SHA-256 protocol/host/port endpoint identifier |
| `proxy` | Protocol URI with username and password replaced by `***` |
| `endpoint` | Credential-free host and port |
| `protocol` | Requested or successful detected protocol |
| `status` | Overall classified status |
| `attempts`, `successes`, `required_successes` | Completed and required measurement counts |
| `observations` | Raw per-attempt evidence and stage timings |
| `target_results`, `target_quorum` | Per-target qualification and required matrix quorum |
| `rotation` | Observed exit stability, changes, dominant share, countries, and ASNs |
| `label` | Optional safe pool or scenario label |
| `score` | Derived value, confidence, inputs, and explanation |
| `checked_at` | Start time of proxy validation |

Observation timings are `dns_ms`, `connect_ms`, `proxy_tls_ms`, `tunnel_ms`,
`tls_ms`, `ttfb_ms`, `body_ms`, and `total_ms`. `body_bytes` and
`throughput_kbps` describe the bounded response transfer. A failure exposes
`stage`, stable `code`, and a sanitized `message`. `exit_ip`, `anonymity`,
`forwarding_evidence`, and `metadata` are present only when the target and local
database supply the required evidence. Forwarding evidence contains header names
without header values. `proxy_authentication` records the successfully negotiated
method. `proxy_tls` and `destination_tls` separately record TLS version, cipher,
ALPN, certificate SHA-256, and certificate expiry. `body_sha256` covers the
bounded final response body.

The CSV export is intentionally flat and contains the last observation's
stage/code plus the most recent successful observation's exit, anonymity,
transfer, and metadata evidence. It also contains the aggregate score and
median. JSONL is the lossless export. TXT emits only safe proxy URIs and should
be filtered by status when used as a working-proxy list.

Run summaries contain cumulative proxy `processed` count, checkpoint `restored`
count, raw observation `attempts`,
`status_count`, `failure_codes`, and `failure_stages`.
These maps count raw observations, so a finally successful proxy can still
contribute an earlier failure. This preserves transient-error evidence.

The same summary object is written by `--summary-output` and by optional run
history. A standalone summary may have an empty `run_id` because no historical
JSONL run was created. Consumers should use `schema_version`, not the presence
of a run identifier, to select a decoder.
The embedded run configuration records both `max_response_bytes` and
`min_response_bytes`, making response-memory and throughput conditions
reproducible without consulting the original command line.

When a quality policy is active, `quality` contains a boolean result and the
actual/operator/expected tuple for every evaluated check. The same evidence is
available as JUnit XML with `--junit-output`.
