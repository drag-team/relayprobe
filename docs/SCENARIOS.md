# Validation scenarios

Scenarios make repeatable multi-target validation reviewable in source control.
The file is strict JSON, limited to 1 MiB, and currently uses
`"schema_version": 1`. Unknown fields, duplicate URLs, invalid thresholds, and
ambiguous same-origin targets without distinct names are rejected before any
network work.

Each target accepts:

- `name`: safe persisted name, required when another target has the same origin;
- `url`: HTTP or HTTPS validation URL without credentials;
- `min_http_status` and `max_http_status`;
- `min_response_bytes` and `min_throughput_kbps`;
- repeatable `require_text`, `reject_text`, and `expect_json` rules;
- `expected_body_sha256` for exact bounded-body integrity.

Top-level controls are `repeat`, `min_success_rate`, `target_matrix`,
`target_quorum`, `rotation_samples`, and `rotation_interval`. In matrix mode,
every target is attempted once per round. A target qualifies from its own
success ratio; the proxy qualifies when at least the quorum of targets qualifies.
The planned matrix is capped at 1,000 attempts per proxy before network activity.

```sh
relayprobe check --scenario examples/scenario.json --preflight report --save proxies.txt
```

Command-line engine options still take precedence where an equivalent flag is
available. Supplying explicit `--target` values replaces scenario targets and
their target-specific rules. Scenario names become the default result pool label
unless `--label` is supplied.

Target content must be controlled or explicitly authorized. Assertion rules can
identify block pages or challenges, but RelayProbe does not bypass them.
