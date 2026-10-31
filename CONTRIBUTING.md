# Contributing to NetVex

NetVex welcomes focused, tested contributions that preserve its terminal-only
design, bounded resource model, and destination security guarantees.

## Before opening a change

Use a GitHub issue for substantial features, protocol additions, data schema
changes, or behavior that weakens a safety default. Security vulnerabilities
must follow [SECURITY.md](SECURITY.md) and must not be disclosed in a public
issue.

Small bug fixes, tests, and documentation corrections can go directly to a pull
request.

## Development setup

Requirements are Go 1.24 or newer, GNU Make, and Git.

```sh
git clone https://github.com/drag-team/netvex.git
cd netvex
make check
make build
```

No external Go modules, root privileges, or live public proxies are required by
the test suite.

## Change requirements

- Keep ordinary operation fully terminal-based and non-interactive when explicit arguments are supplied.
- Keep concurrency, memory, retries, response sizes, and timeouts bounded.
- Preserve TLS verification and destination-policy enforcement.
- Never add proxy discovery, unrelated port scanning, evasion, or rate-limit bypass behavior.
- Keep credentials out of logs, diagnostics, fixtures, history, and error text.
- Add controlled fixtures for every protocol or classification change.
- Update schemas and user documentation when observable output changes.
- Record user-visible changes under `Unreleased` in [CHANGELOG.md](CHANGELOG.md).

Run the complete local gate before submitting:

```sh
make check
```

Focused commands are available as `make fmt-check`, `make test`, `make vet`,
and `make race`.

## Testing network behavior

Use in-memory peers, loopback fixtures, or infrastructure you are explicitly
authorized to operate. Do not place third-party proxy credentials or endpoints
in tests, issues, benchmark output, or pull requests. Tests that require an
external network are not accepted into the default CI path.

Performance changes should include comparable before-and-after commands,
environment details, multiple samples, and raw measurements. Scheduler results
must not be presented as real proxy throughput.

## Pull requests

Keep commits reviewable and the scope coherent. The pull request description
must explain the problem, security implications, test evidence, schema or CLI
impact, and documentation changes. Maintainers may request that unrelated work
be split into a separate change.

By contributing, you agree that your contribution is licensed under the
Apache License 2.0.
