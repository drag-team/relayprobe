# Roadmap

RelayProbe prioritizes correctness, bounded resource use, and defensible network
security over protocol breadth. The roadmap is intentionally outcome-oriented;
it is not a promise that every item will ship unchanged.

## Near term

- Publish reproducible, checksummed Linux amd64 and arm64 release archives.
- Add compatibility coverage across current Ubuntu LTS releases.
- Expand hostile-input fuzzing for CSV, JSON, JSONL, and HTTP response parsing.
- Add deterministic benchmark comparison tooling for pull requests.

## Under evaluation

- Signed releases, provenance attestations, and software bills of materials.
- Optional metadata providers with explicit privacy controls and local caching.
- A transactional SQLite history backend for larger local datasets.
- Additional authenticated proxy mechanisms backed by controlled fixtures.

## Explicitly out of scope

- Proxy discovery, Internet-wide scanning, and scraping proxy lists.
- A web dashboard, HTTP API, background daemon, or privileged service.
- TLS verification bypasses, destination-policy bypasses, or evasion features.
- Claims of guaranteed anonymity based only on missing forwarding headers.

Feature proposals should describe the operational need, security impact,
resource cost, and a realistic verification strategy.
