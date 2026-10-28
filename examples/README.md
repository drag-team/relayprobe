# Examples

The files in this directory are templates, not live validation infrastructure.
`validation.example.net` is a reserved placeholder and must be replaced with an
authorized controlled target before use.

- `scenario.json` demonstrates named matrix targets and per-target assertions.
- `quality-policy.json` demonstrates CI thresholds matching those target names.

Review target authorization, expected content, response size, and rate limits
before running either template. Do not commit production proxy credentials or
private target tokens to a public repository.
