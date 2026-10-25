# Versioning and releases

RelayProbe uses Semantic Versioning. Published versions have the form `vX.Y.Z`;
development versions use `X.Y.Z-dev` on the default branch.

## Sources of version information

| Location | Purpose |
|---|---|
| [`VERSION`](../VERSION) | Version used by local Makefile builds |
| [`CHANGELOG.md`](../CHANGELOG.md) | Human-readable changes in each version |
| Git tag `vX.Y.Z` | Immutable source revision for a published version |
| [GitHub Releases](https://github.com/drag-team/relayprobe/releases) | Linux archives, checksums, and release notes |
| `relayprobe version` | Version, commit, build time, Go version, OS, and architecture of an executable |

The repository does not commit generated binaries. Development work stays in
the `Unreleased` changelog section until a release is prepared. A development
version is not a published release and may be skipped; this is why no `v0.5.0`
tag exists even though the development line previously used that number.

## Compatibility policy

Before `v1.0.0`, minor versions may change command flags or result schemas.
Schema changes increment `schema_version`, and readers should tolerate unknown
fields. Patch releases contain compatible fixes. Published tags are never moved
or silently replaced.

Release archives are currently produced for static Linux amd64 and arm64
executables. Each archive has an adjacent SHA-256 file. Source archives are
provided automatically by GitHub.

The complete maintainer procedure is documented in
[RELEASING.md](RELEASING.md).
