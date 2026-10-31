# Versioning and releases

NetVex uses Semantic Versioning. Published versions have the form `vX.Y.Z`;
development versions use `X.Y.Z-dev` on the default branch.

## Sources of version information

| Location | Purpose |
|---|---|
| [`VERSION`](../VERSION) | Version used by local Makefile builds |
| [`CHANGELOG.md`](../CHANGELOG.md) | Human-readable changes in each version |
| Git tag `vX.Y.Z` | Immutable source revision for a published version |
| [GitHub Releases](https://github.com/drag-team/netvex/releases) | Platform archives, checksums, and release notes |
| `netvex version` | Version, commit, build time, Go version, OS, and architecture of an executable |

The repository does not commit generated binaries. Development work stays in
the `Unreleased` changelog section until a release is prepared. A development
version is not a published release and may be skipped; this is why no `v0.5.0`
tag exists even though the development line previously used that number.

## Compatibility policy

Before `v1.0.0`, minor versions may change command flags or result schemas.
Schema changes increment `schema_version`, and readers should tolerate unknown
fields. Patch releases contain compatible fixes. Published tags are never moved
or silently replaced.

Release archives are produced for static Linux, macOS, Windows, and FreeBSD
amd64 and arm64 executables. Windows uses ZIP; the other platforms use tar.gz.
Each archive has an adjacent SHA-256 file. Source archives are provided
automatically by GitHub. Native CI executes Linux amd64/arm64, macOS arm64, and
Windows amd64; FreeBSD and the remaining release architectures are verified by
cross-compiling the application and its test packages.

The complete maintainer procedure is documented in
[RELEASING.md](RELEASING.md).
