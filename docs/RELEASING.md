# Release process

RelayProbe releases are created from annotated Semantic Versioning tags on a
clean `main` branch. The release workflow builds static Linux, macOS, Windows,
and FreeBSD amd64/arm64 archives, generates SHA-256 checksum files, and
publishes them to GitHub.
`VERSION`, the changelog section, and the tag must agree exactly.

## Prepare

Update the version history, verify schemas and user documentation, then run the
full local gate:

```sh
make clean
make check
make build
./bin/relayprobe version
git status --short
```

Choose the stable version, remove its `-dev` suffix from `VERSION`, and move the
relevant entries from `Unreleased` to a dated version section in `CHANGELOG.md`.
Confirm that release notes do not contain proxy credentials, private targets,
local paths, or unpublished vulnerability details. Commit and push that release
preparation before tagging it.

## Tag

Create an annotated tag only after the release commit has passed CI. The
following example uses `0.7.0`; replace it with the version in `VERSION`:

```sh
version="$(cat VERSION)"
git tag -a "v${version}" -m "RelayProbe v${version}"
make release-check
git push origin main
git push origin "v${version}"
```

The pushed tag triggers `.github/workflows/release.yml`. A failed workflow must
be fixed and rerun; release artifacts must not be assembled manually from an
unverified working tree.

## Verify

Download each archive and its checksum onto a matching clean host. For example,
on Linux:

```sh
version="0.7.0"
sha256sum --check "relayprobe-v${version}-linux-amd64.tar.gz.sha256"
tar -xzf "relayprobe-v${version}-linux-amd64.tar.gz"
./"relayprobe-v${version}-linux-amd64"/relayprobe version
./"relayprobe-v${version}-linux-amd64"/relayprobe doctor
```

Confirm the embedded version, commit, target OS and architecture, license,
README, and changelog. Verify every native architecture available to the
maintainer; CI provides native Linux ARM64, macOS ARM64, and Windows x64 coverage
and compile coverage for the remaining release targets.

## Recovery

Do not move or silently replace a published tag. If a release is defective,
document the problem, publish a corrective patch version, and mark the affected
release clearly. If an unpublished local tag is wrong, delete it locally and
recreate it before any push.
