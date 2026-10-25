# Release process

RelayProbe releases are created from annotated Semantic Versioning tags on a
clean `main` branch. The release workflow builds static Linux amd64 and arm64
archives, generates SHA-256 checksum files, and publishes them to GitHub.

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

Move the relevant entries from `Unreleased` to a dated version section in
`CHANGELOG.md`. Confirm that release notes do not contain proxy credentials,
private targets, local paths, or unpublished vulnerability details.

## Tag

Create an annotated tag only after the release commit has passed CI:

```sh
git tag -a v0.4.0 -m "RelayProbe v0.4.0"
git push origin main
git push origin v0.4.0
```

The pushed tag triggers `.github/workflows/release.yml`. A failed workflow must
be fixed and rerun; release artifacts must not be assembled manually from an
unverified working tree.

## Verify

Download each archive and its checksum onto a clean Linux host:

```sh
sha256sum --check relayprobe-v0.4.0-linux-amd64.tar.gz.sha256
tar -xzf relayprobe-v0.4.0-linux-amd64.tar.gz
./relayprobe-v0.4.0-linux-amd64/relayprobe version
./relayprobe-v0.4.0-linux-amd64/relayprobe doctor
```

Confirm the embedded version, commit, target architecture, license, README, and
changelog. Verify both architectures when suitable hardware or emulation is
available.

## Recovery

Do not move or silently replace a published tag. If a release is defective,
document the problem, publish a corrective patch version, and mark the affected
release clearly. If an unpublished local tag is wrong, delete it locally and
recreate it before any push.
