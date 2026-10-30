BINARY := bin/relayprobe
PREFIX ?= $(HOME)/.local
VERSION ?= $(shell tr -d '\n' < VERSION)
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
MODULE := github.com/drag-team/relayprobe
LDFLAGS := -s -w -X $(MODULE)/internal/buildinfo.Version=$(VERSION) -X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) -X $(MODULE)/internal/buildinfo.Date=$(BUILD_DATE)

.PHONY: all build check clean cross-check fmt fmt-check install race release-check test uninstall version vet

all: check build

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/relayprobe

check: fmt-check vet test race

cross-check:
	@set -eu; tmp="$$(mktemp -d)"; trap 'rm -rf "$$tmp"' EXIT; \
	for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64 freebsd/arm64 openbsd/amd64 netbsd/amd64 dragonfly/amd64 illumos/amd64 solaris/amd64 aix/ppc64; do \
		os="$${target%/*}"; arch="$${target#*/}"; suffix=""; test "$$os" != windows || suffix=.exe; \
		printf 'building %s\n' "$$target"; \
		CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" go build -trimpath -o "$$tmp/relayprobe-$$os-$$arch$$suffix" ./cmd/relayprobe; \
	done

fmt:
	gofmt -w cmd internal

fmt-check:
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -d cmd internal; exit 1; }

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

install: build
	install -Dm755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/relayprobe

version:
	@printf '%s\n' '$(VERSION)'

release-check:
	@case '$(VERSION)' in ''|*-dev) printf '%s\n' 'VERSION must contain a stable release version' >&2; exit 1;; esac
	@printf '%s\n' '$(VERSION)' | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$$' || { printf '%s\n' 'VERSION must use stable Semantic Versioning' >&2; exit 1; }
	@test "$$(cat VERSION)" = '$(VERSION)' || { printf '%s\n' 'VERSION override does not match the canonical VERSION file' >&2; exit 1; }
	@test "$$(git cat-file -t 'v$(VERSION)' 2>/dev/null)" = tag || { printf '%s\n' 'annotated release tag v$(VERSION) is missing' >&2; exit 1; }
	@test "$$(git rev-parse HEAD)" = "$$(git rev-list -n 1 'v$(VERSION)')" || { printf '%s\n' 'release tag does not point to HEAD' >&2; exit 1; }
	@grep -Fq '## [$(VERSION)]' CHANGELOG.md || { printf '%s\n' 'CHANGELOG.md has no section for $(VERSION)' >&2; exit 1; }
	@test -z "$$(git status --porcelain)" || { printf '%s\n' 'working tree is not clean' >&2; exit 1; }
	@$(MAKE) check

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/relayprobe

clean:
	rm -rf bin dist
