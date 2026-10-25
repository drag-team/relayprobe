BINARY := bin/relayprobe
PREFIX ?= $(HOME)/.local
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf 0.4.0-dev)
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
MODULE := github.com/drag-team/relayprobe
LDFLAGS := -s -w -X $(MODULE)/internal/buildinfo.Version=$(VERSION) -X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) -X $(MODULE)/internal/buildinfo.Date=$(BUILD_DATE)

.PHONY: all build check clean fmt fmt-check install race test uninstall vet

all: check build

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/relayprobe

check: fmt-check vet test race

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

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/relayprobe

clean:
	rm -rf bin dist
