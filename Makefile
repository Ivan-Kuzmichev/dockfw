# All Go targets build for Linux: the daemon only runs there. On other hosts
# the tests run inside a golang container (google/nftables is Linux-only).

GO_IMAGE            ?= golang:1.27
STATICCHECK_VERSION ?= v0.8.2

COMMIT  ?= $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo unknown)
VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null || echo 0.0.0-dev+$(COMMIT))
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
IMAGE   ?= dockfw:dev

ifeq ($(shell uname -s),Linux)
GO_RUN :=
else
GO_RUN := docker run --rm -v $(CURDIR):/src -w /src \
	-v dockfw-gomod:/go/pkg/mod -v dockfw-gocache:/root/.cache/go-build \
	$(GO_IMAGE)
endif

.PHONY: all build test lint integration image release-binaries clean

all: lint test build

build:
	CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "$(LDFLAGS)" -o bin/dockfw ./cmd/dockfw

test:
	$(GO_RUN) go test -race ./...

lint:
	GOOS=linux go vet ./...
	GOBIN=$(CURDIR)/bin go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
	GOOS=linux bin/staticcheck ./...
	GOOS=linux golangci-lint run ./...

integration:
	go test -tags integration -count=1 -timeout 15m -v ./test/integration/

image:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) -t $(IMAGE) .

release-binaries:
	rm -rf dist && mkdir -p dist
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/dockfw-linux-$$arch ./cmd/dockfw || exit 1; \
	done
	cd dist && (sha256sum dockfw-linux-* 2>/dev/null || shasum -a 256 dockfw-linux-*) > checksums.txt

clean:
	rm -rf bin dist
