BINARY      := craftnovate
PKG         := ./cmd/craftnovate
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)
IMAGE       ?= ghcr.io/axidex/craftnovate
IMAGE_TAG   ?= dev

.PHONY: all build install test test-race cover vet fmt lint tidy clean run snapshot docker-build docker-run release-check release-patch release-minor release-major

all: build

build: ## Build the craftnovate binary into ./bin
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

install: ## Install craftnovate into $GOBIN
	go install -ldflags "$(LDFLAGS)" $(PKG)

test: ## Run unit + hermetic e2e tests (no network)
	go test ./...

test-race: ## Run tests with the race detector
	go test -race ./...

cover: ## Run tests and print total coverage
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -n 1

vet: ## Run go vet
	go vet ./...

fmt: ## Format all Go source
	gofmt -s -w .

lint: ## Run golangci-lint (if installed)
	golangci-lint run ./...

release-check: ## Validate the GoReleaser config
	goreleaser check

snapshot: ## Build a local cross-platform snapshot release into dist/ (no publish)
	goreleaser release --snapshot --clean

docker-build: ## Build the Docker image (override IMAGE/IMAGE_TAG/VERSION)
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(IMAGE_TAG) .

docker-run: docker-build ## Run craftnovate in Docker against REPO (default .; dry-run)
	docker run --rm -v $(abspath $(or $(REPO),.)):/repo $(IMAGE):$(IMAGE_TAG) craftnovate --repo /repo

release-patch: ## Compute & push the next PATCH tag (triggers the Release workflow)
	./scripts/release.sh patch

release-minor: ## Compute & push the next MINOR tag (triggers the Release workflow)
	./scripts/release.sh minor

release-major: ## Compute & push the next MAJOR tag (triggers the Release workflow)
	./scripts/release.sh major

tidy: ## Tidy go.mod/go.sum
	go mod tidy

clean: ## Remove build and coverage artifacts
	rm -rf bin dist coverage.out

run: build ## Build and scan a Gradle project (set REPO=path to override; default .)
	./bin/$(BINARY) --repo $(or $(REPO),.)
