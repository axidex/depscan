BINARY      := depscan
PKG         := ./cmd/depscan
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)

.PHONY: all build install test test-race test-e2e cover vet fmt lint tidy clean run

all: build

build: ## Build the depscan binary into ./bin
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

install: ## Install depscan into $GOBIN
	go install -ldflags "$(LDFLAGS)" $(PKG)

test: ## Run unit tests
	go test ./...

test-race: ## Run unit tests with the race detector
	go test -race ./...

test-e2e: ## Run the live end-to-end test against real OSV/registries (needs network)
	go test -tags=e2e -timeout=10m ./e2e/...

cover: ## Run tests and print total coverage
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -n 1

vet: ## Run go vet
	go vet ./...

fmt: ## Format all Go source
	gofmt -s -w .

lint: ## Run golangci-lint (if installed)
	golangci-lint run ./...

tidy: ## Tidy go.mod/go.sum
	go mod tidy

clean: ## Remove build and coverage artifacts
	rm -rf bin dist coverage.out results.sarif

run: build ## Build and scan the example SBOM (set SBOM=path to override)
	./bin/$(BINARY) --sbom $(or $(SBOM),internal/sbom/testdata/bom.json) --out results.sarif --format table
