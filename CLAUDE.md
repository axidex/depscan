# depscan

SBOM (CycloneDX JSON) → SARIF 2.1.0 dependency-update analyzer. Module
`github.com/axidex/depscan`, Go 1.26. Vulns from OSV.dev; "outdated" from
npm/PyPI/Maven registries. Architecture & full CLI reference live in README.md.

## Commands
- Run: `go run ./cmd/depscan -s bom.json` — use the **package path**, not
  `go run cmd/depscan/main.go` (cmd spans main.go/root.go/run.go; a single-file
  run fails with "undefined: newRootCmd").
- `make test` (hermetic, no network) · `make test-race` · `make test-e2e`
  (live OSV+Maven, needs network) · `make cover` · `make build`.
- Before finishing: `gofmt -s -w .` and `go test -race ./...`.

## CLI (cobra + viper)
- Flag value resolves: flag → env `DEPSCAN_*` (dashes→underscores) →
  `.depscan.yaml` → default.
- SARIF → `--out` (or stdout via `--out -`); all progress/logs/summary →
  **stderr** only, never mixed. `--out=- --format=table` is rejected.
- `--debug` enables `log/slog` debug records to stderr.
- Exit codes: 0 ok · 1 runtime error or `--fail-on` gate · 2 usage error.

## Testing (suite is fully offline)
- Network clients sit behind interfaces, mocked with `httptest`.
- `cmd`: override the `newScanner` package var to inject fakes; call `runScan()`
  directly for hermetic end-to-end.
- `vuln`: `WithEndpoints(batchURL, vulnBase)` + `WithRetries` aim the OSV client
  at a test server. `outdated`: pass an `*http.Client` with a URL-rewriting
  `RoundTripper`. Loggers default to `slog.New(slog.DiscardHandler)`.
- e2e: `e2e/parse_test.go` (hermetic, default) + `e2e/live_test.go`
  (`//go:build e2e`); the live test asserts SARIF invariants, not CVE counts.

## Verified API gotchas (don't re-derive or regress)
- OSV querybatch: send a versioned purl alone — passing both `version` and a
  versioned purl → HTTP 400. Batch returns only `{id, modified}`; hydrate each
  via `GET /v1/vulns/{id}`, cached by ID. Skip `withdrawn` records.
- OSV fix version: `affected[].ranges[].events[].fixed`; for GIT ranges it's in
  `database_specific.versions[].fixed`.
- OSV affected-name match: Maven names are `group:artifact` (colon); PyPI needs
  PEP 503 normalization (`[-_.]+`→`-`, lowercased).
- Maven Central returns HTTP 200 with `numFound:0` for missing packages (no 404).

## Conventions
Follow the `.agents/skills/golang-*` (samber) skills: stdlib-first, minimal
deps, early returns, errors wrapped with `%w`, table-driven tests with
`t.Parallel()`.
