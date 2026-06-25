# craftnovate

A permissive, **clean-room automated dependency-update tool for the Sourcecraft
platform** (Yandex Cloud git). Module `github.com/axidex/craftnovate`, Go 1.26. It
scans a project's manifests, finds newer stable versions in the registries, and
reports / applies / opens pull requests on Sourcecraft, raising the fixed version
for dependencies with known vulnerabilities. Runs on the project — **no SBOM** —
and **never executes the build tool**. Full reference in README.md; the remaining
work is tracked in `docs/roadmap.md` (the living checklist).

> History: this repo used to be a CycloneDX-SBOM → SARIF analyzer. That tool was
> deleted in favor of this dependency-update tool. Don't reintroduce SBOM/SARIF.

## License posture (hard constraint)
The project ships under **MIT** (`LICENSE`). Permissive only — **never copy or
vendor any AGPL-licensed dependency bot's code** —
reimplement behavior from public specs/observed behavior. Inputs allowed: this
repo's own code, the Apache-2.0 Maven `ComparableVersion` algorithm (ported in
`internal/mavenver`), the public Sourcecraft REST API. Writing in Go also keeps
clean-room distance.

## Commands
- Run: `go run ./cmd/craftnovate --repo /path/to/project` (dry-run). `--write` applies
  edits locally; `--create-prs` opens PRs (needs `SOURCECRAFT_TOKEN`).
- `make build` (→ `./bin/craftnovate`) · `make test` (unit + hermetic e2e, no
  network) · `make test-race` · `make cover` · `make lint` (golangci-lint v2) ·
  `make run REPO=…`.
- Docker: `make docker-build` / `make docker-run REPO=…`. Multi-stage `Dockerfile`
  (static binary → alpine + git/openssh/ca-certs, non-root, `safe.directory '*'`);
  `docker.yml` publishes the multi-arch image to `ghcr.io/axidex/craftnovate` on `v*`.
- Before finishing: `gofmt -s -w .`, `go test ./...`, `golangci-lint run ./...`.
- Release (tag-driven): `make release-patch|minor|major` → `scripts/release.sh`
  pushes a tag → `release.yml` runs GoReleaser (`.goreleaser.yaml` builds
  `./cmd/craftnovate`; tag is the version source, `-X main.version`).

## Architecture (role → package)
- `cmd/craftnovate` — cobra CLI: flags, manager loop, dry-run/write/create-prs.
- `internal/remediate` — **managers**: Gradle (literals, `gradle.properties`/`val`
  refs, `libs.versions.toml` catalog, plugins), PyPI (`requirements*.txt`), npm
  (`package.json`); `Manager` interface + `Managers()`; `PlanUpgrades` (a
  `Selector` seam + datasource dispatch; `separateMajorMinor` buckets into
  non-major/major upgrades), `ApplyUpgrades` (minimal in-place edit) + `DedupeBySite`
  (newest target per site for `--write`), `PlanSecurity` (OSV-fix overlay).
- `internal/datasource` — **datasources**: Maven Central (solr), Gradle Plugin
  Portal (maven-metadata.xml), PyPI (JSON), npm (packument).
- `internal/versioning` — **versioning** interface; `Maven` (wraps mavenver),
  `PEP440`, `NPM` (semver + `NewValue` preserving `^`/`~`); `Get(datasource)`.
- `internal/mavenver` — clean-room Apache `ComparableVersion` port.
- `internal/config` — **policy**: `craftnovate.json` (Config/PackageRule/Decide/Matches,
  allowedVersions, ignoreUnstable/ignoreDeps, groupName, labels, prConcurrentLimit,
  groupStrategy); `Selector` (takes a `versioning.Versioning` per call).
- `internal/osv` — **vulnerability**: OSV querybatch + hydrate + fix extraction.
- `internal/worker` — **worker/platform glue**: `GroupUpgrades`/`GroupUpdates`/
  `GroupUpdatesWith(strategy)` (Renovate-style grouping: `GroupStrategy`
  monorepo/per-dependency/ecosystem/all in `strategy.go`, monorepo-family table,
  security PRs always isolated), `Git.PushBranchWithEdits` (throwaway `git worktree`),
  `OpenPRs` (idempotent, concurrency-limited, labels), `RepoFromRemote`.
- `internal/sourcecraft` — **platform**: REST client (GetRepo, CreatePullRequest,
  UpdatePullRequest, MergePullRequest, SetLabels, ListMyPulls/ListRepoPulls).

## Verified gotchas (don't re-derive)
- **Versions are ecosystem-specific, not generic semver.** Maven (`4.1.133.Final`,
  `5.0.0.CR7`), PEP 440, npm each have their own ordering — always go through
  `internal/versioning`, never string/`Masterminds` compare. Pre-releases (rc/alpha/
  milestone/snapshot/dev) are never proposed unless current is already a pre-release;
  this avoids false "newer" (RC tags, `.Final` downgrades).
- **Per-ecosystem value rewrite**: `Versioning.NewValue(currentValue, newVersion)` —
  Maven/PyPI pin (return newVersion), npm preserves `^`/`~`. `PlanUpgrades` wraps the
  chosen version with it.
- **PR creation is outward-facing**: `--create-prs` pushes branches (throwaway
  worktree; checkout untouched) and opens PRs; gated on `SOURCECRAFT_TOKEN`,
  default dry-run; idempotent via `ListMyPulls`. There is **no REST commit endpoint**
  on Sourcecraft (branches/trees are read-only) → a real `git push` is required.
- **Sourcecraft API base differs per instance**: the public default is
  `https://api.sourcecraft.tech`; self-hosted/enterprise instances differ — pass
  `--api-url`. Bearer PAT / `SOURCECRAFT_TOKEN`. OpenAPI at `/sourcecraft.swagger.json`.
- **OSV**: querybatch versioned purls; hydrate `GET /v1/vulns/{id}`; fix in
  `affected[].ranges[].events[].fixed` (GIT → `database_specific.versions`); skip
  withdrawn; PyPI name match needs PEP 503. Only maven/pypi are OSV-checked (npm
  ranges have no single resolved version).

## CI / release
- `.github/workflows/ci.yml` (generic: `go build/test -race/vet ./...`, golangci-lint
  v2 **pinned** `v2.12.2`, govulncheck) and `release.yml` (GoReleaser on `v*` tags).
  Both are tool-agnostic.
- `release.yml` ships binaries; `docker.yml` ships the container image (separate,
  `buildx`+QEMU multi-arch → GHCR, `packages: write`, builds from the `Dockerfile`).
- golangci-lint v2: suppress gosec with `//nolint:gosec // reason`; `_test.go` is
  exempt from errcheck/gosec/funlen/goconst. mockgen output (`mock_*_test.go`) is
  generated and skipped by lint.
- Uses Go 1.26 features: `new(expr)`, `strings.SplitSeq`. go.mod pins `go 1.26.4`.
- Writing `.github/workflows/*` trips a security hook that denies the first Write —
  re-issue it.

## Conventions
Follow the `.agents/skills/golang-*` (samber) skills: stdlib-first, minimal deps
(`cobra`, `golang.org/x/sync`, `go.uber.org/mock`, `resty.dev/v3` for HTTP), early
returns, errors wrapped with `%w`, table-driven tests with `t.Parallel()`. All
outbound HTTP goes through **resty** (`internal/datasource` share `newRestyClient`;
`internal/osv` and `internal/sourcecraft` build their own); `With*HTTPClient` opts
inject `httptest` clients via `resty.NewWithClient`. Interfaces are mocked with
**gomock** (`go.uber.org/mock`, `//go:generate mockgen`) or httptest; the suite is
fully offline.
