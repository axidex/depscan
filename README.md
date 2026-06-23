# depscan

`depscan` is a self-contained Go binary for CI/CD that turns a **CycloneDX SBOM**
into a **SARIF 2.1.0** report with an update verdict for every dependency: what
to update and why.

It does **not** generate SBOMs and shells out to **no external binaries** (no
Syft, no Grype). Vulnerability data comes from the [OSV.dev](https://osv.dev)
API; "is there a newer version" comes from the public package registries.

## What it does

For each component in the SBOM it combines two signals:

| Signal       | Source                                | Meaning                                            |
|--------------|---------------------------------------|----------------------------------------------------|
| **Vuln**     | OSV.dev (`querybatch` + `vulns/{id}`) | Known CVEs affecting the pinned version            |
| **Outdated** | npm / PyPI / Maven Central registries | Current vs. latest version (patch / minor / major) |

…into one prioritized verdict:

| Verdict           | SARIF level | When                                                             |
|-------------------|-------------|------------------------------------------------------------------|
| **must-update**   | `error`     | A vulnerability with an **available fix** is present             |
| **should-update** | `warning`   | A vulnerability **without** a fix, or a minor/major version lag  |
| **ok**            | —           | Up to date, patch-only lag, or no data (no SARIF result emitted) |

For `must-update`, the recommended target is the **minimal security fix** newer
than the current version — not necessarily the latest release.

## Install

```bash
go install github.com/axidex/depscan/cmd/depscan@latest
# or, from a checkout:
make build      # -> ./bin/depscan
```

Requires Go 1.23+ (developed against Go 1.26).

## Usage

```bash
depscan --sbom bom.json --out results.sarif [--offline] [--fail-on must-update]
```

| Flag            | Short | Default         | Description                                                                               |
|-----------------|-------|-----------------|-------------------------------------------------------------------------------------------|
| `--sbom`        | `-s`  | _(required)_    | Path to a CycloneDX JSON SBOM (`-` reads stdin)                                           |
| `--out`         | `-o`  | `results.sarif` | Where to write the SARIF report (`-` writes stdout)                                       |
| `--offline`     |       | `false`         | Skip registry (outdated) lookups for air-gapped environments                              |
| `--fail-on`     |       | _(none)_        | Exit non-zero if any finding is at this level or higher: `must-update` \| `should-update` |
| `--format`      |       | `sarif`         | `sarif` (file only) or `table` (also print a human table to stdout)                       |
| `--concurrency` |       | `8`             | Max concurrent registry / OSV requests                                                    |
| `--timeout`     |       | `2m`            | Overall scan timeout                                                                      |
| `--debug`       |       | `false`         | Verbose `slog` debug logging to stderr (OSV/registry/verdict detail)                      |
| `--config`      |       | _(auto)_        | Config file path (defaults to `./.depscan.yaml` or `$HOME/.depscan.yaml`)                 |
| `--version`     |       |                 | Print version and exit                                                                    |

SARIF is always written to `--out`. Progress, warnings, and the summary go to
**stderr**, so `--out -` produces a clean SARIF stream on stdout.

The CLI is built with [Cobra](https://github.com/spf13/cobra) +
[Viper](https://github.com/spf13/viper). Every flag can also be set via an
environment variable (`DEPSCAN_*`, dashes become underscores) or a config file,
resolved in precedence order **flag → env → config file → default**:

```bash
# equivalent ways to enable offline mode and the should-update gate
depscan -s bom.json --offline --fail-on should-update
DEPSCAN_OFFLINE=true DEPSCAN_FAIL_ON=should-update depscan -s bom.json
echo "offline: true"$'\n'"fail-on: should-update" > .depscan.yaml && depscan -s bom.json
```

### Example

```console
$ depscan --sbom bom.json --format table
depscan: scanning 4 component(s) (1 without purl skipped)
VERDICT        PACKAGE   CURRENT   LATEST      UPDATE  CVES                          TARGET
must-update    lodash    4.17.20   4.18.1      minor   CVE-2021-23337,CVE-2020-28500 4.17.21
must-update    requests  2.20.0    2.34.2      minor   CVE-2023-32681,CVE-2024-35195 2.31.0
should-update  core      7.0.0     8.0.1       major   CVE-2026-49356                8.0.1
depscan: 2 must-update, 1 should-update, 0 ok
```

### CI gate

```yaml
- run: depscan --sbom bom.json --out results.sarif --fail-on must-update
# upload results.sarif to your code host's security tab
```

## How it works

**Vulnerabilities (OSV, two-step).** All component purls are sent to
`POST /v1/querybatch` in chunks of ≤1000. The batch response only returns
vulnerability IDs, so each unique ID is then hydrated via `GET /v1/vulns/{id}`
(cached, since one CVE can affect many packages). Fix availability is derived
from each affected range's `fixed` event — including GIT ranges, where the
human-readable version lives in `database_specific.versions`. Withdrawn records
are ignored.

**Outdated (registries).** The purl type routes the component to a
`RegistryChecker`:

- **npm** — `registry.npmjs.org/{pkg}/latest`
- **PyPI** — `pypi.org/pypi/{pkg}/json`
- **Maven** — Maven Central search API

The version gap is classified with semantic-version comparison; non-semver
versions (some Maven coordinates) degrade gracefully to "newer exists / not".

**Graceful degradation.** A registry being unreachable marks that component
`outdated: unknown` rather than failing the run. If OSV itself is unreachable,
the scan continues with a warning and outdated-only verdicts. Requests run
concurrently with a bounded worker pool and retry transient failures with
backoff.

## SARIF output

Each non-ok component becomes one `result`. Beyond the human `message`, the
result `properties` bag carries machine-readable detail:
`currentVersion`, `latestVersion`, `updateType`, `cveIds`, `vulnIds`, `hasFix`,
`recommendedVersion`, `ecosystem`, and `purl`. Rule IDs are stable
(`<problem-type>/<version-less-purl>`), and `partialFingerprints` give
deterministic dedup keys across commits.

## Architecture

```
cmd/depscan        CLI: flags, exit codes, wiring
internal/sbom      CycloneDX JSON parsing -> []Component
internal/purl      Package-URL helpers (ecosystem, version-less id)
internal/vuln      OSV client (querybatch + hydrate + cache)
internal/outdated  RegistryChecker interface + npm/PyPI/Maven + semver classify
internal/verdict   Combine signals -> prioritized verdict
internal/sarif     SARIF 2.1.0 assembly
internal/scan      Orchestration (bounded concurrency)
internal/report    Optional table output
```

### Adding an ecosystem

Implement `outdated.RegistryChecker` (two methods: `Ecosystem()` and
`Latest()`) and register it in `outdated.DefaultRegistries`. Unimplemented
ecosystems (cargo, gem, nuget, golang, composer, …) currently resolve to
`outdated: unknown` and are not flagged for being behind.

## Development

```bash
make test        # unit tests (hermetic, no network)
make test-race   # with the race detector
make test-e2e    # live end-to-end against real OSV + Maven Central (needs network)
make cover       # coverage summary
make run         # build + scan the bundled example SBOM
```

Network clients sit behind interfaces and are mocked with `httptest` in unit
tests — `go test ./...` runs fully offline. The `e2e/` package bundles a real
668-component CycloneDX Maven SBOM: a hermetic parse test runs with the normal
suite, while a live full-pipeline test (build tag `e2e`) scans it against OSV
and Maven Central and asserts SARIF 2.1.0 validity.

## Out of scope (first iteration)

PR creation, SBOM generation, repository listing, EPSS/KEV prioritization, and
VEX output. EPSS/KEV can be layered on later from OSV or a separate feed.
