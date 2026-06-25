# depscan

A permissive, automated **dependency-update tool for [Sourcecraft](https://sourcecraft.dev)**
(Yandex Cloud git), written in Go. It scans a project's manifests for declared
dependencies, finds newer **stable** versions in their registries, and reports,
applies, or opens a **pull request** per upgrade on Sourcecraft — and raises the
fixed version for dependencies with known vulnerabilities.

It is a **clean-room** implementation of the standard dependency-bot model
(manager → datasource → versioning → policy → worker → platform), permissively
licensed, with a Sourcecraft platform. It runs directly on the project — **no
SBOM** — and **never executes the build tool**. **No copyleft/AGPL code is
linked or vendored.**

## What it does

```
scan manifests ──▶ look up versions ──▶ pick target ──▶ group ──▶ apply / open PR
  (managers)        (datasources)     (versioning+policy+OSV)     (worker + platform)
```

For each declared dependency it picks the newest *stable* upgrade (correct
per-ecosystem version ordering — a release-candidate or downgrade is never
proposed); for vulnerable deps it prefers the minimal fixed version. It edits the
version in place (minimal diff) and, on `--create-prs`, opens one PR per
dependency on Sourcecraft.

## Install / build

```bash
go install github.com/axidex/depscan/cmd/depscan@latest
# or from a checkout:
make build      # -> ./bin/depscan
```
Requires Go 1.26+.

## Usage

```bash
depscan --repo /path/to/project              # dry-run: list the upgrades
depscan --repo /path/to/project --write       # apply the bumps to manifests locally
SOURCECRAFT_TOKEN=<PAT> depscan --repo . --create-prs   # open a PR per upgrade
```

| Flag                    | Default            | Description                                                  |
|-------------------------|--------------------|--------------------------------------------------------------|
| `--repo`                | `.`                | Project root to scan                                         |
| `--write`               | `false`            | Apply upgrades to manifests in place (no PR)                |
| `--create-prs`          | `false`            | Open a PR per upgrade (needs `SOURCECRAFT_TOKEN`)           |
| `--no-security`         | `false`            | Skip the OSV vulnerability check                            |
| `--api-url`             | _(public API)_     | Sourcecraft REST base (override for self-hosted/enterprise instances) |
| `--base`                | _(current branch)_ | Target branch for PRs                                        |
| `--remote`              | `origin`           | Git remote to push branches to                              |
| `--org` / `--repo-slug` | _(from remote URL)_| Sourcecraft org / repo slug                                 |
| `--concurrency`         | `6`                | Max concurrent registry lookups                             |
| `--verbose`             | `false`            | List coordinates that could not be resolved                 |

The CLI is built with [Cobra](https://github.com/spf13/cobra); progress/warnings
go to **stderr**, the plan/results to stdout.

## Continuous updates (Sourcecraft CI)

Run it on a schedule in the target repo's `.sourcecraft/ci.yaml` and it opens
dependency-update PRs automatically. Sourcecraft CI injects `SOURCECRAFT_TOKEN`,
which the tool reads for the PR API. Re-runs are idempotent. See
[`docs/sourcecraft-ci.md`](docs/sourcecraft-ci.md) for a ready-to-paste workflow.

## Configuration — `depscan.json`

Drop a `depscan.json` (or `.depscan.json`, `.github/depscan.json`) in the repo
root:

```json
{
  "ignoreUnstable": true,
  "ignoreDeps": ["com.example:internal-lib"],
  "prConcurrentLimit": 10,
  "packageRules": [
    { "matchUpdateTypes": ["major"], "enabled": false },
    { "matchPackagePrefixes": ["org.junit"], "allowedVersions": "<5.13" },
    { "matchPackageNames": ["/^io\\.netty:/"], "groupName": "netty", "labels": ["deps"] }
  ]
}
```

- **ignoreUnstable** (default `true`) — never propose alpha/beta/milestone/rc/snapshot.
- **ignoreDeps** — coordinates to skip (exact, `/regex/`, or artifact tail).
- **allowedVersions** — constraint: `<x` / `<=x` / `>x` / `>=x` / `=x` / `/regex/`.
- **prConcurrentLimit** — cap on simultaneously-open PRs (0 = unlimited).
- **packageRules** — ordered; each set `match*` is AND-ed, values within one OR-ed,
  matching rules apply last-wins. Selectors: `matchManagers`, `matchPackageNames`
  (exact / `/regex/` / artifact tail), `matchPackagePrefixes`, `matchUpdateTypes`.
  Settings: `enabled`, `allowedVersions`, `ignoreUnstable`, `groupName`, `labels`,
  `reviewers`.

## How it works

- **Managers** (`internal/remediate`) — extract editable version sites: Gradle
  (`build.gradle.kts`/`.gradle` literals, `gradle.properties` & `val` refs,
  `libs.versions.toml` catalog, plugins), PyPI (`requirements*.txt`), npm
  (`package.json`). `ApplyUpgrades` rewrites the version in place.
- **Datasources** (`internal/datasource`) — list published versions: Maven
  Central, Gradle Plugin Portal, PyPI, npm.
- **Versioning** (`internal/versioning`, `internal/mavenver`) — per-ecosystem
  ordering/stability/update-type: Maven (clean-room Apache `ComparableVersion`
  port), PEP 440, semver/npm (with `^`/`~` range preservation).
- **Policy** (`internal/config`) — resolves `depscan.json` + packageRules into a
  per-dependency decision and picks the target.
- **Security** (`internal/osv`) — checks declared deps against OSV.dev; vulnerable
  deps get the minimal fixed version as target and a `security` label.
- **Worker** (`internal/worker`) — groups upgrades into PRs (one per dependency or
  by `groupName`), pushes a branch via a throwaway `git worktree` (your checkout
  is never disturbed), opens the PR, idempotent and concurrency-limited.
- **Platform** (`internal/sourcecraft`) — Sourcecraft REST client (bearer PAT;
  `--api-url` to override the base for self-hosted/enterprise instances).

## Supported today

- **Gradle** (literals, `gradle.properties`/`val` refs, version catalog, plugins),
  **PyPI** (`requirements*.txt` `==` pins), **npm** (`package.json` `^`/`~`/exact).
- Not yet: docker / GitHub-Actions managers, lockfile sync (`updateArtifacts`),
  richer `rangeStrategy`. See the roadmap.

## Development

```bash
make test        # unit + hermetic e2e (no network — registries mocked with httptest)
make test-race   # with the race detector
make lint        # golangci-lint
make run REPO=/path/to/project   # build + dry-run on a project
```

## Roadmap

The path to full dependency-bot parity (more managers/datasources, lockfile
`updateArtifacts`, richer ranges, worker lifecycle) is tracked in
[`docs/roadmap.md`](docs/roadmap.md).

## License posture

Clean-room and permissive: depscan's own code, an Apache-2.0 reference algorithm
(Maven `ComparableVersion`, ported), and the public Sourcecraft REST API. **No
AGPL code is linked or vendored.**
