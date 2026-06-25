# depscan — roadmap to a full-featured dependency-update tool for Sourcecraft

Clean-room, permissive (no AGPL) Go dependency-update tool for Sourcecraft. This
is the living checklist; tick items as they land. Each item ships with tests; the
whole pipeline is covered by a hermetic e2e (`internal/worker`, httptest registry).

Architecture (role → our package): manager → `internal/remediate`,
datasource → `internal/datasource`, versioning → `internal/mavenver`,
lookup/config → `internal/config`, worker → `internal/worker`, platform →
`internal/sourcecraft`. CLI: `cmd/depscan`.

## Foundation (pre-M1) — DONE
- [x] `mavenver`: Compare, IsStable, IsUpgrade, SelectUpgrade (Apache ComparableVersion port) + tests
- [x] `datasource.Maven.Versions` (Maven Central) + httptest tests
- [x] `remediate`: GradleResolver/ExtractDeclared (literal GAV), PlanUpgrades, ApplyUpgrades (minimal in-place edit) + tests
- [x] `worker`: GroupUpgrades, Git.PushBranchWithEdits (git worktree), OpenPRs (idempotent), RepoFromRemote + tests
- [x] `sourcecraft`: GetRepo, CreatePullRequest, FindOpenPRBySourceBranch, ListMyPulls + httptest tests
- [x] CLI: `--repo` / `--write` / `--create-prs` / `--base` / `--remote` / `--org` / `--repo-slug`
- [x] hermetic e2e of the full pipeline (extract → datasource → select → group → apply)

## M1 — control & correctness
- [x] `mavenver.UpdateType(current, target)` → major/minor/patch + tests
- [x] `internal/config` (depscan.json analog): Config/PackageRule, Defaults/Merge/Discover/Load
- [x] packageRules matcher (matchPackageNames incl. `/regex/` + artifact tail, matchPackagePrefixes, matchUpdateTypes, matchManagers); Decide last-wins
- [x] `allowedVersions` evaluator (exact, `<`/`<=`/`>`/`>=`/`=`, `/regex/`) + `ignoreUnstable` + `ignoreDeps`
- [x] `config.Selector` wired into `remediate.PlanUpgrades` (Selector seam, default preserves behavior) — fixes the `0.7.0-0.6.x-compat` case via ignoreUnstable/allowedVersions
- [ ] lookup buckets: separate major/minor/patch into distinct PRs (matchUpdateTypes-driven branches)
- [ ] thread groupName/labels/reviewers Decision into grouping + PR body/reviewers

## M2 — Gradle coverage
- [x] `Manager` interface (Name/Extract) + `Managers()` registry; `GradleManager` adapter
- [x] version catalog `gradle/libs.versions.toml` ([versions]/[libraries]/[plugins], version.ref + inline + shorthand)
- [x] `gradle.properties` + `val` property refs (`"g:a:$ver"` → edit the property/version definition)
- [x] shared version sites collapse to one edit (deterministic representative coordinate)
- [x] catalog plugins + Gradle Plugin Portal datasource (`internal/datasource.MavenMetadata` via maven-metadata.xml)
- [x] datasource dispatch (`DeclaredDependency.Datasource`; `PlanUpgrades` takes `map[string]VersionLister`)
- [x] tests + e2e (catalog pipeline e2e); gomock (`go.uber.org/mock`) for VersionLister + Platform; `golangci-lint` clean
- [ ] follow-up: `plugins { id("x") version "…" }` DSL block + `settings.gradle.kts` pluginManagement (only the catalog `[plugins]` table is wired so far)

## M3 — platform + worker lifecycle
- [x] `sourcecraft` client: `UpdatePullRequest`, `MergePullRequest`, `SetLabels`, `ListRepoPulls` (+ correct PR branch `ref`, `IsOpen`, `SourceBranchName`) + httptest tests
- [x] worker: grouping by config `groupName` (`Update`/`GroupUpdates`), config `labels` applied on create, PR concurrency limit (`prConcurrentLimit`), single-fetch idempotency via `ListMyPulls` (open + branch-prefix count)
- [x] scheduling — handled by Sourcecraft CI `on.schedule` cron (see `docs/sourcecraft-ci.md`)
- [ ] EnsurePR update-in-place (PATCH title/body on drift); reviewers (API uses a `reviewers_delta` model — not yet wired)
- [ ] automerge wiring (MergePullRequest exists; not auto-invoked — needs merge-checks gating)
- [ ] rebase/freshen open PR branches on base change; dependency dashboard issue + rebase checkboxes

## M4 — lockfiles & multi-ecosystem
- [x] versioning abstraction (`internal/versioning`): `Versioning` interface, `Maven` (wraps mavenver), `PEP440` (clean-room PEP 440 ordering/stability/update-type), `Get(datasource)`; selector seam refactored per-ecosystem (`Select`/`Decide`/`Matches`/`AllowedVersionsMatch` take a `Versioning`)
- [x] PyPI datasource (`datasource.PyPI`, pypi.org JSON releases) + PyPI manager (`requirements*.txt` `==` pins; extras/markers preserved); `Managers()` = [Gradle, PyPI]; CLI runs managers per-ecosystem and aggregates
- [x] npm: `versioning.NPM` (semver ordering/stability/update-type + `NewValue` preserving `^`/`~`), `datasource.NPM` (packument), `NPMManager` (package.json, section-aware, `^`/`~`/exact; complex ranges skipped) + tests; `Versioning.NewValue` threaded through `PlanUpgrades` (Maven/PyPI return the version unchanged)
- [ ] datasources: docker (v2 tags), github-releases
- [ ] versioning: docker; richer `rangeStrategy` (bump/widen/pin — currently replace/preserve-operator only)
- [ ] managers: Dockerfile, github-actions
- [ ] `updateArtifacts`: sync lockfiles by running the real tool (Gradle locking, npm) — local + Docker `binarySource`
- [x] OSV vuln datasource → security-priority targets (B-native): `internal/osv` (querybatch + hydrate + fix extraction, PEP 503 name match); `remediate.PlanSecurity` overlays the minimal fixed version as the target for vulnerable deps; PRs labelled `security` with vuln IDs in the body; `--no-security` to skip

---
Design source: a component-design workflow (8 component specs). Update this file
as items land — it is the source of truth for progress.
