# Running depscan in Sourcecraft CI

Run it on a schedule in the target repo's `.sourcecraft/ci.yaml` and it opens
dependency-update PRs automatically. Sourcecraft injects
`SOURCECRAFT_TOKEN` into the runner; the tool reads it for the PR REST API. No
code change is needed.

## Concrete example (matches the appsec `.sourcecraft/ci.yaml` style)

Add a schedule trigger under the existing `on.schedule:` …

```yaml
on:
  schedule:
    - workflows: [ depscan ]
      cron: "0 6 * * 1"        # Mondays 06:00
```

… and a workflow (same `runs_on`/`checkout`/cube style as the rest of the file):

```yaml
workflows:
  depscan:
    settings:
      max_cube_duration: 20m
    checkout:
      enabled: true            # need the repo to scan and to push branches
    tasks:
      - name: open-update-prs
        cubes:
          - name: install-tool
            script:
              - sudo apt update && sudo apt install -y golang-go
              - go install github.com/axidex/depscan/cmd/depscan@latest
          - name: preview
            script:
              # dry-run first: list the bumps without opening PRs
              - $(go env GOPATH)/bin/depscan --repo .
          - name: open-prs
            env:
              GIT_PAT: ${{ secrets.src.repo.pat }}   # for `git push`
            script:
              # SOURCECRAFT_TOKEN (already in env) authenticates the PR REST API.
              - >
                $(go env GOPATH)/bin/depscan
                --repo .
                --create-prs
                --org <org> --repo-slug <repo>
```

## Environment-specific knobs (verify for your instance)

- **API base** — Pass it with `--api-url`. The
  tool calls `GET /repos/{org}/{repo}`, `POST /repos/id:{repoID}/pulls`,
  `GET /me/pulls`, `POST /pulls/id:{id}/labels`
- **Tool binary** — the cube above assumes the runner can `go install` (Go +
  module-proxy/GitHub access). If it can't, download a release binary or vendor
  one instead of `go install`.
- **git push auth** — PR *creation* uses `SOURCECRAFT_TOKEN` (REST), but the
  *branch* is pushed with `git push origin`. If the CI checkout's `origin` isn't
  already push-authenticated, point it at a token-authed HTTPS URL first (the
  `git remote set-url` line above; adjust host/scheme). There is **no REST commit
  endpoint** on Sourcecraft (branches/trees are read-only), so a real git push is
  required.

## Behavior

- Scans Gradle (`build.gradle.kts`, `gradle.properties`, `libs.versions.toml`),
  PyPI (`requirements*.txt`) and npm (`package.json`); one PR per dependency,
  branch `depscan/<coord>-<target>`. **Idempotent** — a dependency whose
  PR is already open is skipped (via `/me/pulls`), so the schedule won't duplicate.
- Vulnerable deps (OSV) get a `security` label and the fixed version as target;
  `--no-security` skips the OSV check.
- Honors `depscan.json` (ignoreUnstable / allowedVersions / ignoreDeps /
  packageRules / groupName / labels / prConcurrentLimit) if present.

## Dry-run locally first

```bash
depscan --repo /path/to/project          # preview the plan
depscan --repo /path/to/project --write   # apply edits locally (no PR)
```
