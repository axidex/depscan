// Command craftnovate is a permissive, automated dependency-update
// tool for the Sourcecraft platform. It scans a Gradle project's build files for
// declared dependencies, finds newer stable versions on Maven Central, groups
// the upgrades into pull requests, and — with --create-prs — pushes a branch per
// group and opens the PR on Sourcecraft. It runs on the project without an SBOM
// and never executes the build tool.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/axidex/craftnovate/internal/config"
	"github.com/axidex/craftnovate/internal/datasource"
	"github.com/axidex/craftnovate/internal/osv"
	"github.com/axidex/craftnovate/internal/remediate"
	"github.com/axidex/craftnovate/internal/sourcecraft"
	"github.com/axidex/craftnovate/internal/versioning"
	"github.com/axidex/craftnovate/internal/worker"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

// datasource ids used to wire registries and label managers.
const (
	dsMaven        = "maven"
	dsGradlePlugin = "gradle-plugin"
	dsPyPI         = "pypi"
	dsNPM          = "npm"
)

type options struct {
	repo          string
	write         bool
	createPRs     bool
	concurrency   int
	timeout       time.Duration
	verbose       bool
	base          string
	remote        string
	org           string
	repoSlug      string
	apiURL        string
	noSecurity    bool
	groupStrategy string
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1) // cobra already printed the error
	}
}

func newRootCmd() *cobra.Command {
	var o options

	cmd := &cobra.Command{
		Use:   "craftnovate",
		Short: "Automated dependency-update PRs for Sourcecraft",
		Long: "craftnovate scans a Gradle project for declared dependencies, finds newer\n" +
			"stable versions on Maven Central, and reports, applies (--write), or opens\n" +
			"pull requests (--create-prs) for the available upgrades on Sourcecraft.\n" +
			"It runs directly on the project (no SBOM) and never executes the build tool.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: false,
		Args:          cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return run(o)
		},
	}

	f := cmd.Flags()
	f.StringVar(&o.repo, "repo", ".", "path to the project root to scan")
	f.BoolVar(&o.write, "write", false, "apply upgrades to build files in place (local edit, no PR)")
	f.BoolVar(&o.createPRs, "create-prs", false, "open a pull request per upgrade on Sourcecraft (needs SOURCECRAFT_TOKEN)")
	f.IntVar(&o.concurrency, "concurrency", 6, "max concurrent Maven Central lookups")
	f.DurationVar(&o.timeout, "timeout", 3*time.Minute, "overall timeout")
	f.BoolVar(&o.verbose, "verbose", false, "list coordinates that could not be resolved")
	f.StringVar(&o.base, "base", "", "target branch for PRs (default: current branch)")
	f.StringVar(&o.remote, "remote", "origin", "git remote to push branches to")
	f.StringVar(&o.org, "org", "", "Sourcecraft org slug (default: parsed from the remote URL)")
	f.StringVar(&o.repoSlug, "repo-slug", "", "Sourcecraft repo slug (default: parsed from the remote URL)")
	f.BoolVar(&o.noSecurity, "no-security", false, "skip the OSV vulnerability check (no security-priority targets)")
	f.StringVar(&o.apiURL, "api-url", "", "Sourcecraft REST API base URL (default https://api.sourcecraft.tech)")
	f.StringVar(&o.groupStrategy, "group-strategy", "", "PR grouping: monorepo|per-dependency|ecosystem|all (default monorepo)")

	cmd.SetVersionTemplate("craftnovate {{.Version}}\n")
	return cmd
}

func run(o options) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	cfg, err := config.Load(o.repo)
	if err != nil {
		return err
	}
	if path, ok := config.Discover(o.repo); ok {
		fmt.Fprintf(os.Stderr, "using config %s\n", path)
	}

	stratName := o.groupStrategy
	if stratName == "" {
		stratName = cfg.GroupStrategy
	}
	strategy := worker.ParseStrategy(stratName)

	ups, declaredCount, errs, err := planAll(ctx, o, cfg, strategy.SeparatesMajorMinor())
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "scanned %s: %d declared dependenc(ies) across %d manager(s)\n", o.repo, declaredCount, len(remediate.Managers()))
	if declaredCount == 0 {
		fmt.Fprintln(os.Stderr, "nothing to check (no supported manifests found)")
		return nil
	}
	reportLookupErrors(o, errs)
	if len(ups) == 0 {
		if len(errs) > 0 {
			fmt.Printf("no upgrades among the resolvable dependencies (%d could not be checked — see above)\n", len(errs))
		} else {
			fmt.Println("all declared dependencies are up to date")
		}
		return nil
	}

	groups := worker.GroupUpdatesWith(toUpdates(cfg, ups), strategy)
	printPlan(groups)

	switch {
	case o.createPRs:
		return createPRs(ctx, o, groups, cfg.PRConcurrentLimit)
	case o.write:
		// One site can carry both a non-major and a major upgrade; --write edits
		// the working tree once, so collapse to the newest target per site.
		edits := remediate.DedupeBySite(ups)
		if err := remediate.ApplyUpgrades(o.repo, edits); err != nil {
			return err
		}
		fmt.Printf("\napplied %d upgrade(s) to %s\n", len(edits), o.repo)
		return nil
	default:
		fmt.Println("\ndry-run — re-run with --write to edit locally, or --create-prs to open PRs on Sourcecraft")
		return nil
	}
}

// planAll runs every manager against the repo, plans normal upgrades, then
// (unless --no-security) overlays OSV vulnerability fixes as security-priority
// targets. It returns the upgrades, the declared count, and lookup errors.
func planAll(ctx context.Context, o options, cfg config.Config, separateMajorMinor bool) (ups []remediate.Upgrade, declaredCount int, errs []error, err error) {
	datasources := map[string]remediate.VersionLister{
		dsMaven:        datasource.NewMaven(),
		dsGradlePlugin: datasource.NewGradlePlugin(),
		dsPyPI:         datasource.NewPyPI(),
		dsNPM:          datasource.NewNPM(),
	}
	var allDeclared []remediate.DeclaredDependency
	for _, m := range remediate.Managers() {
		declared, mErr := m.Extract(o.repo)
		if mErr != nil {
			return nil, 0, nil, mErr
		}
		allDeclared = append(allDeclared, declared...)
		mUps, mErrs := remediate.PlanUpgrades(ctx, declared, datasources, config.NewSelector(cfg, m.Name()), o.concurrency, separateMajorMinor)
		ups = append(ups, mUps...)
		errs = append(errs, mErrs...)
	}

	if !o.noSecurity {
		if advisories, vErr := vulnAdvisories(ctx, allDeclared); vErr != nil {
			fmt.Fprintf(os.Stderr, "craftnovate: OSV check degraded: %v\n", vErr)
		} else {
			ups = remediate.PlanSecurity(allDeclared, ups, advisories)
		}
	}
	return ups, len(allDeclared), errs, nil
}

// vulnAdvisories asks OSV about every Maven/PyPI declared dependency at its
// current version, keyed for remediate.PlanSecurity.
func vulnAdvisories(ctx context.Context, declared []remediate.DeclaredDependency) (map[string]remediate.VulnAdvisory, error) {
	var coords []osv.Coordinate
	for _, d := range declared {
		if d.Datasource == dsMaven || d.Datasource == dsPyPI {
			coords = append(coords, osv.Coordinate{Ecosystem: d.Datasource, Name: d.Coordinate(), Version: d.Version})
		}
	}
	raw, err := osv.New().Query(ctx, coords)
	if err != nil {
		return nil, err
	}
	out := make(map[string]remediate.VulnAdvisory, len(raw))
	for k, a := range raw {
		out[k] = remediate.VulnAdvisory{VulnIDs: a.VulnIDs, FixedVersions: a.FixedVersions}
	}
	return out, nil
}

func reportLookupErrors(o options, errs []error) {
	if len(errs) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "%d coordinate(s) not resolvable in their registry (internal modules / unknown packages)\n", len(errs))
	if o.verbose {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "  -", e)
		}
	}
}

// toUpdates attaches each upgrade's resolved policy (groupName, labels) from the
// config, for grouping into PRs.
func toUpdates(cfg config.Config, ups []remediate.Upgrade) []worker.Update {
	updates := make([]worker.Update, 0, len(ups))
	for _, u := range ups {
		manager := "gradle"
		switch u.Dep.Datasource {
		case dsPyPI:
			manager = dsPyPI
		case dsNPM:
			manager = dsNPM
		}
		d := cfg.Decide(versioning.Get(u.Dep.Datasource), config.PackageContext{
			Manager: manager, Datasource: u.Dep.Datasource,
			Name: u.Dep.Coordinate(), Current: u.Dep.Version, Target: u.Target,
		})
		labels := d.Labels
		if u.Security {
			labels = append(append([]string(nil), labels...), "security")
		}
		updates = append(updates, worker.Update{Upgrade: u, GroupName: d.GroupName, Manager: manager, Labels: labels})
	}
	return updates
}

func printPlan(groups []worker.PRGroup) {
	fmt.Printf("%d pull request(s) planned:\n", len(groups))
	for _, grp := range groups {
		fmt.Printf("  %s\n    branch: %s\n", grp.Title, grp.Branch)
		if len(grp.Labels) > 0 {
			fmt.Printf("    labels: %s\n", strings.Join(grp.Labels, ", "))
		}
		for _, u := range grp.Upgrades {
			fmt.Printf("      %s:%d  %s -> %s%s\n", u.Dep.File, u.Dep.Line, u.Dep.Version, u.Target, securityNote(u))
		}
	}
}

// securityNote marks an upgrade chosen to fix a vulnerability, naming the
// advisories when known.
func securityNote(u remediate.Upgrade) string {
	if !u.Security {
		return ""
	}
	if len(u.VulnIDs) > 0 {
		return "  [security: " + strings.Join(u.VulnIDs, ", ") + "]"
	}
	return "  [security]"
}

func createPRs(ctx context.Context, o options, groups []worker.PRGroup, maxOpen int) error {
	token := os.Getenv("SOURCECRAFT_TOKEN")
	if token == "" {
		return errors.New("--create-prs requires the SOURCECRAFT_TOKEN environment variable")
	}

	git := worker.NewGit(o.repo)
	base := o.base
	if base == "" {
		b, err := git.CurrentBranch(ctx)
		if err != nil {
			return err
		}
		base = b
	}

	org, slug := o.org, o.repoSlug
	if org == "" || slug == "" {
		ro, rs, err := worker.RepoFromRemote(ctx, git, o.remote)
		if err != nil {
			return err
		}
		if org == "" {
			org = ro
		}
		if slug == "" {
			slug = rs
		}
	}

	var scOpts []sourcecraft.Option
	if o.apiURL != "" {
		scOpts = append(scOpts, sourcecraft.WithBaseURL(o.apiURL))
	}
	sc := sourcecraft.New(token, scOpts...)
	repo, err := sc.GetRepo(ctx, org, slug)
	if err != nil {
		return fmt.Errorf("resolve %s/%s: %w", org, slug, err)
	}

	fmt.Printf("\nopening PRs on %s/%s (base %s, remote %s)...\n", org, slug, base, o.remote)
	results := worker.OpenPRs(ctx, git, sc, repo.ID, base, o.remote, groups, maxOpen)
	if failed := summarizeResults(results); failed > 0 {
		return fmt.Errorf("%d PR(s) failed", failed)
	}
	return nil
}

// summarizeResults prints each PR outcome and returns the failure count.
func summarizeResults(results []worker.PRResult) int {
	var created, skipped, failed int
	for _, r := range results {
		switch r.Action {
		case worker.ActionCreated:
			created++
			fmt.Printf("  ✓ %s (%s)\n", r.Group.Title, r.Group.Branch)
		case worker.ActionExists:
			skipped++
			fmt.Printf("  • %s — already open\n", r.Group.Title)
		case worker.ActionRateLimited:
			skipped++
			fmt.Printf("  • %s — skipped (PR limit reached)\n", r.Group.Title)
		case worker.ActionError:
			failed++
			fmt.Printf("  ✗ %s — %v\n", r.Group.Title, r.Err)
		}
	}
	fmt.Printf("\n%d created, %d skipped, %d failed\n", created, skipped, failed)
	return failed
}
