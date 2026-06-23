// Package scan orchestrates the depscan pipeline: it queries the vulnerability
// client once for all components, checks registries for outdated versions with
// bounded concurrency, and combines both signals into per-component verdicts.
package scan

import (
	"context"
	"fmt"
	"log/slog"

	"golang.org/x/sync/errgroup"

	"github.com/axidex/depscan/internal/outdated"
	"github.com/axidex/depscan/internal/sbom"
	"github.com/axidex/depscan/internal/verdict"
	"github.com/axidex/depscan/internal/vuln"
)

// Options tunes a scan run.
type Options struct {
	// Offline skips registry (outdated) lookups for air-gapped environments;
	// vulnerability queries are still attempted.
	Offline bool
	// Concurrency bounds simultaneous registry requests. Defaults to 8.
	Concurrency int
	// Logger receives debug diagnostics. Nil disables scan-level logging.
	Logger *slog.Logger
}

// Report is the result of a scan.
type Report struct {
	Verdicts []verdict.Verdict
	// Warnings collects non-fatal degradations (e.g. OSV unreachable) so the
	// caller can surface them without failing the run.
	Warnings []string
}

// Scanner combines a vulnerability client and an outdated checker.
type Scanner struct {
	vuln     vuln.Client
	outdated *outdated.Checker
}

// New constructs a Scanner. Either dependency may be nil to disable that
// signal (e.g. a nil vuln client skips vulnerability resolution entirely).
func New(v vuln.Client, o *outdated.Checker) *Scanner {
	return &Scanner{vuln: v, outdated: o}
}

// Scan analyzes components and returns a verdict per component (in input order).
func (s *Scanner) Scan(ctx context.Context, components []sbom.Component, opts Options) (Report, error) {
	report := Report{
		Verdicts: make([]verdict.Verdict, 0, len(components)),
		Warnings: []string{},
	}
	if len(components) == 0 {
		return report, nil
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	logger.DebugContext(ctx, "scan: starting",
		"components", len(components), "offline", opts.Offline, "concurrency", opts.Concurrency)

	vulnResults := s.queryVulns(ctx, components, &report)
	logger.DebugContext(ctx, "scan: vulnerability lookup complete", "purlsWithVulns", len(vulnResults))

	outdatedResults, err := s.checkOutdated(ctx, components, opts)
	if err != nil {
		return report, err
	}

	var must, should int
	for i, c := range components {
		vr := vulnResults[c.PURL]
		or := outdatedResults[i]
		v := verdict.Decide(c, vr, or)
		switch v.Level {
		case verdict.LevelMust:
			must++
		case verdict.LevelShould:
			should++
		}
		logger.DebugContext(ctx, "scan: verdict",
			"package", c.Name, "version", c.Version, "level", string(v.Level),
			"vulns", len(v.Vulns), "outdated", string(or.Kind), "target", v.TargetVersion)
		report.Verdicts = append(report.Verdicts, v)
	}
	logger.DebugContext(ctx, "scan: complete",
		"mustUpdate", must, "shouldUpdate", should, "ok", len(components)-must-should)

	return report, nil
}

// queryVulns runs a single batched vulnerability query. An OSV failure is a
// non-fatal degradation: it is recorded as a warning and the scan proceeds
// with no vulnerability data.
func (s *Scanner) queryVulns(ctx context.Context, components []sbom.Component, report *Report) map[string]vuln.Result {
	if s.vuln == nil {
		return map[string]vuln.Result{}
	}

	purls := make([]string, 0, len(components))
	for _, c := range components {
		if c.PURL != "" {
			purls = append(purls, c.PURL)
		}
	}
	if len(purls) == 0 {
		return map[string]vuln.Result{}
	}

	results, err := s.vuln.Query(ctx, purls)
	if err != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("vulnerability lookup degraded: %v", err))
		return map[string]vuln.Result{}
	}
	return results
}

// checkOutdated resolves the outdated result for each component (by index),
// with bounded concurrency. Offline mode or a nil checker yields all-unknown.
// Individual registry failures are folded into KindUnknown by the checker, so
// the only error returned here is context cancellation.
func (s *Scanner) checkOutdated(ctx context.Context, components []sbom.Component, opts Options) ([]outdated.Result, error) {
	results := make([]outdated.Result, len(components))

	if opts.Offline || s.outdated == nil {
		for i, c := range components {
			results[i] = outdated.Result{Current: c.Version, Kind: outdated.KindUnknown}
		}
		return results, nil
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 8
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	for i, c := range components {
		g.Go(func() error {
			if gctx.Err() != nil {
				return gctx.Err()
			}
			results[i] = s.outdated.Check(gctx, c.PURL, c.Version)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("scan: outdated checks cancelled: %w", err)
	}
	return results, nil
}
