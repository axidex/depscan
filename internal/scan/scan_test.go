package scan_test

import (
	"context"
	"errors"
	"testing"

	"github.com/axidex/depscan/internal/outdated"
	"github.com/axidex/depscan/internal/purl"
	"github.com/axidex/depscan/internal/sbom"
	"github.com/axidex/depscan/internal/scan"
	"github.com/axidex/depscan/internal/verdict"
	"github.com/axidex/depscan/internal/vuln"
)

type fakeVuln struct {
	results map[string]vuln.Result
	err     error
}

func (f fakeVuln) Query(_ context.Context, _ []string) (map[string]vuln.Result, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.results, nil
}

// fakeRegistry returns a fixed latest version for one ecosystem.
type fakeRegistry struct {
	ecosystem string
	latest    map[string]string // keyed by package name
}

func (f fakeRegistry) Ecosystem() string { return f.ecosystem }
func (f fakeRegistry) Latest(_ context.Context, p purl.PURL) (string, error) {
	if v, ok := f.latest[p.Name]; ok {
		return v, nil
	}
	return "", outdated.ErrNotFound
}

func components() []sbom.Component {
	return []sbom.Component{
		{PURL: "pkg:npm/lodash@4.17.20", Name: "lodash", Version: "4.17.20"},
		{PURL: "pkg:npm/guava@30.0.0", Name: "guava", Version: "30.0.0"},
		{PURL: "pkg:npm/safe@1.0.0", Name: "safe", Version: "1.0.0"},
	}
}

func newScanner() *scan.Scanner {
	v := fakeVuln{results: map[string]vuln.Result{
		"pkg:npm/lodash@4.17.20": {Vulns: []vuln.Vuln{{
			ID:            "CVE-2021-23337",
			CVEs:          []string{"CVE-2021-23337"},
			HasFix:        true,
			FixedVersions: []string{"4.17.21"},
		}}},
	}}
	reg := fakeRegistry{ecosystem: "npm", latest: map[string]string{
		"lodash": "4.17.21",
		"guava":  "33.0.0",
		"safe":   "1.0.0",
	}}
	return scan.New(v, outdated.NewChecker(reg))
}

func byName(verdicts []verdict.Verdict) map[string]verdict.Verdict {
	m := map[string]verdict.Verdict{}
	for _, v := range verdicts {
		m[v.Component.Name] = v
	}
	return m
}

func TestScanner_Scan(t *testing.T) {
	t.Parallel()

	rep, err := newScanner().Scan(context.Background(), components(), scan.Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(rep.Verdicts) != 3 {
		t.Fatalf("verdicts = %d, want 3", len(rep.Verdicts))
	}

	v := byName(rep.Verdicts)
	if v["lodash"].Level != verdict.LevelMust {
		t.Errorf("lodash = %q, want must-update", v["lodash"].Level)
	}
	if v["lodash"].TargetVersion != "4.17.21" {
		t.Errorf("lodash target = %q, want 4.17.21", v["lodash"].TargetVersion)
	}
	if v["guava"].Level != verdict.LevelShould {
		t.Errorf("guava = %q, want should-update", v["guava"].Level)
	}
	if v["safe"].Level != verdict.LevelOK {
		t.Errorf("safe = %q, want ok", v["safe"].Level)
	}
}

func TestScanner_Offline(t *testing.T) {
	t.Parallel()

	// Offline skips registry lookups: guava should no longer be flagged for
	// being outdated, but the vulnerable lodash is still must-update.
	rep, err := newScanner().Scan(context.Background(), components(), scan.Options{Offline: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	v := byName(rep.Verdicts)
	if v["guava"].Outdated.Kind != outdated.KindUnknown {
		t.Errorf("guava outdated kind = %q, want unknown (offline)", v["guava"].Outdated.Kind)
	}
	if v["guava"].Level != verdict.LevelOK {
		t.Errorf("guava level = %q, want ok (offline, no vuln)", v["guava"].Level)
	}
	if v["lodash"].Level != verdict.LevelMust {
		t.Errorf("lodash level = %q, want must-update (vuln still resolved offline)", v["lodash"].Level)
	}
}

func TestScanner_VulnDegradesGracefully(t *testing.T) {
	t.Parallel()

	reg := fakeRegistry{ecosystem: "npm", latest: map[string]string{"guava": "33.0.0"}}
	scanner := scan.New(fakeVuln{err: errors.New("osv unreachable")}, outdated.NewChecker(reg))

	rep, err := scanner.Scan(context.Background(), components(), scan.Options{})
	if err != nil {
		t.Fatalf("Scan should not fail on OSV error: %v", err)
	}
	if len(rep.Warnings) == 0 {
		t.Error("expected a warning for degraded vuln lookup")
	}
	// guava is still flagged as outdated even though OSV failed.
	if byName(rep.Verdicts)["guava"].Level != verdict.LevelShould {
		t.Errorf("guava = %q, want should-update", byName(rep.Verdicts)["guava"].Level)
	}
}

func TestScanner_NilVulnClient(t *testing.T) {
	t.Parallel()

	reg := fakeRegistry{ecosystem: "npm", latest: map[string]string{"lodash": "4.17.21"}}
	scanner := scan.New(nil, outdated.NewChecker(reg))

	rep, err := scanner.Scan(context.Background(), components(), scan.Options{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// No vuln client -> lodash only flagged by outdated (patch -> ok).
	if byName(rep.Verdicts)["lodash"].Level != verdict.LevelOK {
		t.Errorf("lodash = %q, want ok (no vuln client, patch only)", byName(rep.Verdicts)["lodash"].Level)
	}
}

func TestScanner_Empty(t *testing.T) {
	t.Parallel()

	rep, err := newScanner().Scan(context.Background(), nil, scan.Options{})
	if err != nil {
		t.Fatalf("Scan(nil): %v", err)
	}
	if len(rep.Verdicts) != 0 {
		t.Errorf("verdicts = %d, want 0", len(rep.Verdicts))
	}
}
