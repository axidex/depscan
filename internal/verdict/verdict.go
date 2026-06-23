// Package verdict combines the vulnerability and outdated signals for a single
// component into a prioritized verdict: must-update, should-update, or ok.
package verdict

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/axidex/depscan/internal/outdated"
	"github.com/axidex/depscan/internal/sbom"
	"github.com/axidex/depscan/internal/vuln"
)

// Level is the prioritized verdict for a component.
type Level string

const (
	// LevelOK means no action is required.
	LevelOK Level = "ok"
	// LevelShould means an update is recommended: a minor/major version lag, a
	// newer (non-semver) release, or a vulnerability with no available fix.
	LevelShould Level = "should-update"
	// LevelMust means a vulnerability with an available fix is present.
	LevelMust Level = "must-update"
)

// Verdict is the combined assessment for one component.
type Verdict struct {
	Component sbom.Component
	Level     Level
	Vulns     []vuln.Vuln
	Outdated  outdated.Result
	// TargetVersion is the recommended version to upgrade to: the minimal
	// security fix for must-update, otherwise the latest published version.
	TargetVersion string
	// HasFix is true when at least one present vulnerability has a known fix.
	HasFix  bool
	Reasons []string
}

// outdatedActionable reports whether an outdated kind warrants a should-update
// on its own. Patch-only lag and unknown are intentionally not actionable.
func outdatedActionable(k outdated.UpdateKind) bool {
	switch k {
	case outdated.KindMinor, outdated.KindMajor, outdated.KindNewer:
		return true
	default:
		return false
	}
}

// Decide computes the verdict for comp given its vulnerability and outdated
// results. Priority: must-update (vuln with fix) > should-update (vuln without
// fix, or minor/major lag) > ok.
func Decide(comp sbom.Component, vr vuln.Result, or outdated.Result) Verdict {
	v := Verdict{
		Component: comp,
		Level:     LevelOK,
		Vulns:     vr.Vulns,
		Outdated:  or,
		Reasons:   []string{},
	}

	hasVuln := len(vr.Vulns) > 0
	for _, vu := range vr.Vulns {
		if vu.HasFix {
			v.HasFix = true
			break
		}
	}

	switch {
	case hasVuln && v.HasFix:
		v.Level = LevelMust
		v.TargetVersion = recommendedFix(comp.Version, vr.Vulns)
		if v.TargetVersion == "" && or.Known() {
			v.TargetVersion = or.Latest
		}
	case hasVuln:
		v.Level = LevelShould
		if outdatedActionable(or.Kind) {
			v.TargetVersion = or.Latest
		}
	case outdatedActionable(or.Kind):
		v.Level = LevelShould
		v.TargetVersion = or.Latest
	}

	v.Reasons = buildReasons(v)
	return v
}

// recommendedFix returns the smallest known fixed version strictly greater than
// current. It falls back to the highest fixed version, then to any fixed
// version, when versions are not cleanly comparable.
func recommendedFix(current string, vulns []vuln.Vuln) string {
	cv, cerr := semver.NewVersion(current)

	var bestAbove *semver.Version
	bestAboveRaw := ""
	var highest *semver.Version
	highestRaw := ""
	anyRaw := ""

	for _, vu := range vulns {
		for _, f := range vu.FixedVersions {
			if anyRaw == "" {
				anyRaw = f
			}
			fv, err := semver.NewVersion(f)
			if err != nil {
				continue
			}
			if highest == nil || fv.GreaterThan(highest) {
				highest, highestRaw = fv, f
			}
			if cerr == nil && fv.Compare(cv) <= 0 {
				continue
			}
			if bestAbove == nil || fv.LessThan(bestAbove) {
				bestAbove, bestAboveRaw = fv, f
			}
		}
	}

	switch {
	case bestAboveRaw != "":
		return bestAboveRaw
	case highestRaw != "":
		return highestRaw
	default:
		return anyRaw
	}
}

func buildReasons(v Verdict) []string {
	reasons := []string{}

	if len(v.Vulns) > 0 {
		ids := VulnIDs(v.Vulns)
		fixNote := "no fix available"
		if v.HasFix {
			fixNote = fmt.Sprintf("fix available (%s)", v.TargetVersion)
		}
		reasons = append(reasons, fmt.Sprintf(
			"%d known vulnerabilit%s [%s] — %s",
			len(v.Vulns),
			plural(len(v.Vulns), "y", "ies"),
			strings.Join(ids, ", "),
			fixNote,
		))
	}

	if outdatedActionable(v.Outdated.Kind) {
		reasons = append(reasons, fmt.Sprintf(
			"%s update available: %s → %s",
			v.Outdated.Kind,
			emptyAs(v.Component.Version, "?"),
			v.Outdated.Latest,
		))
	} else if v.Outdated.Kind == outdated.KindPatch {
		reasons = append(reasons, fmt.Sprintf(
			"patch update available: %s → %s",
			emptyAs(v.Component.Version, "?"),
			v.Outdated.Latest,
		))
	}

	return reasons
}

// VulnIDs returns the OSV IDs of the given vulnerabilities, sorted.
func VulnIDs(vulns []vuln.Vuln) []string {
	ids := make([]string, 0, len(vulns))
	for _, vu := range vulns {
		ids = append(ids, vu.ID)
	}
	sort.Strings(ids)
	return ids
}

// CVEs returns the union of CVE identifiers across the given vulnerabilities,
// sorted and de-duplicated.
func CVEs(vulns []vuln.Vuln) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, vu := range vulns {
		for _, cve := range vu.CVEs {
			if !seen[cve] {
				seen[cve] = true
				out = append(out, cve)
			}
		}
	}
	sort.Strings(out)
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func emptyAs(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
