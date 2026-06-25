package remediate

import "github.com/axidex/depscan/internal/versioning"

// VulnAdvisory is a vulnerability source's outcome for one coordinate@version.
type VulnAdvisory struct {
	VulnIDs       []string
	FixedVersions []string
}

// AdvisoryKey is the map key PlanSecurity expects: "<datasource>|<coordinate>|<version>".
func AdvisoryKey(datasource, coordinate, version string) string {
	return datasource + "|" + coordinate + "|" + version
}

// PlanSecurity reconciles normal upgrades with vulnerability advisories: for a
// vulnerable declared dependency it prefers the minimal fixed version that is an
// upgrade (a security upgrade), otherwise it keeps the normal upgrade. The
// result has one entry per editable site, security upgrades taking precedence.
func PlanSecurity(declared []DeclaredDependency, normal []Upgrade, advisories map[string]VulnAdvisory) []Upgrade {
	type siteKey struct {
		file string
		line int
		col  int
	}
	siteOf := func(d DeclaredDependency) siteKey { return siteKey{d.File, d.Line, d.Col} }

	bySite := make(map[siteKey]Upgrade, len(normal))
	for _, u := range normal {
		bySite[siteOf(u.Dep)] = u
	}

	out := make([]Upgrade, 0, len(normal))
	for _, d := range declared {
		if adv, ok := advisories[AdvisoryKey(d.Datasource, d.Coordinate(), d.Version)]; ok {
			if sec := minFixUpgrade(versioning.Get(d.Datasource), d.Version, adv.FixedVersions); sec != "" {
				out = append(out, Upgrade{Dep: d, Target: sec, Security: true, VulnIDs: adv.VulnIDs})
				continue
			}
		}
		if u, ok := bySite[siteOf(d)]; ok {
			out = append(out, u)
		}
	}
	return out
}

// minFixUpgrade returns the smallest fixed version that is a valid upgrade over
// current, or "" if none qualifies.
func minFixUpgrade(v versioning.Versioning, current string, fixed []string) string {
	best := ""
	for _, f := range fixed {
		if !v.IsUpgrade(current, f) {
			continue
		}
		if best == "" || v.Compare(f, best) < 0 {
			best = f
		}
	}
	return best
}
