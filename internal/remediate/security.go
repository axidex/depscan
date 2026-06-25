package remediate

import "github.com/axidex/craftnovate/internal/versioning"

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
// vulnerable declared dependency it replaces that site's normal upgrade(s) with
// a single security upgrade to the minimal fixed version, otherwise it keeps the
// normal upgrade(s). A site may carry more than one normal upgrade when
// major/minor are separated, so they are tracked per site as a slice.
func PlanSecurity(declared []DeclaredDependency, normal []Upgrade, advisories map[string]VulnAdvisory) []Upgrade {
	type siteKey struct {
		file string
		line int
		col  int
	}
	siteOf := func(d DeclaredDependency) siteKey { return siteKey{d.File, d.Line, d.Col} }

	bySite := make(map[siteKey][]Upgrade, len(normal))
	for _, u := range normal {
		k := siteOf(u.Dep)
		bySite[k] = append(bySite[k], u)
	}

	out := make([]Upgrade, 0, len(normal))
	for _, d := range declared {
		if adv, ok := advisories[AdvisoryKey(d.Datasource, d.Coordinate(), d.Version)]; ok {
			v := versioning.Get(d.Datasource)
			if sec := minFixUpgrade(v, d.Version, adv.FixedVersions); sec != "" {
				out = append(out, Upgrade{
					Dep: d, Target: v.NewValue(d.Version, sec), UpdateType: v.UpdateType(d.Version, sec),
					Security: true, VulnIDs: adv.VulnIDs,
				})
				continue
			}
		}
		out = append(out, bySite[siteOf(d)]...)
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
