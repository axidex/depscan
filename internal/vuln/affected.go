package vuln

import (
	"regexp"
	"strings"

	"github.com/axidex/depscan/internal/purl"
)

// toVuln distills a hydrated OSV record into a domain Vuln for the package
// identified by queriedPURL. Fixed-version extraction is scoped to the affected
// entries that match the queried package so we never recommend a fix that
// belongs to a different ecosystem in the same advisory.
func toVuln(record osvVuln, queriedPURL string) Vuln {
	v := Vuln{
		ID:      record.ID,
		Aliases: record.Aliases,
		Summary: summaryOf(record),
		CVEs:    cveIDs(record),
	}

	target, _ := purl.Parse(queriedPURL)
	fixes := []string{}
	pkgSeverity := ""
	for _, aff := range record.Affected {
		if !affectedMatches(aff, target) {
			continue
		}
		fixes = append(fixes, fixedVersions(aff)...)
		if pkgSeverity == "" {
			pkgSeverity = bestSeverity(aff.Severity)
		}
	}

	v.FixedVersions = dedupeStrings(fixes)
	v.HasFix = len(v.FixedVersions) > 0

	v.Severity = pkgSeverity
	if v.Severity == "" {
		v.Severity = bestSeverity(record.Severity)
	}

	return v
}

// affectedMatches reports whether an affected entry describes the queried
// package. It prefers a purl comparison and falls back to mapping the OSV
// ecosystem string onto the purl type.
func affectedMatches(aff osvAffected, target purl.PURL) bool {
	if target.Name == "" {
		return false
	}
	if aff.Package.PURL != "" {
		if ap, err := purl.Parse(aff.Package.PURL); err == nil {
			return ap.Type == target.Type &&
				strings.EqualFold(ap.Namespace, target.Namespace) &&
				sameName(target.Type, ap.Name, target.Name)
		}
	}
	// No usable purl: compare ecosystem-derived type and the OSV name string,
	// whose encoding varies by ecosystem (Maven uses "group:artifact", npm may
	// be scoped "@ns/name", PyPI is PEP 503 normalized).
	if ecosystemToType(aff.Package.Ecosystem) != target.Type {
		return false
	}
	return matchesName(target, aff.Package.Name)
}

// matchesName compares an OSV package-name string against the target purl,
// accounting for ecosystem-specific name encodings.
func matchesName(target purl.PURL, osvName string) bool {
	candidates := []string{osvName}
	if target.Namespace != "" {
		candidates = append(candidates,
			strings.TrimPrefix(osvName, target.Namespace+"/"),
			strings.TrimPrefix(osvName, target.Namespace+":"),
		)
	}
	wanted := []string{
		target.Name,
		target.Coordinates(),
		target.Namespace + ":" + target.Name,
	}
	for _, c := range candidates {
		for _, w := range wanted {
			if sameName(target.Type, c, w) {
				return true
			}
		}
	}
	return false
}

var pep503Separators = regexp.MustCompile(`[-_.]+`)

// sameName compares two package names case-insensitively, applying PEP 503
// normalization for PyPI (lowercase; collapse runs of '-', '_', '.' to a
// single '-') so that, e.g., "Flask.SQLAlchemy" matches "flask-sqlalchemy".
func sameName(ecosystem, a, b string) bool {
	if ecosystem == "pypi" {
		return pep503(a) == pep503(b)
	}
	return strings.EqualFold(a, b)
}

func pep503(name string) string {
	return pep503Separators.ReplaceAllString(strings.ToLower(name), "-")
}

// fixedVersions extracts human-readable fixed versions from an affected entry.
// For SEMVER/ECOSYSTEM ranges the event's fixed value is itself a version; for
// GIT ranges it is a commit SHA, so the version lives in database_specific.
func fixedVersions(aff osvAffected) []string {
	out := []string{}
	for _, r := range aff.Ranges {
		isGit := strings.EqualFold(r.Type, "GIT")
		if !isGit {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					out = append(out, ev.Fixed)
				}
			}
		}
		// database_specific.versions carries version strings even for GIT ranges.
		for _, ev := range r.DatabaseSpecific.Versions {
			if ev.Fixed != "" {
				out = append(out, ev.Fixed)
			}
		}
	}
	return out
}

// bestSeverity returns the most informative CVSS score string available,
// preferring newer CVSS versions.
func bestSeverity(sev []osvSeverity) string {
	order := map[string]int{"CVSS_V4": 3, "CVSS_V3": 2, "CVSS_V2": 1}
	best := ""
	bestRank := -1
	for _, s := range sev {
		if s.Score == "" {
			continue
		}
		rank := order[strings.ToUpper(s.Type)]
		if rank > bestRank {
			bestRank = rank
			best = s.Score
		}
	}
	return best
}

func summaryOf(record osvVuln) string {
	if record.Summary != "" {
		return record.Summary
	}
	const limit = 200
	d := strings.TrimSpace(record.Details)
	if len(d) > limit {
		return d[:limit] + "…"
	}
	return d
}

// cveIDs collects CVE identifiers from the record's id and aliases.
func cveIDs(record osvVuln) []string {
	out := []string{}
	add := func(id string) {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			out = append(out, id)
		}
	}
	add(record.ID)
	for _, a := range record.Aliases {
		add(a)
	}
	return dedupeStrings(out)
}

// ecosystemToType maps an OSV ecosystem label to a purl type. The OSV
// ecosystem string may carry a ":suffix" (e.g. "Alpine:v3.16") which is
// stripped before mapping.
func ecosystemToType(ecosystem string) string {
	base, _, _ := strings.Cut(ecosystem, ":")
	switch strings.ToLower(strings.TrimSpace(base)) {
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "maven":
		return "maven"
	case "go":
		return "golang"
	case "crates.io":
		return "cargo"
	case "rubygems":
		return "gem"
	case "nuget":
		return "nuget"
	case "packagist":
		return "composer"
	case "hex":
		return "hex"
	case "pub":
		return "pub"
	default:
		return strings.ToLower(strings.TrimSpace(base))
	}
}
