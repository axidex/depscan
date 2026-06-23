// Package vuln resolves known vulnerabilities for SBOM components using the
// OSV.dev API. It performs the two-step OSV protocol — a batched querybatch to
// discover vulnerability IDs affecting each pinned version, then per-ID
// hydration to fetch severity and fixed-version data — behind a small Client
// interface so callers can mock it in tests.
package vuln

import "context"

// Vuln is a single vulnerability affecting a component, distilled from the OSV
// record to the fields depscan needs for its verdict.
type Vuln struct {
	// ID is the OSV identifier (often a GHSA or CVE id).
	ID string
	// Aliases are alternate identifiers for the same issue.
	Aliases []string
	// CVEs are the aliases (and ID) that are CVE identifiers.
	CVEs []string
	// Summary is a short human description.
	Summary string
	// Severity is a representative CVSS vector/score string, if published.
	Severity string
	// FixedVersions lists versions that resolve this vulnerability for the
	// queried package. Empty when no fix is known.
	FixedVersions []string
	// HasFix is true when at least one fixed version is known.
	HasFix bool
}

// Result is the set of vulnerabilities affecting one queried purl.
type Result struct {
	Vulns []Vuln
}

// Client queries a vulnerability database for a set of versioned purls and
// returns, per purl, the vulnerabilities affecting that exact version.
//
// Implementations must be safe for the depscan workflow: a transport failure
// should be returned as an error so the caller can decide whether to degrade
// gracefully, while a purl with simply no vulnerabilities maps to a zero-value
// Result.
type Client interface {
	Query(ctx context.Context, purls []string) (map[string]Result, error)
}
