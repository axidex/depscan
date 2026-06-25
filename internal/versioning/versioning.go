// Package versioning abstracts per-ecosystem version semantics behind one
// interface, so the manager/selector pipeline can compare and pick upgrade
// targets for Maven, PyPI, and future ecosystems without hard-coding a scheme.
package versioning

import "github.com/axidex/craftnovate/internal/mavenver"

// Versioning is the comparison/selection surface a single ecosystem provides.
type Versioning interface {
	// Compare returns -1, 0, or +1 as a is older than, equal to, or newer than b.
	Compare(a, b string) int
	// IsStable reports whether v is a release (no pre-release qualifier).
	IsStable(v string) bool
	// IsUpgrade reports whether candidate is a newer version acceptable to ship
	// over current (a pre-release only when current is itself a pre-release).
	IsUpgrade(current, candidate string) bool
	// UpdateType classifies an upgrade as "major"/"minor"/"patch", or "" when
	// candidate is not strictly newer.
	UpdateType(current, target string) string
	// SelectUpgrade returns the newest candidate that IsUpgrade, or "".
	SelectUpgrade(current string, candidates []string) string
	// NewValue renders the manifest value to write for newVersion, preserving the
	// shape of currentValue. Pinned ecosystems return newVersion; npm preserves a
	// leading range operator (e.g. "^1.2.3" + "1.5.0" → "^1.5.0").
	NewValue(currentValue, newVersion string) string
}

// Get returns the Versioning for a datasource id. Maven Central and the Gradle
// Plugin Portal use Maven semantics; PyPI uses PEP 440; npm uses semver. Unknown
// → Maven.
func Get(datasource string) Versioning {
	switch datasource {
	case "pypi":
		return PEP440{}
	case "npm":
		return NPM{}
	default:
		return Maven{}
	}
}

// Maven implements Versioning via the Apache ComparableVersion port in mavenver.
// Each method delegates to the corresponding mavenver function.
type Maven struct{}

// Compare delegates to mavenver.Compare.
func (Maven) Compare(a, b string) int { return mavenver.Compare(a, b) }

// IsStable delegates to mavenver.IsStable.
func (Maven) IsStable(v string) bool { return mavenver.IsStable(v) }

// IsUpgrade delegates to mavenver.IsUpgrade.
func (Maven) IsUpgrade(current, candidate string) bool { return mavenver.IsUpgrade(current, candidate) }

// UpdateType delegates to mavenver.UpdateType.
func (Maven) UpdateType(current, target string) string { return mavenver.UpdateType(current, target) }

// SelectUpgrade delegates to mavenver.SelectUpgrade.
func (Maven) SelectUpgrade(current string, c []string) string {
	return mavenver.SelectUpgrade(current, c)
}

// NewValue returns newVersion unchanged: Maven coordinates are pinned.
func (Maven) NewValue(_, newVersion string) string { return newVersion }
