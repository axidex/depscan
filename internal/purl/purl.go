// Package purl provides a thin, scanner-oriented wrapper around Package URLs.
//
// It parses a raw purl string into the few fields depscan cares about and
// exposes helpers for the two operations used across the codebase: routing by
// ecosystem type and producing a stable, version-less identifier for SARIF
// rule IDs and fingerprints.
package purl

import (
	"fmt"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

// PURL is the subset of a parsed Package URL used by depscan.
type PURL struct {
	// Raw is the original, unmodified purl string.
	Raw string
	// Type is the package ecosystem, e.g. "npm", "pypi", "maven".
	Type string
	// Namespace is the optional grouping component (npm scope, maven groupId).
	Namespace string
	// Name is the package name (maven artifactId).
	Name string
	// Version is the pinned version, if any.
	Version string
}

// Parse decodes a purl string. It returns an error for an empty or malformed
// purl so callers can degrade gracefully rather than scan a bogus coordinate.
func Parse(raw string) (PURL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return PURL{}, fmt.Errorf("purl: empty string")
	}

	parsed, err := packageurl.FromString(raw)
	if err != nil {
		return PURL{}, fmt.Errorf("purl: parse %q: %w", raw, err)
	}

	return PURL{
		Raw:       raw,
		Type:      strings.ToLower(parsed.Type),
		Namespace: parsed.Namespace,
		Name:      parsed.Name,
		Version:   parsed.Version,
	}, nil
}

// Coordinates returns "namespace/name" when a namespace is present, otherwise
// just "name". It is the human-facing package identifier without a version.
func (p PURL) Coordinates() string {
	if p.Namespace != "" {
		return p.Namespace + "/" + p.Name
	}
	return p.Name
}

// WithoutVersion returns a canonical, version-less purl string of the form
// pkg:type/namespace/name. It is deterministic and used for stable SARIF rule
// IDs and partial fingerprints. Qualifiers and subpaths are intentionally
// dropped so the identifier stays stable across builds.
func (p PURL) WithoutVersion() string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	b.WriteByte('/')
	if p.Namespace != "" {
		b.WriteString(p.Namespace)
		b.WriteByte('/')
	}
	b.WriteString(p.Name)
	return b.String()
}
