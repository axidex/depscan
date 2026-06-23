// Package e2e holds end-to-end tests that exercise depscan against real-world
// SBOMs. Tests in this file are hermetic (no network) and run with the normal
// suite; the live OSV/registry test is gated behind the "e2e" build tag.
package e2e

import (
	"os"
	"testing"

	"github.com/axidex/depscan/internal/purl"
	"github.com/axidex/depscan/internal/sbom"
)

const kotlinSBOM = "data/CdxSbomKotlin.json"

// loadKotlinComponents parses the bundled Kotlin SBOM fixture.
func loadKotlinComponents(t *testing.T) []sbom.Component {
	t.Helper()
	f, err := os.Open(kotlinSBOM)
	if err != nil {
		t.Fatalf("open %s: %v", kotlinSBOM, err)
	}
	t.Cleanup(func() { f.Close() })

	components, skipped, err := sbom.Parse(f)
	if err != nil {
		t.Fatalf("parse %s: %v", kotlinSBOM, err)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0 (every component should carry a purl)", skipped)
	}
	return components
}

// TestKotlinSBOM_Parse verifies depscan parses a large, real CycloneDX 1.6
// Maven SBOM: 668 components, all Maven purls (with ?type=jar qualifiers).
func TestKotlinSBOM_Parse(t *testing.T) {
	t.Parallel()

	components := loadKotlinComponents(t)

	const wantCount = 668
	if len(components) != wantCount {
		t.Errorf("component count = %d, want %d", len(components), wantCount)
	}

	foundStdlib := false
	for _, c := range components {
		p, err := purl.Parse(c.PURL)
		if err != nil {
			t.Errorf("component %q has unparseable purl %q: %v", c.Name, c.PURL, err)
			continue
		}
		if p.Type != "maven" {
			t.Errorf("component %q: type = %q, want maven", c.Name, p.Type)
		}
		if p.Namespace == "" || p.Name == "" {
			t.Errorf("component %q: missing groupId/artifactId in %q", c.Name, c.PURL)
		}
		if c.Version == "" {
			t.Errorf("component %q: empty version", c.Name)
		}
		if c.PURL == "pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@2.1.21?type=jar" {
			foundStdlib = true
			if p.WithoutVersion() != "pkg:maven/org.jetbrains.kotlin/kotlin-stdlib" {
				t.Errorf("kotlin-stdlib version-less purl = %q", p.WithoutVersion())
			}
		}
	}
	if !foundStdlib {
		t.Error("expected to find kotlin-stdlib@2.1.21 component")
	}
}
