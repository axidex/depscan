package remediate

import "testing"

func TestExtractDeclared(t *testing.T) {
	t.Parallel()

	g, err := NewGradleResolver(writeRepo(t))
	if err != nil {
		t.Fatalf("NewGradleResolver: %v", err)
	}

	declared := g.ExtractDeclared()

	got := map[string]DeclaredDependency{}
	for _, d := range declared {
		got[d.Coordinate()] = d
	}
	// Two inline literals (bcpkix, okio) plus two property-ref resolutions:
	// com.example:lib via $libVersion and quarkus-bom via ${quarkusPlatformVersion},
	// both editable at their gradle.properties definition. quarkus-rest has no
	// version; the build/ decoy is skipped.
	if len(declared) != 4 {
		t.Fatalf("got %d declared deps, want 4:\n%+v", len(declared), declared)
	}
	if d := got["org.bouncycastle:bcpkix-jdk18on"]; d.Version != "1.79" || d.File != "build.gradle.kts" {
		t.Errorf("bcpkix = %+v, want 1.79 in build.gradle.kts", d)
	}
	if d := got["com.squareup.okio:okio"]; d.Version != "3.12.0" {
		t.Errorf("okio = %+v, want 3.12.0", d)
	}
	// Property refs resolve to the gradle.properties definition site.
	if d := got["com.example:lib"]; d.Version != "1.0.0" || d.File != "gradle.properties" {
		t.Errorf("com.example:lib = %+v, want 1.0.0 in gradle.properties", d)
	}
	if d := got["io.quarkus.platform:quarkus-bom"]; d.Version != "3.36.0" || d.File != "gradle.properties" {
		t.Errorf("quarkus-bom = %+v, want 3.36.0 in gradle.properties", d)
	}

	// Col must point exactly at Version within the snippet (apply correctness).
	for _, d := range declared {
		if d.Col+len(d.Version) > len(d.Snippet) || d.Snippet[d.Col:d.Col+len(d.Version)] != d.Version {
			t.Errorf("%s: Col %d does not point at Version %q in %q", d.Coordinate(), d.Col, d.Version, d.Snippet)
		}
	}
}
