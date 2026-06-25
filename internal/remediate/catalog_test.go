package remediate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCatalogRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "gradle"), 0o755); err != nil {
		t.Fatal(err)
	}
	catalog := `[versions]
netty = "4.1.133.Final"

[libraries]
netty-codec = { module = "io.netty:netty-codec", version.ref = "netty" }
netty-handler = { module = "io.netty:netty-handler", version.ref = "netty" }
guava = { group = "com.google.guava", name = "guava", version = "33.0.0" }
junit = "org.junit.jupiter:junit-jupiter:5.10.0"

[plugins]
spotless = { id = "com.diffplug.spotless", version = "6.25.0" }
`
	if err := os.WriteFile(filepath.Join(root, "gradle", "libs.versions.toml"), []byte(catalog), 0o644); err != nil {
		t.Fatal(err)
	}
	// a build file so NewGradleResolver has something to walk too (optional)
	if err := os.WriteFile(filepath.Join(root, "build.gradle.kts"), []byte("plugins {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestCatalogExtract(t *testing.T) {
	t.Parallel()

	g, err := NewGradleResolver(writeCatalogRepo(t))
	if err != nil {
		t.Fatalf("NewGradleResolver: %v", err)
	}
	declared := g.ExtractDeclared()

	got := map[string]DeclaredDependency{}
	for _, d := range declared {
		got[d.Coordinate()] = d
	}

	// netty-codec + netty-handler share version.ref "netty" → collapse to ONE
	// editable entry at the [versions] line (representative = smaller coord).
	if len(declared) != 4 {
		t.Fatalf("got %d declared, want 4 (netty rep, guava, junit, spotless):\n%+v", len(declared), declared)
	}
	if _, ok := got["io.netty:netty-handler"]; ok {
		t.Error("netty-handler should collapse into the shared netty version site, not appear separately")
	}
	netty := got["io.netty:netty-codec"]
	if netty.Version != "4.1.133.Final" || !strings.HasSuffix(netty.File, "libs.versions.toml") {
		t.Errorf("netty rep = %+v, want 4.1.133.Final in libs.versions.toml", netty)
	}
	if d := got["com.google.guava:guava"]; d.Version != "33.0.0" {
		t.Errorf("guava = %+v, want inline 33.0.0", d)
	}
	if d := got["org.junit.jupiter:junit-jupiter"]; d.Version != "5.10.0" {
		t.Errorf("junit shorthand = %+v, want 5.10.0", d)
	}
	// Plugin → gradle-plugin datasource, marker-artifact coordinate.
	plug := got["com.diffplug.spotless:com.diffplug.spotless.gradle.plugin"]
	if plug.Version != "6.25.0" || plug.Datasource != "gradle-plugin" {
		t.Errorf("spotless plugin = %+v, want 6.25.0 via gradle-plugin", plug)
	}

	for _, d := range declared {
		if d.Col+len(d.Version) > len(d.Snippet) || d.Snippet[d.Col:d.Col+len(d.Version)] != d.Version {
			t.Errorf("%s: Col %d does not point at Version %q in %q", d.Coordinate(), d.Col, d.Version, d.Snippet)
		}
	}
}

func TestCatalogApplySharedVersion(t *testing.T) {
	t.Parallel()

	root := writeCatalogRepo(t)
	g, err := NewGradleResolver(root)
	if err != nil {
		t.Fatalf("NewGradleResolver: %v", err)
	}
	var ups []Upgrade
	for _, d := range g.ExtractDeclared() {
		if d.Coordinate() == "io.netty:netty-codec" {
			ups = append(ups, Upgrade{Dep: d, Target: "4.2.15.Final"})
		}
	}
	if len(ups) != 1 {
		t.Fatalf("expected 1 netty upgrade, got %d", len(ups))
	}
	if err := ApplyUpgrades(root, ups); err != nil {
		t.Fatalf("ApplyUpgrades: %v", err)
	}

	out, err := os.ReadFile(filepath.Join(root, "gradle", "libs.versions.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `netty = "4.2.15.Final"`) {
		t.Errorf("the [versions] netty line was not bumped:\n%s", out)
	}
	// The library lines (version.ref) stay untouched.
	if !strings.Contains(string(out), `version.ref = "netty"`) {
		t.Errorf("version.ref lines should be untouched:\n%s", out)
	}
}
