package worker_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/axidex/depscan/internal/config"
	"github.com/axidex/depscan/internal/datasource"
	"github.com/axidex/depscan/internal/remediate"
	"github.com/axidex/depscan/internal/worker"
)

// fakeMavenCentral serves the Maven Central solrsearch response for the given
// per-artifact versions, parsing the artifact out of the `q=g:.. AND a:..` query.
func fakeMavenCentral(t *testing.T, versions map[string][]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		i := strings.LastIndex(q, "a:")
		if i < 0 {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		artifact := strings.TrimSpace(q[i+2:])
		vs := versions[artifact]
		var docs strings.Builder
		for j, v := range vs {
			if j > 0 {
				docs.WriteByte(',')
			}
			docs.WriteString(`{"v":"` + v + `"}`)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":{"numFound":` + itoa(len(vs)) + `,"docs":[` + docs.String() + `]}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestPipelineE2E exercises the whole manifest-scan flow end to end against a
// fake Maven Central and a config file: extract → config selector → datasource →
// plan → group → apply, asserting both the applied edits and the config effects
// (ignoreDeps skip, allowedVersions cap, ignoreUnstable milestone rejection).
func TestPipelineE2E(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	build := `dependencies {
    implementation("org.bouncycastle:bcpkix-jdk18on:1.79")
    implementation("com.squareup.okio:okio:3.10.2")
    implementation("org.junit.jupiter:junit-jupiter:5.10.0")
    implementation("com.example:internal-lib:1.0.0")
}
`
	mustWrite(t, filepath.Join(root, "build.gradle.kts"), build)
	cfgJSON := `{
        "ignoreDeps": ["com.example:internal-lib"],
        "packageRules": [
            {"matchPackagePrefixes": ["org.junit"], "allowedVersions": "<5.13"}
        ]
    }`
	mustWrite(t, filepath.Join(root, "depscan.json"), cfgJSON)

	srv := fakeMavenCentral(t, map[string][]string{
		"bcpkix-jdk18on": {"1.80", "1.79", "1.78.1"},
		"okio":           {"3.12.0", "3.11.0", "3.10.2"},
		"junit-jupiter":  {"5.13.0-M3", "5.12.2", "5.10.0"},
		"internal-lib":   {"2.0.0", "1.0.0"},
	})

	g, err := remediate.NewGradleResolver(root)
	if err != nil {
		t.Fatalf("NewGradleResolver: %v", err)
	}
	declared := g.ExtractDeclared()
	if len(declared) != 4 {
		t.Fatalf("declared = %d, want 4", len(declared))
	}

	cfg, err := config.Load(root)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	sel := config.NewSelector(cfg, "gradle")
	ds := datasource.NewMaven(datasource.WithHTTPClient(srv.Client()), datasource.WithSearchURL(srv.URL))
	datasources := map[string]remediate.VersionLister{"maven": ds}

	ups, errs := remediate.PlanUpgrades(context.Background(), declared, datasources, sel, 4)
	if len(errs) != 0 {
		t.Fatalf("lookup errors: %v", errs)
	}

	// Expected: bcpkix→1.80, okio→3.12.0, junit→5.12.2 (M3 rejected + <5.13 cap);
	// internal-lib skipped by ignoreDeps despite a 2.0.0 being available.
	got := map[string]string{}
	for _, u := range ups {
		got[u.Dep.Coordinate()] = u.Target
	}
	want := map[string]string{
		"org.bouncycastle:bcpkix-jdk18on": "1.80",
		"com.squareup.okio:okio":          "3.12.0",
		"org.junit.jupiter:junit-jupiter": "5.12.2",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d upgrades %v, want %d %v", len(got), got, len(want), want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s → %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["com.example:internal-lib"]; ok {
		t.Error("internal-lib must be skipped (ignoreDeps)")
	}

	// Grouping: one PR per coordinate.
	if groups := worker.GroupUpgrades(ups); len(groups) != 3 {
		t.Errorf("groups = %d, want 3", len(groups))
	}

	// Apply and verify the file.
	if err := remediate.ApplyUpgrades(root, ups); err != nil {
		t.Fatalf("ApplyUpgrades: %v", err)
	}
	out := mustRead(t, filepath.Join(root, "build.gradle.kts"))
	for _, want := range []string{
		`"org.bouncycastle:bcpkix-jdk18on:1.80"`,
		`"com.squareup.okio:okio:3.12.0"`,
		`"org.junit.jupiter:junit-jupiter:5.12.2"`,
		`"com.example:internal-lib:1.0.0"`, // unchanged
	} {
		if !strings.Contains(out, want) {
			t.Errorf("build file missing %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "5.13.0-M3") {
		t.Error("milestone version must not be applied")
	}
}

// TestCatalogPipelineE2E runs the full pipeline against a version catalog: a
// shared version.ref must collapse to one editable [versions] entry, be looked
// up via the representative coordinate, and apply at the [versions] line.
func TestCatalogPipelineE2E(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "build.gradle.kts"), "plugins {}\n")
	if err := os.MkdirAll(filepath.Join(root, "gradle"), 0o755); err != nil {
		t.Fatal(err)
	}
	catalog := `[versions]
netty = "4.1.133.Final"

[libraries]
netty-codec = { module = "io.netty:netty-codec", version.ref = "netty" }
netty-handler = { module = "io.netty:netty-handler", version.ref = "netty" }
`
	mustWrite(t, filepath.Join(root, "gradle", "libs.versions.toml"), catalog)

	srv := fakeMavenCentral(t, map[string][]string{
		"netty-codec": {"4.2.15.Final", "4.1.133.Final"},
	})

	g, err := remediate.NewGradleResolver(root)
	if err != nil {
		t.Fatalf("NewGradleResolver: %v", err)
	}
	declared := g.ExtractDeclared()
	if len(declared) != 1 {
		t.Fatalf("declared = %d, want 1 (shared netty version site)", len(declared))
	}

	cfg, err := config.Load(root)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	ds := datasource.NewMaven(datasource.WithHTTPClient(srv.Client()), datasource.WithSearchURL(srv.URL))
	datasources := map[string]remediate.VersionLister{"maven": ds}

	ups, errs := remediate.PlanUpgrades(context.Background(), declared, datasources, config.NewSelector(cfg, "gradle"), 4)
	if len(errs) != 0 {
		t.Fatalf("lookup errors: %v", errs)
	}
	if len(ups) != 1 || ups[0].Target != "4.2.15.Final" {
		t.Fatalf("ups = %+v, want one netty → 4.2.15.Final", ups)
	}

	if err := remediate.ApplyUpgrades(root, ups); err != nil {
		t.Fatalf("ApplyUpgrades: %v", err)
	}
	out := mustRead(t, filepath.Join(root, "gradle", "libs.versions.toml"))
	if !strings.Contains(out, `netty = "4.2.15.Final"`) {
		t.Errorf("[versions] netty not bumped:\n%s", out)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
