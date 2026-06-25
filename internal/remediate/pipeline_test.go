package remediate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/mock/gomock"
)

func TestPlanAndApplyUpgrades(t *testing.T) {
	t.Parallel()

	root := writeRepo(t)
	g, err := NewGradleResolver(root)
	if err != nil {
		t.Fatalf("NewGradleResolver: %v", err)
	}
	// writeRepo has bcpkix & okio (literals) plus com.example:lib ($libVersion)
	// and quarkus-bom (${quarkusPlatformVersion}) via property-ref extraction.
	declared := g.ExtractDeclared()

	ctrl := gomock.NewController(t)
	lister := NewMockVersionLister(ctrl)
	lister.EXPECT().Versions(gomock.Any(), "org.bouncycastle", "bcpkix-jdk18on").
		Return([]string{"1.84", "1.80", "1.79", "1.85-beta"}, nil)
	lister.EXPECT().Versions(gomock.Any(), "com.squareup.okio", "okio").
		Return([]string{"3.12.0", "3.11.0"}, nil) // already latest stable
	lister.EXPECT().Versions(gomock.Any(), "com.example", "lib").
		Return([]string{"1.0.0"}, nil) // already current
	lister.EXPECT().Versions(gomock.Any(), "io.quarkus.platform", "quarkus-bom").
		Return([]string{"3.36.0"}, nil) // already current

	ups, errs := PlanUpgrades(context.Background(), declared, map[string]VersionLister{"maven": lister}, DefaultSelector{}, 4, false)
	if len(errs) != 0 {
		t.Fatalf("unexpected lookup errors: %v", errs)
	}
	// Only bcpkix has a newer stable (1.84); the 1.85-beta is rejected.
	if len(ups) != 1 {
		t.Fatalf("got %d upgrades, want 1:\n%+v", len(ups), ups)
	}
	if ups[0].Dep.Coordinate() != "org.bouncycastle:bcpkix-jdk18on" || ups[0].Target != "1.84" {
		t.Fatalf("upgrade = %+v, want bcpkix -> 1.84", ups[0])
	}

	if err := ApplyUpgrades(root, ups); err != nil {
		t.Fatalf("ApplyUpgrades: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "build.gradle.kts"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"org.bouncycastle:bcpkix-jdk18on:1.84"`) {
		t.Errorf("build.gradle.kts not updated to 1.84:\n%s", got)
	}
	if strings.Contains(string(got), `bcpkix-jdk18on:1.79"`) {
		t.Errorf("old bcpkix version 1.79 still present")
	}
	if !strings.Contains(string(got), `"com.squareup.okio:okio:3.12.0"`) {
		t.Errorf("okio literal was altered")
	}
}

// fakeLister serves a fixed version list per "group:artifact".
type fakeLister map[string][]string

func (f fakeLister) Versions(_ context.Context, group, artifact string) ([]string, error) {
	return f[group+":"+artifact], nil
}

func TestPlanUpgrades_SeparateMajorMinor(t *testing.T) {
	t.Parallel()

	declared := []DeclaredDependency{
		{Group: "io.x", Artifact: "lib", Version: "1.2.0", Datasource: "maven", File: "b.gradle", Line: 1},
	}
	ds := map[string]VersionLister{"maven": fakeLister{
		"io.x:lib": {"1.2.0", "1.3.0", "1.5.0", "2.0.0", "2.1.0"},
	}}

	ups, errs := PlanUpgrades(context.Background(), declared, ds, DefaultSelector{}, 4, true)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	if len(ups) != 2 {
		t.Fatalf("got %d upgrades, want 2 (non-major + major):\n%+v", len(ups), ups)
	}
	byType := map[string]string{}
	for _, u := range ups {
		byType[u.UpdateType] = u.Target
	}
	if byType["minor"] != "1.5.0" {
		t.Errorf("non-major target = %q, want 1.5.0 (newest within major 1)", byType["minor"])
	}
	if byType["major"] != "2.1.0" {
		t.Errorf("major target = %q, want 2.1.0 (newest major)", byType["major"])
	}

	// Without separation, only the single newest is chosen.
	one, _ := PlanUpgrades(context.Background(), declared, ds, DefaultSelector{}, 4, false)
	if len(one) != 1 || one[0].Target != "2.1.0" {
		t.Fatalf("single mode = %+v, want one 2.1.0", one)
	}
}

func TestDedupeBySite(t *testing.T) {
	t.Parallel()

	site := DeclaredDependency{Group: "io.x", Artifact: "lib", Version: "1.2.0", Datasource: "maven", File: "b.gradle", Line: 1, Col: 5}
	ups := []Upgrade{
		{Dep: site, Target: "1.5.0", UpdateType: "minor"},
		{Dep: site, Target: "2.1.0", UpdateType: "major"},
	}
	got := DedupeBySite(ups)
	if len(got) != 1 || got[0].Target != "2.1.0" {
		t.Fatalf("DedupeBySite = %+v, want one 2.1.0 (newest)", got)
	}
}
