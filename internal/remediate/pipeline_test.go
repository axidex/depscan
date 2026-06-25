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

	ups, errs := PlanUpgrades(context.Background(), declared, map[string]VersionLister{"maven": lister}, DefaultSelector{}, 4)
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
