package remediate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const samplePackageJSON = `{
  "name": "app",
  "version": "1.0.0",
  "main": "index.js",
  "dependencies": {
    "lodash": "^4.17.0",
    "express": "~4.18.0",
    "left-pad": "1.3.0",
    "star": "*"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}
`

func TestNPMExtract(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(samplePackageJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	declared, err := NPMManager{}.Extract(root)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got := map[string]DeclaredDependency{}
	for _, d := range declared {
		got[d.Coordinate()] = d
	}
	// name/version/main are not in a deps object; "star":"*" is a skipped range.
	if len(declared) != 4 {
		t.Fatalf("got %d declared, want 4 (lodash, express, left-pad, jest):\n%+v", len(declared), declared)
	}
	if got["lodash"].Version != "^4.17.0" || got["jest"].Version != "^29.0.0" ||
		got["express"].Version != "~4.18.0" || got["left-pad"].Version != "1.3.0" {
		t.Errorf("versions wrong: %+v", got)
	}
	for _, d := range declared {
		if d.Datasource != "npm" {
			t.Errorf("%s datasource = %q, want npm", d.Coordinate(), d.Datasource)
		}
		if d.Snippet[d.Col:d.Col+len(d.Version)] != d.Version {
			t.Errorf("%s: Col does not point at version in %q", d.Coordinate(), d.Snippet)
		}
	}
}

// fakeNPM lists versions for npm coordinates.
type fakeNPM map[string][]string

func (f fakeNPM) Versions(_ context.Context, _, artifact string) ([]string, error) {
	return f[artifact], nil
}

// TestNPMRangePreservedThroughPlanAndApply checks the whole npm path: a "^"
// range is bumped to a newer stable version while keeping the caret.
func TestNPMRangePreservedThroughPlanAndApply(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(samplePackageJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	declared, err := NPMManager{}.Extract(root)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	ds := map[string]VersionLister{"npm": fakeNPM{
		"lodash":   {"4.17.0", "4.17.21", "5.0.0-rc.1"},
		"express":  {"4.18.0"},           // already latest
		"left-pad": {"1.3.0"},            // already latest
		"jest":     {"29.0.0", "29.7.0"}, // minor bump
	}}
	ups, errs := PlanUpgrades(context.Background(), declared, ds, DefaultSelector{}, 4, false)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}

	byCoord := map[string]Upgrade{}
	for _, u := range ups {
		byCoord[u.Dep.Coordinate()] = u
	}
	// lodash ^4.17.0 → ^4.17.21 (caret preserved, rc skipped); jest ^29.0.0 → ^29.7.0.
	if byCoord["lodash"].Target != "^4.17.21" {
		t.Errorf("lodash target = %q, want ^4.17.21", byCoord["lodash"].Target)
	}
	if byCoord["jest"].Target != "^29.7.0" {
		t.Errorf("jest target = %q, want ^29.7.0", byCoord["jest"].Target)
	}
	if _, ok := byCoord["express"]; ok {
		t.Error("express should be up to date")
	}

	if err := ApplyUpgrades(root, ups); err != nil {
		t.Fatalf("ApplyUpgrades: %v", err)
	}
	out, _ := os.ReadFile(filepath.Join(root, "package.json"))
	if !strings.Contains(string(out), `"lodash": "^4.17.21"`) {
		t.Errorf("lodash not bumped with caret preserved:\n%s", out)
	}
	if !strings.Contains(string(out), `"jest": "^29.7.0"`) {
		t.Errorf("jest not bumped:\n%s", out)
	}
}
