package sbom_test

import (
	"os"
	"strings"
	"testing"

	"github.com/axidex/depscan/internal/sbom"
)

func TestParse_Fixture(t *testing.T) {
	t.Parallel()

	f, err := os.Open("testdata/bom.json")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	components, skipped, err := sbom.Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// One component (no-purl-lib) has no purl and must be skipped/counted.
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}

	// Expect: demo-app (metadata is not in components[]), lodash, @babel/core,
	// nested requests, guava. metadata.component is not part of components[].
	byPURL := map[string]sbom.Component{}
	for _, c := range components {
		byPURL[c.PURL] = c
	}

	want := []string{
		"pkg:npm/lodash@4.17.20",
		"pkg:npm/%40babel/core@7.0.0",
		"pkg:pypi/requests@2.20.0", // nested component is flattened
		"pkg:maven/com.google.guava/guava@30.0-jre",
	}
	for _, w := range want {
		if _, ok := byPURL[w]; !ok {
			t.Errorf("missing component %q; got %d components", w, len(components))
		}
	}
	if len(components) != len(want) {
		t.Errorf("len(components) = %d, want %d", len(components), len(want))
	}

	lodash := byPURL["pkg:npm/lodash@4.17.20"]
	if lodash.Name != "lodash" || lodash.Version != "4.17.20" || lodash.BOMRef == "" {
		t.Errorf("lodash parsed incorrectly: %+v", lodash)
	}
}

func TestParse_Empty(t *testing.T) {
	t.Parallel()

	// Valid CycloneDX JSON with no components.
	in := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`
	components, skipped, err := sbom.Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(components) != 0 || skipped != 0 {
		t.Errorf("got %d components / %d skipped, want 0/0", len(components), skipped)
	}
}

func TestParse_Invalid(t *testing.T) {
	t.Parallel()

	if _, _, err := sbom.Parse(strings.NewReader("{not json")); err == nil {
		t.Fatal("Parse(invalid) = nil error, want error")
	}
}
