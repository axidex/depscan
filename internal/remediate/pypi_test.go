package remediate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPyPIExtractAndApply(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	req := `# app deps
requests==2.32.5
urllib3 == 2.6.3
flask[async]==3.0.0
black==26.1.0  ; python_version >= "3.9"
-r other.txt
not-a-pin>=1.0
`
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte(req), 0o644); err != nil {
		t.Fatal(err)
	}

	declared, err := PyPIManager{}.Extract(root)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got := map[string]DeclaredDependency{}
	for _, d := range declared {
		got[d.Coordinate()] = d
		if d.Datasource != "pypi" {
			t.Errorf("%s datasource = %q, want pypi", d.Coordinate(), d.Datasource)
		}
	}
	// Four exact pins; the ">=" line and the "-r" include are skipped.
	if len(declared) != 4 {
		t.Fatalf("got %d declared, want 4:\n%+v", len(declared), declared)
	}
	if got["requests"].Version != "2.32.5" || got["urllib3"].Version != "2.6.3" ||
		got["flask"].Version != "3.0.0" || got["black"].Version != "26.1.0" {
		t.Errorf("versions wrong: %+v", got)
	}
	// Coordinate is the bare package name (no group), and Col points at Version.
	for _, d := range declared {
		if strings.Contains(d.Coordinate(), ":") {
			t.Errorf("pypi coordinate %q should have no ':'", d.Coordinate())
		}
		if d.Snippet[d.Col:d.Col+len(d.Version)] != d.Version {
			t.Errorf("%s: Col does not point at version in %q", d.Coordinate(), d.Snippet)
		}
	}

	// Apply a bump and verify the in-place edit, leaving extras/markers intact.
	ups := []Upgrade{{Dep: got["urllib3"], Target: "2.7.0"}, {Dep: got["flask"], Target: "3.1.0"}}
	if err := ApplyUpgrades(root, ups); err != nil {
		t.Fatalf("ApplyUpgrades: %v", err)
	}
	out, _ := os.ReadFile(filepath.Join(root, "requirements.txt"))
	if !strings.Contains(string(out), "urllib3 == 2.7.0") {
		t.Errorf("urllib3 not bumped:\n%s", out)
	}
	if !strings.Contains(string(out), "flask[async]==3.1.0") {
		t.Errorf("flask not bumped (extras must be preserved):\n%s", out)
	}
}
