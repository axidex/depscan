package remediate

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// PyPIManager extracts Python dependencies pinned with "==" in requirements
// files. Ranges and other specifiers are skipped (only exact pins are editable).
type PyPIManager struct{}

// Name implements Manager.
func (PyPIManager) Name() string { return "pypi" }

// requirementPin matches `name[extras] == version` at the start of a line.
var requirementPin = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9._!+-]*)`)

// Extract implements Manager: every `name==version` across requirements*.txt.
func (PyPIManager) Extract(root string) ([]DeclaredDependency, error) {
	var out []DeclaredDependency
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !isRequirementsFile(d.Name()) {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		data, rerr := os.ReadFile(path) //nolint:gosec // G304: path comes from walking the user-supplied repo root
		if rerr != nil {
			return fmt.Errorf("remediate: read %s: %w", rel, rerr)
		}
		for i, line := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "-") {
				continue // comment, blank, or an option/include line
			}
			m := requirementPin.FindStringSubmatchIndex(line)
			if m == nil {
				continue
			}
			out = append(out, DeclaredDependency{
				Artifact: line[m[2]:m[3]], Version: line[m[4]:m[5]], Datasource: datasourcePyPI,
				File: rel, Line: i + 1, Col: m[4], Snippet: line,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Coordinate() != out[j].Coordinate() {
			return out[i].Coordinate() < out[j].Coordinate()
		}
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out, nil
}

func isRequirementsFile(name string) bool {
	return strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt")
}
