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

// NPMManager extracts npm dependencies from package.json. It handles caret,
// tilde, and exact constraints (the common cases); complex ranges ("*",
// ">=1 <2", "workspace:*", git/file URLs) are skipped as non-editable.
type NPMManager struct{}

// Name implements Manager.
func (NPMManager) Name() string { return "npm" }

var (
	// npmDepsSection opens one of the dependency objects.
	npmDepsSection = regexp.MustCompile(`"(?:dependencies|devDependencies|peerDependencies|optionalDependencies)"\s*:\s*\{`)
	// npmEntry matches `"name": "^1.2.3"` with a caret/tilde/exact semver value.
	npmEntry = regexp.MustCompile(`"([^"]+)"\s*:\s*"((?:\^|~)?\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?)"`)
)

// Extract implements Manager: simple-ranged dependencies across all package.json.
func (NPMManager) Extract(root string) ([]DeclaredDependency, error) {
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
		if d.Name() != "package.json" {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		data, rerr := os.ReadFile(path) //nolint:gosec // G304: path comes from walking the user-supplied repo root
		if rerr != nil {
			return fmt.Errorf("remediate: read %s: %w", rel, rerr)
		}
		out = append(out, extractPackageJSON(rel, string(data))...)
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

// extractPackageJSON scans a package.json line by line, emitting an entry for
// every simple-ranged dependency inside a *dependencies object.
func extractPackageJSON(rel, content string) []DeclaredDependency {
	var out []DeclaredDependency
	inDeps := false
	for i, line := range strings.Split(content, "\n") {
		if !inDeps {
			if npmDepsSection.MatchString(line) {
				inDeps = true
			}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "}") {
			inDeps = false
			continue
		}
		m := npmEntry.FindStringSubmatchIndex(line)
		if m == nil {
			continue
		}
		out = append(out, DeclaredDependency{
			Artifact: line[m[2]:m[3]], Version: line[m[4]:m[5]], Datasource: datasourceNPM,
			File: rel, Line: i + 1, Col: m[4], Snippet: line,
		})
	}
	return out
}
