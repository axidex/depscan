// Package remediate scans a project's build files for declared dependencies and
// applies version upgrades in place — the "manager" and "apply" steps of a
// permissive automated dependency-update flow. It works directly on the
// project (no SBOM, no build-tool execution). Which versions exist and which to
// pick live in internal/datasource and internal/mavenver.
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

// GradleResolver indexes a Gradle project's build files, gradle.properties /
// `val` declarations, and version catalog so dependencies can be enumerated
// (ExtractDeclared) and upgraded in place (ApplyUpgrades).
type GradleResolver struct {
	root            string
	files           []gradleFile
	props           map[string]site // property / val name -> its definition site
	catalogVersions map[string]site // libs.versions.toml [versions] key -> site
	catalogLibs     []catalogEntry  // [libraries] and [plugins] entries
}

type gradleFile struct {
	rel   string // repo-relative path
	lines []string
}

// site is an editable version location: a file line and the column of the
// version token within it.
type site struct {
	file  string
	line  int // 1-based
	col   int // 0-based byte offset of value in the raw line
	value string
	raw   string // the full source line, for display
}

// catalogEntry is a version-catalog library or plugin: a coordinate plus either
// an inline version site or a reference into [versions].
type catalogEntry struct {
	group, artifact string
	datasource      string // "maven" or "gradle-plugin"
	versionRef      string // key into [versions]; "" when inline
	inline          site   // used when versionRef == ""
}

// skipDirs are directories never scanned for build files.
var skipDirs = map[string]bool{
	".git": true, ".gradle": true, "build": true, ".idea": true,
	"node_modules": true, ".venv": true, ".kotlin": true,
}

// valDecl matches a Kotlin/Groovy `val name = "value"` (or `def`/`ext` style)
// version declaration.
var valDecl = regexp.MustCompile(`(?:val|def)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]+)"`)

// NewGradleResolver indexes every Gradle build file, gradle.properties, `val`
// version declaration, and version catalog under root.
func NewGradleResolver(root string) (*GradleResolver, error) {
	g := &GradleResolver{
		root:            root,
		props:           map[string]site{},
		catalogVersions: map[string]site{},
	}

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
		name := d.Name()
		rel := g.relPath(path)
		switch {
		case strings.HasSuffix(name, ".gradle.kts"), strings.HasSuffix(name, ".gradle"):
			data, readErr := os.ReadFile(path) //nolint:gosec // G304: path comes from walking the user-supplied repo root
			if readErr != nil {
				return fmt.Errorf("remediate: read %s: %w", rel, readErr)
			}
			g.files = append(g.files, gradleFile{rel: rel, lines: strings.Split(string(data), "\n")})
		case name == "gradle.properties":
			if perr := g.indexProperties(path, rel); perr != nil {
				return perr
			}
		case name == "libs.versions.toml":
			if cerr := g.indexCatalog(path, rel); cerr != nil {
				return cerr
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(g.files, func(i, j int) bool { return g.files[i].rel < g.files[j].rel })
	g.indexVals() // `val x = "..."` declarations live inside the build files
	return g, nil
}

func (g *GradleResolver) relPath(path string) string {
	if rel, err := filepath.Rel(g.root, path); err == nil {
		return rel
	}
	return path
}

// indexProperties records each gradle.properties key=value as a named version
// site (first declaration wins).
func (g *GradleResolver) indexProperties(path, rel string) error {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path comes from walking the user-supplied repo root
	if err != nil {
		return fmt.Errorf("remediate: read %s: %w", rel, err)
	}
	for i, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if _, exists := g.props[key]; exists || key == "" || value == "" {
			continue
		}
		g.props[key] = site{file: rel, line: i + 1, col: valueColumn(line, value), value: value, raw: line}
	}
	return nil
}

// indexVals records `val name = "..."` declarations from the build files as
// named version sites (only if not already a gradle.properties key).
func (g *GradleResolver) indexVals() {
	for _, f := range g.files {
		for i, line := range f.lines {
			m := valDecl.FindStringSubmatchIndex(line)
			if m == nil {
				continue
			}
			name := line[m[2]:m[3]]
			value := line[m[4]:m[5]]
			if _, exists := g.props[name]; exists {
				continue
			}
			g.props[name] = site{file: f.rel, line: i + 1, col: m[4], value: value, raw: line}
		}
	}
}

// valueColumn returns the 0-based byte offset of value within raw, searching
// after the first '=' so a value also present in the key is not mismatched.
func valueColumn(raw, value string) int {
	eq := strings.Index(raw, "=")
	if eq < 0 {
		eq = -1
	}
	off := strings.Index(raw[eq+1:], value)
	if off < 0 {
		return 0
	}
	return eq + 1 + off
}
