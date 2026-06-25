package remediate

import (
	"regexp"
	"sort"
)

// Datasource identifiers a coordinate is looked up against.
const (
	datasourceMaven        = "maven"
	datasourceGradlePlugin = "gradle-plugin"
	datasourcePyPI         = "pypi"
	datasourceNPM          = "npm"
)

// DeclaredDependency is one editable version site for a coordinate, located
// precisely (file/line/col) so an upgrade applies as a minimal in-place edit.
type DeclaredDependency struct {
	Group      string
	Artifact   string
	Version    string
	Datasource string // "maven" | "gradle-plugin"
	File       string // repo-relative path
	Line       int    // 1-based
	Col        int    // 0-based byte offset of Version in the raw line
	Snippet    string // the full source line
}

// Coordinate returns "group:artifact" for Maven, or just the name for flat
// ecosystems (PyPI) where Group is empty.
func (d DeclaredDependency) Coordinate() string {
	if d.Group == "" {
		return d.Artifact
	}
	return d.Group + ":" + d.Artifact
}

// gavLiteral matches an inline "group:artifact:version" literal; the version
// class excludes '$', so interpolations are handled separately.
var gavLiteral = regexp.MustCompile(`["']([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+)["':@]`)

// gavInterpolated matches "group:artifact:$prop" or "${prop}".
var gavInterpolated = regexp.MustCompile(`["']([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?["']`)

// rawRef is a coordinate paired with the editable version site it resolves to.
type rawRef struct {
	group, artifact, datasource string
	s                           site
}

// ExtractDeclared enumerates every editable dependency version across the build
// files and version catalog: inline literals, property/`val` interpolations, and
// catalog libraries/plugins. References that share one version site (a property
// or a [versions] key used by several deps) collapse to a single editable entry
// (one edit, one PR) with a deterministic representative coordinate.
func (g *GradleResolver) ExtractDeclared() []DeclaredDependency {
	var refs []rawRef
	for _, f := range g.files {
		for i, line := range f.lines {
			refs = append(refs, literalRefs(f.rel, i+1, line)...)
			refs = append(refs, g.interpolatedRefs(i+1, line)...)
		}
	}
	refs = append(refs, g.catalogRefs()...)
	return collapseRefs(refs)
}

func literalRefs(rel string, lineNo int, line string) []rawRef {
	var out []rawRef
	for _, m := range gavLiteral.FindAllStringSubmatchIndex(line, -1) {
		out = append(out, rawRef{
			group: line[m[2]:m[3]], artifact: line[m[4]:m[5]], datasource: datasourceMaven,
			s: site{file: rel, line: lineNo, col: m[6], value: line[m[6]:m[7]], raw: line},
		})
	}
	return out
}

func (g *GradleResolver) interpolatedRefs(lineNo int, line string) []rawRef {
	_ = lineNo
	var out []rawRef
	for _, m := range gavInterpolated.FindAllStringSubmatch(line, -1) {
		s, ok := g.props[m[3]]
		if !ok {
			continue
		}
		out = append(out, rawRef{group: m[1], artifact: m[2], datasource: datasourceMaven, s: s})
	}
	return out
}

func (g *GradleResolver) catalogRefs() []rawRef {
	var out []rawRef
	for _, e := range g.catalogLibs {
		s := e.inline
		if e.versionRef != "" {
			v, ok := g.catalogVersions[e.versionRef]
			if !ok {
				continue
			}
			s = v
		}
		if s.file == "" {
			continue // no resolvable version site
		}
		out = append(out, rawRef{group: e.group, artifact: e.artifact, datasource: e.datasource, s: s})
	}
	return out
}

// collapseRefs deduplicates refs sharing an edit site into one
// DeclaredDependency, choosing the lexicographically-smallest coordinate as the
// representative for the datasource lookup (a shared version variable governs a
// family that releases in lockstep, so the representative's target fits all).
func collapseRefs(refs []rawRef) []DeclaredDependency {
	type key struct {
		file string
		line int
		col  int
	}
	bySite := map[key]rawRef{}
	for _, r := range refs {
		k := key{r.s.file, r.s.line, r.s.col}
		if cur, ok := bySite[k]; !ok || coordOf(r) < coordOf(cur) {
			bySite[k] = r
		}
	}

	out := make([]DeclaredDependency, 0, len(bySite))
	for _, r := range bySite {
		out = append(out, DeclaredDependency{
			Group: r.group, Artifact: r.artifact, Version: r.s.value, Datasource: r.datasource,
			File: r.s.file, Line: r.s.line, Col: r.s.col, Snippet: r.s.raw,
		})
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
	return out
}

func coordOf(r rawRef) string { return r.group + ":" + r.artifact }
