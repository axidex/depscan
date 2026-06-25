package remediate

import (
	"os"
	"regexp"
	"strings"
)

// Minimal line-oriented parser for a Gradle version catalog (libs.versions.toml).
// We do not need a full TOML parser: catalogs are regular, and we only extract
// coordinates + the editable version site (inline value or a [versions] ref).
var (
	tomlSection  = regexp.MustCompile(`^\s*\[([A-Za-z0-9_.\-]+)\]`)
	tomlKeyValue = regexp.MustCompile(`^\s*([A-Za-z0-9_.\-]+)\s*=\s*"([^"]+)"\s*$`)
	tomlModule   = regexp.MustCompile(`module\s*=\s*"([^"]+)"`)
	tomlGroup    = regexp.MustCompile(`group\s*=\s*"([^"]+)"`)
	tomlName     = regexp.MustCompile(`name\s*=\s*"([^"]+)"`)
	tomlID       = regexp.MustCompile(`id\s*=\s*"([^"]+)"`)
	tomlVerRef   = regexp.MustCompile(`version\.ref\s*=\s*"([^"]+)"`)
	tomlVerLit   = regexp.MustCompile(`(^|[^.])version\s*=\s*"([^"]+)"`) // not version.ref
)

// indexCatalog parses a libs.versions.toml into catalogVersions (the [versions]
// table, editable sites) and catalogLibs ([libraries]/[plugins] coordinates).
func (g *GradleResolver) indexCatalog(path, rel string) error {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path comes from walking the user-supplied repo root
	if err != nil {
		return err
	}
	section := ""
	for i, line := range strings.Split(string(data), "\n") {
		if m := tomlSection.FindStringSubmatch(line); m != nil {
			section = m[1]
			continue
		}
		switch section {
		case "versions":
			if m := tomlKeyValue.FindStringSubmatchIndex(line); m != nil {
				key := line[m[2]:m[3]]
				value := line[m[4]:m[5]]
				g.catalogVersions[key] = site{file: rel, line: i + 1, col: m[4], value: value, raw: line}
			}
		case "libraries":
			g.parseCatalogLib(line, i+1, rel)
		case "plugins":
			g.parseCatalogPlugin(line, i+1, rel)
		}
	}
	return nil
}

func (g *GradleResolver) parseCatalogLib(line string, lineNo int, rel string) {
	// Shorthand: name = "group:artifact:version"
	if m := tomlKeyValue.FindStringSubmatchIndex(line); m != nil {
		value := line[m[4]:m[5]]
		if parts := strings.Split(value, ":"); len(parts) == 3 {
			g.catalogLibs = append(g.catalogLibs, catalogEntry{
				group: parts[0], artifact: parts[1], datasource: datasourceMaven,
				inline: site{file: rel, line: lineNo, col: m[4] + len(parts[0]) + len(parts[1]) + 2, value: parts[2], raw: line},
			})
		}
		return
	}
	group, artifact, ok := catalogModule(line)
	if !ok {
		return
	}
	g.catalogLibs = append(g.catalogLibs, g.entryWithVersion(line, lineNo, rel, group, artifact, datasourceMaven))
}

func (g *GradleResolver) parseCatalogPlugin(line string, lineNo int, rel string) {
	m := tomlID.FindStringSubmatch(line)
	if m == nil {
		return
	}
	id := m[1]
	g.catalogLibs = append(g.catalogLibs, g.entryWithVersion(line, lineNo, rel, id, id+".gradle.plugin", datasourceGradlePlugin))
}

// catalogModule extracts a coordinate from module="g:a" or group=".." name="..".
func catalogModule(line string) (group, artifact string, ok bool) {
	if m := tomlModule.FindStringSubmatch(line); m != nil {
		if parts := strings.SplitN(m[1], ":", 2); len(parts) == 2 {
			return parts[0], parts[1], true
		}
	}
	gm, nm := tomlGroup.FindStringSubmatch(line), tomlName.FindStringSubmatch(line)
	if gm != nil && nm != nil {
		return gm[1], nm[1], true
	}
	return "", "", false
}

// entryWithVersion fills a catalogEntry's version from a version.ref or an inline
// version on the same line.
func (g *GradleResolver) entryWithVersion(line string, lineNo int, rel, group, artifact, ds string) catalogEntry {
	e := catalogEntry{group: group, artifact: artifact, datasource: ds}
	if m := tomlVerRef.FindStringSubmatch(line); m != nil {
		e.versionRef = m[1]
		return e
	}
	if m := tomlVerLit.FindStringSubmatchIndex(line); m != nil {
		// group 2 holds the version literal; m[4]:m[5] is its span.
		e.inline = site{file: rel, line: lineNo, col: m[4], value: line[m[4]:m[5]], raw: line}
	}
	return e
}
