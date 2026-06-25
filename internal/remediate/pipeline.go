package remediate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/axidex/craftnovate/internal/versioning"
)

// Update types, classifying an upgrade relative to the current version (the
// values versioning.UpdateType returns).
const (
	updateMajor = "major"
	updateMinor = "minor"
	updatePatch = "patch"
)

// Upgrade is a declared dependency together with the newer version to bump it
// to. UpdateType classifies the bump ("major"/"minor"/"patch") and drives
// major/minor separation and grouping. Security marks an upgrade chosen to fix a
// known vulnerability (Target is then the minimal fixed version), with VulnIDs
// naming the advisories.
type Upgrade struct {
	Dep        DeclaredDependency
	Target     string
	UpdateType string
	Security   bool
	VulnIDs    []string
}

// VersionLister returns the versions a registry publishes for a coordinate
// (implemented by internal/datasource.Maven and .MavenMetadata).
//
//go:generate mockgen -destination mock_versionlister_test.go -package remediate github.com/axidex/craftnovate/internal/remediate VersionLister
type VersionLister interface {
	Versions(ctx context.Context, group, artifact string) ([]string, error)
}

// Selector chooses the upgrade target for a coordinate given its ecosystem's
// versioning and the registry's candidate versions, or ok=false to skip. It is
// the policy seam: the default picks the newest stable version, while
// internal/config supplies a config-driven selector
// (ignoreUnstable/allowedVersions/ignoreDeps/rules).
type Selector interface {
	Select(v versioning.Versioning, coordinate, current string, candidates []string) (target string, ok bool)
}

// DefaultSelector picks the newest stable version that is an upgrade.
type DefaultSelector struct{}

// Select implements Selector via the ecosystem versioning's SelectUpgrade.
func (DefaultSelector) Select(v versioning.Versioning, _, current string, candidates []string) (string, bool) {
	t := v.SelectUpgrade(current, candidates)
	return t, t != ""
}

// datasourceOf returns a dependency's datasource id, defaulting to "maven".
func datasourceOf(d DeclaredDependency) string {
	if d.Datasource == "" {
		return datasourceMaven
	}
	return d.Datasource
}

// PlanUpgrades queries the matching datasource once per unique (datasource,
// coordinate) (bounded concurrency) and returns an Upgrade for every declared
// occurrence that has a newer stable version. Coordinates whose datasource has
// no registered lister, or whose lookup fails, are collected as errors, not
// fatal.
//
// When separateMajorMinor is set, each occurrence may yield two upgrades — the
// newest non-major (minor/patch) bump and the newest major bump — so they can be
// reviewed in separate pull requests (Renovate's default). Otherwise it yields a
// single upgrade to the newest permitted version.
func PlanUpgrades(ctx context.Context, declared []DeclaredDependency, datasources map[string]VersionLister, sel Selector, concurrency int, separateMajorMinor bool) ([]Upgrade, []error) {
	if sel == nil {
		sel = DefaultSelector{}
	}
	type coordKey struct{ ds, group, artifact string }

	seen := map[coordKey]bool{}
	var coords []coordKey
	for _, d := range declared {
		k := coordKey{datasourceOf(d), d.Group, d.Artifact}
		if !seen[k] {
			seen[k] = true
			coords = append(coords, k)
		}
	}

	if concurrency <= 0 {
		concurrency = 8
	}
	versionsByCoord := make(map[coordKey][]string, len(coords))
	var mu sync.Mutex
	var errs []error

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	for _, k := range coords {
		lister := datasources[k.ds]
		g.Go(func() error {
			if lister == nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s:%s: no datasource %q", k.group, k.artifact, k.ds))
				mu.Unlock()
				return nil
			}
			versions, err := lister.Versions(gctx, k.group, k.artifact)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s:%s: %w", k.group, k.artifact, err))
				return nil
			}
			versionsByCoord[k] = versions
			return nil
		})
	}
	_ = g.Wait()

	var ups []Upgrade
	for _, d := range declared {
		vsn := versioning.Get(datasourceOf(d))
		cands := versionsByCoord[coordKey{datasourceOf(d), d.Group, d.Artifact}]
		for _, base := range chooseTargets(vsn, sel, d, cands, separateMajorMinor) {
			ups = append(ups, Upgrade{
				Dep:        d,
				Target:     vsn.NewValue(d.Version, base), // preserve range shape (npm ^/~)
				UpdateType: vsn.UpdateType(d.Version, base),
			})
		}
	}
	sort.Slice(ups, func(i, j int) bool {
		a, b := ups[i], ups[j]
		if a.Dep.Coordinate() != b.Dep.Coordinate() {
			return a.Dep.Coordinate() < b.Dep.Coordinate()
		}
		if ra, rb := majorRank(a.UpdateType), majorRank(b.UpdateType); ra != rb {
			return ra < rb // non-major before major
		}
		if a.Dep.File != b.Dep.File {
			return a.Dep.File < b.Dep.File
		}
		return a.Dep.Line < b.Dep.Line
	})
	return ups, errs
}

// chooseTargets returns the base version(s) to upgrade d to. With
// separateMajorMinor it picks the newest permitted non-major bump and the newest
// permitted major bump independently (each becomes its own pull request);
// otherwise it picks the single newest permitted version.
func chooseTargets(v versioning.Versioning, sel Selector, d DeclaredDependency, candidates []string, separateMajorMinor bool) []string {
	coord := d.Coordinate()
	if !separateMajorMinor {
		if t, ok := sel.Select(v, coord, d.Version, candidates); ok {
			return []string{t}
		}
		return nil
	}
	nonMajor, major := bucketCandidates(v, d.Version, candidates)
	var out []string
	if t, ok := sel.Select(v, coord, d.Version, nonMajor); ok {
		out = append(out, t)
	}
	if t, ok := sel.Select(v, coord, d.Version, major); ok {
		out = append(out, t)
	}
	return out
}

// bucketCandidates splits candidates into non-major (minor/patch) and major
// upgrades relative to current; non-upgrades are dropped.
func bucketCandidates(v versioning.Versioning, current string, candidates []string) (nonMajor, major []string) {
	for _, c := range candidates {
		switch v.UpdateType(current, c) {
		case updateMajor:
			major = append(major, c)
		case updateMinor, updatePatch:
			nonMajor = append(nonMajor, c)
		}
	}
	return nonMajor, major
}

func majorRank(updateType string) int {
	if updateType == updateMajor {
		return 1
	}
	return 0
}

// DedupeBySite keeps a single upgrade per edit site — the newest target — so the
// in-place --write path never rewrites one location twice (separateMajorMinor
// can produce a non-major and a major upgrade for the same site). Pull requests
// don't need this: each branch applies only its own group's edits.
func DedupeBySite(ups []Upgrade) []Upgrade {
	type siteKey struct {
		file string
		line int
		col  int
	}
	best := map[siteKey]Upgrade{}
	var order []siteKey
	for _, u := range ups {
		k := siteKey{u.Dep.File, u.Dep.Line, u.Dep.Col}
		cur, ok := best[k]
		if !ok {
			best[k] = u
			order = append(order, k)
			continue
		}
		if versioning.Get(datasourceOf(u.Dep)).Compare(u.Target, cur.Target) > 0 {
			best[k] = u
		}
	}
	out := make([]Upgrade, 0, len(order))
	for _, k := range order {
		out = append(out, best[k])
	}
	return out
}

// ApplyUpgrades rewrites each affected build file in place, replacing the old
// version with the target at the recorded column. Edits on the same line are
// applied right-to-left so earlier columns stay valid. It refuses an edit whose
// recorded column no longer holds the expected version (the file changed since
// extraction), rather than corrupt the file.
func ApplyUpgrades(root string, ups []Upgrade) error {
	byFile := map[string][]Upgrade{}
	for _, u := range ups {
		byFile[u.Dep.File] = append(byFile[u.Dep.File], u)
	}

	for rel, list := range byFile {
		path := filepath.Join(root, rel)
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("remediate: stat %s: %w", rel, err)
		}
		data, err := os.ReadFile(path) //nolint:gosec // G304: path is a build file under the user-supplied repo root
		if err != nil {
			return fmt.Errorf("remediate: read %s: %w", rel, err)
		}
		lines := strings.Split(string(data), "\n")

		byLine := map[int][]Upgrade{}
		for _, u := range list {
			byLine[u.Dep.Line] = append(byLine[u.Dep.Line], u)
		}
		for ln, group := range byLine {
			if ln < 1 || ln > len(lines) {
				return fmt.Errorf("remediate: %s:%d out of range", rel, ln)
			}
			sort.Slice(group, func(i, j int) bool { return group[i].Dep.Col > group[j].Dep.Col })
			line := lines[ln-1]
			for _, u := range group {
				c, old := u.Dep.Col, u.Dep.Version
				if c+len(old) > len(line) || line[c:c+len(old)] != old {
					return fmt.Errorf("remediate: %s:%d version %q not at expected column (file changed since scan)", rel, ln, old)
				}
				line = line[:c] + u.Target + line[c+len(old):]
			}
			lines[ln-1] = line
		}

		//nolint:gosec // G703: path is a build file under the user-supplied repo root
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), info.Mode().Perm()); err != nil {
			return fmt.Errorf("remediate: write %s: %w", rel, err)
		}
	}
	return nil
}
