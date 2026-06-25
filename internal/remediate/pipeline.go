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

	"github.com/axidex/depscan/internal/versioning"
)

// Upgrade is a declared dependency together with the newer version to bump it
// to. Security marks an upgrade chosen to fix a known vulnerability (Target is
// then the minimal fixed version), with VulnIDs naming the advisories.
type Upgrade struct {
	Dep      DeclaredDependency
	Target   string
	Security bool
	VulnIDs  []string
}

// VersionLister returns the versions a registry publishes for a coordinate
// (implemented by internal/datasource.Maven and .MavenMetadata).
//
//go:generate mockgen -destination mock_versionlister_test.go -package remediate github.com/axidex/depscan/internal/remediate VersionLister
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
func PlanUpgrades(ctx context.Context, declared []DeclaredDependency, datasources map[string]VersionLister, sel Selector, concurrency int) ([]Upgrade, []error) {
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
		chosen, ok := sel.Select(vsn, d.Coordinate(), d.Version, versionsByCoord[coordKey{datasourceOf(d), d.Group, d.Artifact}])
		if !ok {
			continue
		}
		// Render the manifest value to write, preserving range shape (npm ^/~).
		ups = append(ups, Upgrade{Dep: d, Target: vsn.NewValue(d.Version, chosen)})
	}
	sort.Slice(ups, func(i, j int) bool {
		if ups[i].Dep.Coordinate() != ups[j].Dep.Coordinate() {
			return ups[i].Dep.Coordinate() < ups[j].Dep.Coordinate()
		}
		return ups[i].Dep.File < ups[j].Dep.File
	})
	return ups, errs
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
