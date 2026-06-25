// Package config is depscan's policy configuration. It resolves built-in
// defaults with a repo config file (depscan.json) and an ordered packageRules
// array into a per-dependency Decision (enabled, allowed versions, stability,
// grouping, labels, reviewers), and provides a Selector that turns that policy
// into the chosen upgrade target.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/axidex/depscan/internal/versioning"
)

// Config is the resolved configuration. Pointer fields distinguish "unset" from
// the zero value so Merge precedence works.
type Config struct {
	Enabled         *bool    `json:"enabled,omitempty"`
	IgnoreDeps      []string `json:"ignoreDeps,omitempty"`
	IgnoreUnstable  *bool    `json:"ignoreUnstable,omitempty"`
	AllowedVersions string   `json:"allowedVersions,omitempty"`
	GroupName       string   `json:"groupName,omitempty"`
	Labels          []string `json:"labels,omitempty"`
	Reviewers       []string `json:"reviewers,omitempty"`
	// PRConcurrentLimit caps how many depscan PRs may be open at once
	// (0 = unlimited).
	PRConcurrentLimit int           `json:"prConcurrentLimit,omitempty"`
	PackageRules      []PackageRule `json:"packageRules,omitempty"`
}

// PackageRule is one ordered rule: every set match* selector must hold (AND);
// within a selector the values are OR-ed. Matching rules apply last-wins.
type PackageRule struct {
	MatchManagers        []string `json:"matchManagers,omitempty"`
	MatchPackageNames    []string `json:"matchPackageNames,omitempty"`
	MatchPackagePrefixes []string `json:"matchPackagePrefixes,omitempty"`
	MatchUpdateTypes     []string `json:"matchUpdateTypes,omitempty"`

	Enabled         *bool    `json:"enabled,omitempty"`
	AllowedVersions string   `json:"allowedVersions,omitempty"`
	IgnoreUnstable  *bool    `json:"ignoreUnstable,omitempty"`
	GroupName       string   `json:"groupName,omitempty"`
	Labels          []string `json:"labels,omitempty"`
	Reviewers       []string `json:"reviewers,omitempty"`
}

// PackageContext is the manager-agnostic subject a rule matches against.
type PackageContext struct {
	Manager    string
	Datasource string
	Name       string // "group:artifact"
	Current    string
	Target     string // candidate target; UpdateType derived from Current→Target
}

// Decision is the effective policy for one package after applying all rules.
type Decision struct {
	Enabled         bool
	IgnoreUnstable  bool
	AllowedVersions string
	GroupName       string
	Labels          []string
	Reviewers       []string
}

func deref(p *bool, def bool) bool {
	if p != nil {
		return *p
	}
	return def
}

// Defaults are the built-in settings: enabled, stable-only.
func Defaults() Config {
	return Config{Enabled: new(true), IgnoreUnstable: new(true)}
}

// candidateNames is the ordered list of config file names; the first found wins.
var candidateNames = []string{
	"depscan.json",
	".depscan.json",
	filepath.Join(".github", "depscan.json"),
}

// Discover returns the path of the first config file present under root.
func Discover(root string) (string, bool) {
	for _, name := range candidateNames {
		p := filepath.Join(root, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, true
		}
	}
	return "", false
}

// Load resolves the configuration for root: built-in defaults merged with the
// repo config file (if any). A missing config file is not an error.
func Load(root string) (Config, error) {
	def := Defaults()
	path, ok := Discover(root)
	if !ok {
		return def, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a discovered config file under the user-supplied repo root
	if err != nil {
		return def, fmt.Errorf("config: read %s: %w", path, err)
	}
	var file Config
	if err := json.Unmarshal(data, &file); err != nil {
		return def, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return def.Merge(file), nil
}

// Merge overlays over onto c, with over winning for set fields (slices replace).
func (c Config) Merge(over Config) Config {
	out := c
	if over.Enabled != nil {
		out.Enabled = over.Enabled
	}
	if over.IgnoreUnstable != nil {
		out.IgnoreUnstable = over.IgnoreUnstable
	}
	if over.AllowedVersions != "" {
		out.AllowedVersions = over.AllowedVersions
	}
	if over.GroupName != "" {
		out.GroupName = over.GroupName
	}
	if len(over.IgnoreDeps) > 0 {
		out.IgnoreDeps = over.IgnoreDeps
	}
	if len(over.Labels) > 0 {
		out.Labels = over.Labels
	}
	if len(over.Reviewers) > 0 {
		out.Reviewers = over.Reviewers
	}
	if len(over.PackageRules) > 0 {
		out.PackageRules = over.PackageRules
	}
	return out
}

// Decide computes the effective Decision for a package: base settings, then
// ignoreDeps, then each matching packageRule in order (last-wins). v supplies
// the ecosystem's update-type classification for matchUpdateTypes.
func (c Config) Decide(v versioning.Versioning, pc PackageContext) Decision {
	d := Decision{
		Enabled:         deref(c.Enabled, true),
		IgnoreUnstable:  deref(c.IgnoreUnstable, true),
		AllowedVersions: c.AllowedVersions,
		GroupName:       c.GroupName,
		Labels:          c.Labels,
		Reviewers:       c.Reviewers,
	}
	for _, dep := range c.IgnoreDeps {
		if matchName(dep, pc.Name) {
			d.Enabled = false
		}
	}
	for _, r := range c.PackageRules {
		if !r.Matches(v, pc) {
			continue
		}
		if r.Enabled != nil {
			d.Enabled = *r.Enabled
		}
		if r.IgnoreUnstable != nil {
			d.IgnoreUnstable = *r.IgnoreUnstable
		}
		if r.AllowedVersions != "" {
			d.AllowedVersions = r.AllowedVersions
		}
		if r.GroupName != "" {
			d.GroupName = r.GroupName
		}
		if len(r.Labels) > 0 {
			d.Labels = r.Labels
		}
		if len(r.Reviewers) > 0 {
			d.Reviewers = r.Reviewers
		}
	}
	return d
}

// Matches reports whether every set selector on the rule holds for pc. v
// classifies the update type for matchUpdateTypes.
func (r PackageRule) Matches(v versioning.Versioning, pc PackageContext) bool {
	if len(r.MatchManagers) > 0 && !contains(r.MatchManagers, pc.Manager) {
		return false
	}
	if len(r.MatchPackageNames) > 0 && !anyNameMatch(r.MatchPackageNames, pc.Name) {
		return false
	}
	if len(r.MatchPackagePrefixes) > 0 && !anyPrefix(r.MatchPackagePrefixes, pc.Name) {
		return false
	}
	if len(r.MatchUpdateTypes) > 0 {
		ut := v.UpdateType(pc.Current, pc.Target)
		if ut == "" || !contains(r.MatchUpdateTypes, ut) {
			return false
		}
	}
	return true
}

// matchName matches an exact name, a /regex/ pattern, or the artifact tail
// (after the last ':') against the package coordinate.
func matchName(pattern, name string) bool {
	if len(pattern) >= 2 && strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") {
		re, err := regexp.Compile(pattern[1 : len(pattern)-1])
		return err == nil && re.MatchString(name)
	}
	if pattern == name {
		return true
	}
	if i := strings.LastIndex(name, ":"); i >= 0 {
		return pattern == name[i+1:]
	}
	return false
}

func anyNameMatch(patterns []string, name string) bool {
	for _, p := range patterns {
		if matchName(p, name) {
			return true
		}
	}
	return false
}

func anyPrefix(prefixes []string, name string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func contains(s []string, v string) bool {
	return slices.Contains(s, v)
}

// AllowedVersionsMatch reports whether version satisfies constraint under the
// ecosystem versioning v. It supports an exact version, a comparator (`<`, `<=`,
// `>`, `>=`, `=`) and a `/regex/`. An empty constraint allows everything.
func AllowedVersionsMatch(v versioning.Versioning, constraint, version string) bool {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		return true
	}
	if len(constraint) >= 2 && strings.HasPrefix(constraint, "/") && strings.HasSuffix(constraint, "/") {
		re, err := regexp.Compile(constraint[1 : len(constraint)-1])
		return err == nil && re.MatchString(version)
	}
	for _, op := range []string{"<=", ">=", "<", ">", "="} {
		if !strings.HasPrefix(constraint, op) {
			continue
		}
		bound := strings.TrimSpace(constraint[len(op):])
		cmp := v.Compare(version, bound)
		switch op {
		case "<":
			return cmp < 0
		case "<=":
			return cmp <= 0
		case ">":
			return cmp > 0
		case ">=":
			return cmp >= 0
		case "=":
			return cmp == 0
		}
	}
	return v.Compare(version, constraint) == 0
}

// Selector applies a resolved Config to pick the upgrade target for a
// dependency. It satisfies the selector seam consumed by remediate.PlanUpgrades;
// the ecosystem versioning is supplied per call.
type Selector struct {
	cfg     Config
	manager string
}

// NewSelector binds a Selector to a config and the manager label used for
// packageRules matchManagers.
func NewSelector(cfg Config, manager string) Selector {
	return Selector{cfg: cfg, manager: manager}
}

// Select returns the newest candidate (newest first under v) that the config
// permits as an upgrade over current: enabled, passing ignoreUnstable and
// allowedVersions. Evaluating per candidate (with its Target) lets
// matchUpdateTypes rules — e.g. disable major bumps — take effect during
// selection.
func (s Selector) Select(v versioning.Versioning, coordinate, current string, candidates []string) (string, bool) {
	sorted := append([]string(nil), candidates...)
	sort.Slice(sorted, func(i, j int) bool { return v.Compare(sorted[i], sorted[j]) > 0 })

	for _, c := range sorted {
		if v.Compare(c, current) <= 0 {
			continue
		}
		pc := PackageContext{Manager: s.manager, Name: coordinate, Current: current, Target: c}
		d := s.cfg.Decide(v, pc)
		if !d.Enabled {
			continue
		}
		if d.IgnoreUnstable && !v.IsStable(c) && v.IsStable(current) {
			continue
		}
		if !AllowedVersionsMatch(v, d.AllowedVersions, c) {
			continue
		}
		return c, true
	}
	return "", false
}
