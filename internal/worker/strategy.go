package worker

import (
	"fmt"
	"sort"
	"strings"

	"github.com/axidex/craftnovate/internal/remediate"
)

// GroupStrategy decides how upgrades are batched into pull requests.
type GroupStrategy string

// The supported grouping strategies.
const (
	// StrategyMonorepo separates major from minor/patch and groups known
	// monorepo families (Renovate's default behavior). It is the default.
	StrategyMonorepo GroupStrategy = "monorepo"
	// StrategyPerDependency opens one pull request per dependency.
	StrategyPerDependency GroupStrategy = "per-dependency"
	// StrategyEcosystem groups all non-major upgrades of a manager into one
	// pull request and keeps each major upgrade separate.
	StrategyEcosystem GroupStrategy = "ecosystem"
	// StrategyAll batches every upgrade into a single pull request.
	StrategyAll GroupStrategy = "all"
)

// ParseStrategy resolves a strategy name; an empty or unknown value yields the
// default (monorepo).
func ParseStrategy(s string) GroupStrategy {
	switch GroupStrategy(s) {
	case StrategyPerDependency:
		return StrategyPerDependency
	case StrategyEcosystem:
		return StrategyEcosystem
	case StrategyAll:
		return StrategyAll
	default:
		return StrategyMonorepo
	}
}

// SeparatesMajorMinor reports whether the strategy plans major and non-major
// upgrades as independent pull requests.
func (s GroupStrategy) SeparatesMajorMinor() bool {
	return s == StrategyMonorepo || s == StrategyEcosystem
}

// update buckets.
const (
	bucketNonMajor = "nonmajor"
	bucketMajor    = "major"
)

func bucketOf(updateType string) string {
	if updateType == bucketMajor {
		return bucketMajor
	}
	return bucketNonMajor
}

// groupSpec is how one update maps into a pull-request group: a dedup key, plus
// (for named groups) a display base and bucket used to render the branch/title.
type groupSpec struct {
	key        string
	display    string // title/branch base for a named (multi-coordinate) group
	bucket     string // "", bucketNonMajor, or bucketMajor
	forceNamed bool   // render as a named group even with a single coordinate
}

// specFor maps an update to its grouping spec under the strategy. Security fixes
// always get their own PR (even if a groupName would otherwise apply); otherwise
// an explicit config groupName wins.
func specFor(u Update, strategy GroupStrategy) groupSpec {
	coord := u.Upgrade.Dep.Coordinate()
	bkt := bucketOf(u.Upgrade.UpdateType)

	if u.Upgrade.Security {
		return groupSpec{key: "sec:" + coord + "|" + u.Upgrade.Target}
	}
	if u.GroupName != "" {
		return groupSpec{key: "name:" + u.GroupName, display: u.GroupName, forceNamed: true}
	}

	switch strategy {
	case StrategyAll:
		return groupSpec{key: "all", display: "all dependencies", forceNamed: true}
	case StrategyEcosystem:
		if bkt == bucketMajor {
			return groupSpec{key: "coord:" + coord + "|major", bucket: bucketMajor}
		}
		return groupSpec{key: "eco:" + u.Manager + "|nonmajor", display: u.Manager + " dependencies", bucket: bucketNonMajor}
	case StrategyPerDependency:
		return groupSpec{key: "coord:" + coord}
	default: // StrategyMonorepo
		if fam := family(u.Upgrade); fam != "" {
			return groupSpec{key: "fam:" + fam + "|" + bkt, display: fam, bucket: bkt}
		}
		return groupSpec{key: "coord:" + coord + "|" + bkt, bucket: bkt}
	}
}

// GroupUpdatesWith batches updates into pull requests under the strategy,
// deterministically deriving each group's branch, title, body and labels. A
// group covering several coordinates (or an explicit groupName/all group) is
// rendered as a named bucket group with a stable branch; a single-coordinate
// group keeps the "<coord>-<target>" branch so re-runs match.
func GroupUpdatesWith(updates []Update, strategy GroupStrategy) []PRGroup {
	type bucket struct {
		spec     groupSpec
		ups      []remediate.Upgrade
		labels   []string
		labelSet map[string]bool
		coords   map[string]bool
	}
	byKey := map[string]*bucket{}
	var order []string
	for _, u := range updates {
		s := specFor(u, strategy)
		b, ok := byKey[s.key]
		if !ok {
			b = &bucket{spec: s, labelSet: map[string]bool{}, coords: map[string]bool{}}
			byKey[s.key] = b
			order = append(order, s.key)
		}
		b.ups = append(b.ups, u.Upgrade)
		b.coords[u.Upgrade.Dep.Coordinate()] = true
		for _, l := range u.Labels {
			if !b.labelSet[l] {
				b.labelSet[l] = true
				b.labels = append(b.labels, l)
			}
		}
	}
	sort.Strings(order)

	groups := make([]PRGroup, 0, len(order))
	for _, key := range order {
		b := byKey[key]
		g := PRGroup{Labels: b.labels, Upgrades: b.ups}
		coord := b.ups[0].Dep.Coordinate()
		switch {
		case b.spec.forceNamed || len(b.coords) > 1:
			// Multi-coordinate (or force-named) group: a stable, target-agnostic
			// bucket branch keyed on the family/manager/group name.
			base := b.spec.display
			g.Coordinate = base
			g.Branch = BranchPrefix + branchPart(base) + bucketBranchSuffix(b.spec.bucket)
			g.Title = "chore(deps): update " + base + bucketTitleSuffix(b.spec.bucket)
			g.Body = prBodyGroup(base, b.ups)
		case heterogeneousTargets(b.ups):
			// One coordinate declared on multiple major lines: each site has its
			// own newest bump, so don't name the branch/title after one target.
			g.Coordinate = coord
			g.Branch = BranchPrefix + branchPart(coord) + bucketBranchSuffix(b.spec.bucket)
			g.Title = "chore(deps): update " + coord + bucketTitleSuffix(b.spec.bucket)
			g.Body = prBodyGroup(coord, b.ups)
		default:
			target := b.ups[0].Target
			g.Coordinate = coord
			g.Branch = BranchPrefix + branchPart(coord) + "-" + sanitizeRef(target)
			g.Title = fmt.Sprintf("chore(deps): update %s to %s", coord, target)
			g.Body = prBody(coord, b.ups)
		}
		groups = append(groups, g)
	}
	return groups
}

// heterogeneousTargets reports whether the upgrades carry more than one distinct
// target (the same coordinate declared on different major lines, each bumped to
// its own newest version).
func heterogeneousTargets(ups []remediate.Upgrade) bool {
	for _, u := range ups[1:] {
		if u.Target != ups[0].Target {
			return true
		}
	}
	return false
}

func bucketBranchSuffix(bucket string) string {
	switch bucket {
	case bucketMajor:
		return "-major"
	case bucketNonMajor:
		return "-nonmajor"
	default:
		return ""
	}
}

func bucketTitleSuffix(bucket string) string {
	switch bucket {
	case bucketMajor:
		return " (major)"
	case bucketNonMajor:
		return " (minor & patch)"
	default:
		return ""
	}
}

// datasource ids carried on a DeclaredDependency.
const (
	dsMaven        = "maven"
	dsGradlePlugin = "gradle-plugin"
	dsNPM          = "npm"
)

// family returns the monorepo family an upgrade belongs to, or "" if none: a
// known Maven group family, or an npm scope. Members of a family are grouped
// into one pull request (Renovate's group:monorepos).
func family(u remediate.Upgrade) string {
	switch u.Dep.Datasource {
	case dsMaven, dsGradlePlugin:
		return mavenFamily(u.Dep.Group)
	case dsNPM:
		if name := u.Dep.Artifact; strings.HasPrefix(name, "@") {
			if i := strings.Index(name, "/"); i > 0 {
				return name[:i] // scope, e.g. "@angular"
			}
		}
	}
	return ""
}

// mavenFamilies maps a Maven groupId prefix to a monorepo family name. Ordered
// most-specific first so e.g. kotlinx wins over kotlin and spring-boot over
// spring. Reimplemented from public knowledge of where these artifacts live (not
// copied from any dependency bot's data).
var mavenFamilies = []struct{ prefix, name string }{
	{"org.jetbrains.kotlinx", "kotlinx"},
	{"org.jetbrains.kotlin", "kotlin"},
	{"com.fasterxml.jackson", "jackson"},
	{"io.netty", "netty"},
	{"io.grpc", "grpc"},
	{"org.springframework.boot", "spring-boot"},
	{"org.springframework.security", "spring-security"},
	{"org.springframework", "spring"},
	{"io.micrometer", "micrometer"},
	{"org.junit", "junit5"},
	{"com.squareup.okhttp3", "okhttp"},
	{"com.squareup.retrofit2", "retrofit"},
	{"software.amazon.awssdk", "aws-sdk-v2"},
	{"com.amazonaws", "aws-sdk-v1"},
	{"com.google.protobuf", "protobuf"},
	{"org.mockito", "mockito"},
	{"org.testcontainers", "testcontainers"},
	{"io.quarkus", "quarkus"},
	{"org.apache.logging.log4j", "log4j"},
	{"com.azure", "azure-sdk"},
	{"org.jetbrains.exposed", "exposed"},
	{"io.ktor", "ktor"},
}

func mavenFamily(group string) string {
	for _, f := range mavenFamilies {
		if group == f.prefix || strings.HasPrefix(group, f.prefix+".") {
			return f.name
		}
	}
	return ""
}
