package worker

import (
	"strings"
	"testing"

	"github.com/axidex/craftnovate/internal/remediate"
)

func upd(group, artifact, version, target, updateType, datasource, manager string) Update {
	return Update{
		Upgrade: remediate.Upgrade{
			Dep: remediate.DeclaredDependency{
				Group: group, Artifact: artifact, Version: version, Datasource: datasource, File: "build.gradle.kts", Line: 1,
			},
			Target: target, UpdateType: updateType,
		},
		Manager: manager,
	}
}

func groupByBranch(groups []PRGroup) map[string]PRGroup {
	m := map[string]PRGroup{}
	for _, g := range groups {
		m[g.Branch] = g
	}
	return m
}

func TestParseStrategy(t *testing.T) {
	t.Parallel()
	cases := map[string]GroupStrategy{
		"":               StrategyMonorepo,
		"monorepo":       StrategyMonorepo,
		"bogus":          StrategyMonorepo,
		"per-dependency": StrategyPerDependency,
		"ecosystem":      StrategyEcosystem,
		"all":            StrategyAll,
	}
	for in, want := range cases {
		if got := ParseStrategy(in); got != want {
			t.Errorf("ParseStrategy(%q) = %q, want %q", in, got, want)
		}
	}
	if !StrategyMonorepo.SeparatesMajorMinor() || !StrategyEcosystem.SeparatesMajorMinor() {
		t.Error("monorepo/ecosystem must separate major from minor")
	}
	if StrategyPerDependency.SeparatesMajorMinor() || StrategyAll.SeparatesMajorMinor() {
		t.Error("per-dependency/all must not separate major from minor")
	}
}

func TestMavenFamily(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"com.fasterxml.jackson.core": "jackson",
		"org.jetbrains.kotlinx":      "kotlinx",
		"org.jetbrains.kotlin":       "kotlin",
		"org.springframework.boot":   "spring-boot",
		"org.springframework":        "spring",
		"org.junit.jupiter":          "junit5",
		"com.google.guava":           "", // not a known family
	}
	for group, want := range cases {
		if got := mavenFamily(group); got != want {
			t.Errorf("mavenFamily(%q) = %q, want %q", group, got, want)
		}
	}
}

// Monorepo strategy: same-family siblings group by bucket; majors split off; a
// lone family member renders per-dependency.
func TestGroupUpdatesWith_Monorepo(t *testing.T) {
	t.Parallel()

	updates := []Update{
		upd("com.fasterxml.jackson.core", "jackson-databind", "2.15.0", "2.17.0", "minor", "maven", "gradle"),
		upd("com.fasterxml.jackson.core", "jackson-core", "2.15.0", "2.17.0", "minor", "maven", "gradle"),
		upd("com.fasterxml.jackson.core", "jackson-annotations", "2.15.0", "3.0.0", "major", "maven", "gradle"),
		upd("com.fasterxml.jackson.dataformat", "jackson-dataformat-yaml", "2.15.0", "3.0.0", "major", "maven", "gradle"),
		upd("com.google.guava", "guava", "30.0-jre", "30.1.1-jre", "minor", "maven", "gradle"),
	}
	groups := groupByBranch(GroupUpdatesWith(updates, StrategyMonorepo))

	nonMajor, ok := groups["craftnovate/jackson-nonmajor"]
	if !ok {
		t.Fatalf("missing jackson non-major group; got %v", branches(groups))
	}
	if len(nonMajor.Upgrades) != 2 || !strings.Contains(nonMajor.Title, "jackson (minor & patch)") {
		t.Errorf("jackson non-major = %d upgrades, title %q", len(nonMajor.Upgrades), nonMajor.Title)
	}
	major, ok := groups["craftnovate/jackson-major"]
	if !ok || len(major.Upgrades) != 2 || !strings.Contains(major.Title, "jackson (major)") {
		t.Errorf("jackson major group wrong: %+v", major)
	}
	// guava is not a known family and is alone → per-dependency branch.
	if _, ok := groups["craftnovate/com.google.guava-guava-30.1.1-jre"]; !ok {
		t.Errorf("guava should render per-dependency; got %v", branches(groups))
	}
}

// Security fixes are always their own PR, never merged into a family group.
func TestGroupUpdatesWith_SecurityIsolated(t *testing.T) {
	t.Parallel()

	sec := upd("com.fasterxml.jackson.core", "jackson-databind", "2.15.0", "2.16.1", "patch", "maven", "gradle")
	sec.Upgrade.Security = true
	sec.Upgrade.VulnIDs = []string{"GHSA-xxxx"}
	sec.Labels = []string{"security"}
	normal := upd("com.fasterxml.jackson.core", "jackson-core", "2.15.0", "2.17.0", "minor", "maven", "gradle")

	groups := GroupUpdatesWith([]Update{sec, normal}, StrategyMonorepo)
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2 (security separate from family)", len(groups))
	}
	var foundSec bool
	for _, g := range groups {
		if len(g.Upgrades) == 1 && g.Upgrades[0].Security {
			foundSec = true
			if g.Coordinate != "com.fasterxml.jackson.core:jackson-databind" {
				t.Errorf("security group coordinate = %q", g.Coordinate)
			}
		}
	}
	if !foundSec {
		t.Error("security upgrade was not isolated into its own group")
	}
}

// Ecosystem strategy: non-major upgrades batch per manager; majors stay separate.
func TestGroupUpdatesWith_Ecosystem(t *testing.T) {
	t.Parallel()

	updates := []Update{
		upd("org.apache.commons", "commons-lang3", "3.10", "3.18.0", "minor", "maven", "gradle"),
		upd("com.squareup.okio", "okio", "3.2.0", "3.4.0", "minor", "maven", "gradle"),
		upd("com.google.guava", "guava", "30.0-jre", "32.0.0-jre", "major", "maven", "gradle"),
		upd("", "requests", "2.25.0", "2.31.0", "minor", "pypi", "pypi"),
		upd("", "urllib3", "1.26.0", "1.26.20", "patch", "pypi", "pypi"),
	}
	groups := groupByBranch(GroupUpdatesWith(updates, StrategyEcosystem))

	gradle, ok := groups["craftnovate/gradle-dependencies-nonmajor"]
	if !ok || len(gradle.Upgrades) != 2 {
		t.Errorf("gradle non-major group = %+v, want 2 upgrades; branches %v", gradle, branches(groups))
	}
	if pypi, ok := groups["craftnovate/pypi-dependencies-nonmajor"]; !ok || len(pypi.Upgrades) != 2 {
		t.Errorf("pypi non-major group = %+v; branches %v", pypi, branches(groups))
	}
	// guava major is separate, rendered per-dependency.
	if _, ok := groups["craftnovate/com.google.guava-guava-32.0.0-jre"]; !ok {
		t.Errorf("guava major should be its own per-dependency PR; got %v", branches(groups))
	}
}

// All strategy: everything in a single pull request.
func TestGroupUpdatesWith_All(t *testing.T) {
	t.Parallel()

	updates := []Update{
		upd("com.google.guava", "guava", "30.0-jre", "32.0.0-jre", "major", "maven", "gradle"),
		upd("", "requests", "2.25.0", "2.31.0", "minor", "pypi", "pypi"),
	}
	groups := GroupUpdatesWith(updates, StrategyAll)
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	if groups[0].Branch != "craftnovate/all-dependencies" || !strings.Contains(groups[0].Title, "all dependencies") {
		t.Errorf("all group = branch %q title %q", groups[0].Branch, groups[0].Title)
	}
	if len(groups[0].Upgrades) != 2 {
		t.Errorf("all group has %d upgrades, want 2", len(groups[0].Upgrades))
	}
}

// npm scoped packages group by scope under the monorepo strategy. The branch
// must not begin with a dash (the scope's leading '@' is stripped), while the
// title keeps the readable "@angular".
func TestGroupUpdatesWith_NPMScope(t *testing.T) {
	t.Parallel()

	updates := []Update{
		upd("", "@angular/core", "17.0.0", "17.1.0", "minor", "npm", "npm"),
		upd("", "@angular/common", "17.0.0", "17.1.0", "minor", "npm", "npm"),
	}
	groups := GroupUpdatesWith(updates, StrategyMonorepo)
	if len(groups) != 1 || len(groups[0].Upgrades) != 2 || !strings.Contains(groups[0].Title, "@angular") {
		t.Fatalf("npm scope grouping wrong: %+v", groups)
	}
	if groups[0].Branch != "craftnovate/angular-nonmajor" {
		t.Errorf("branch = %q, want craftnovate/angular-nonmajor (no leading dash)", groups[0].Branch)
	}
}

// A security fix that also carries a config groupName must still get its own PR,
// never be folded into the named group.
func TestGroupUpdatesWith_SecurityBeatsGroupName(t *testing.T) {
	t.Parallel()

	sec := upd("io.netty", "netty-codec-http", "4.1.133.Final", "4.1.135.Final", "patch", "maven", "gradle")
	sec.Upgrade.Security = true
	sec.GroupName = "all-deps"
	normal := upd("com.google.guava", "guava", "30.0-jre", "30.1.1-jre", "minor", "maven", "gradle")
	normal.GroupName = "all-deps"

	groups := GroupUpdatesWith([]Update{sec, normal}, StrategyMonorepo)
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2 (security isolated from the groupName)", len(groups))
	}
	var secBranch string
	for _, g := range groups {
		if len(g.Upgrades) == 1 && g.Upgrades[0].Security {
			secBranch = g.Branch
		}
	}
	if secBranch == "" || strings.Contains(secBranch, "all-deps") {
		t.Errorf("security branch = %q, want its own per-coordinate branch", secBranch)
	}
}

// One coordinate declared on two major lines (separate strategy) bumps each site
// to its own newest version; the single group must not name its branch/title
// after just one site's target.
func TestGroupUpdatesWith_HeterogeneousTargets(t *testing.T) {
	t.Parallel()

	a := upd("io.example", "lib", "2.15.0", "2.18.0", "minor", "maven", "gradle")
	a.Upgrade.Dep.File = "appA/build.gradle.kts"
	b := upd("io.example", "lib", "3.0.0", "3.5.0", "minor", "maven", "gradle")
	b.Upgrade.Dep.File = "appB/build.gradle.kts"

	groups := GroupUpdatesWith([]Update{a, b}, StrategyMonorepo)
	if len(groups) != 1 || len(groups[0].Upgrades) != 2 {
		t.Fatalf("want one 2-upgrade group, got %+v", groups)
	}
	g := groups[0]
	if g.Branch != "craftnovate/io.example-lib-nonmajor" {
		t.Errorf("branch = %q, want craftnovate/io.example-lib-nonmajor (target-agnostic)", g.Branch)
	}
	if strings.Contains(g.Title, "2.18.0") || strings.Contains(g.Title, "3.5.0") {
		t.Errorf("title must not name one site's target: %q", g.Title)
	}
}

func branches(m map[string]PRGroup) []string {
	out := make([]string, 0, len(m))
	for b := range m {
		out = append(out, b)
	}
	return out
}
