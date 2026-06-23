package verdict_test

import (
	"testing"

	"github.com/axidex/depscan/internal/outdated"
	"github.com/axidex/depscan/internal/sbom"
	"github.com/axidex/depscan/internal/verdict"
	"github.com/axidex/depscan/internal/vuln"
)

func comp(version string) sbom.Component {
	return sbom.Component{PURL: "pkg:npm/lodash@" + version, Name: "lodash", Version: version}
}

func vulnWithFix(fixes ...string) vuln.Result {
	return vuln.Result{Vulns: []vuln.Vuln{{
		ID:            "CVE-2021-23337",
		CVEs:          []string{"CVE-2021-23337"},
		FixedVersions: fixes,
		HasFix:        len(fixes) > 0,
	}}}
}

func vulnNoFix() vuln.Result {
	return vuln.Result{Vulns: []vuln.Vuln{{ID: "GHSA-nofix"}}}
}

func od(kind outdated.UpdateKind, latest string) outdated.Result {
	return outdated.Result{Kind: kind, Latest: latest}
}

func TestDecide(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		current    string
		vr         vuln.Result
		or         outdated.Result
		wantLevel  verdict.Level
		wantTarget string
	}{
		{
			name:       "vuln with fix is must-update",
			current:    "4.17.20",
			vr:         vulnWithFix("4.17.21"),
			or:         od(outdated.KindPatch, "4.17.21"),
			wantLevel:  verdict.LevelMust,
			wantTarget: "4.17.21",
		},
		{
			name:       "must-update overrides major outdated, targets security fix",
			current:    "4.17.20",
			vr:         vulnWithFix("4.17.21"),
			or:         od(outdated.KindMajor, "5.0.0"),
			wantLevel:  verdict.LevelMust,
			wantTarget: "4.17.21",
		},
		{
			name:       "vuln without fix is should-update",
			current:    "1.0.0",
			vr:         vulnNoFix(),
			or:         od(outdated.KindUnknown, ""),
			wantLevel:  verdict.LevelShould,
			wantTarget: "",
		},
		{
			name:       "major outdated without vuln is should-update",
			current:    "1.0.0",
			vr:         vuln.Result{},
			or:         od(outdated.KindMajor, "3.0.0"),
			wantLevel:  verdict.LevelShould,
			wantTarget: "3.0.0",
		},
		{
			name:       "minor outdated without vuln is should-update",
			current:    "1.0.0",
			vr:         vuln.Result{},
			or:         od(outdated.KindMinor, "1.4.0"),
			wantLevel:  verdict.LevelShould,
			wantTarget: "1.4.0",
		},
		{
			name:      "patch outdated without vuln is ok",
			current:   "1.0.0",
			vr:        vuln.Result{},
			or:        od(outdated.KindPatch, "1.0.5"),
			wantLevel: verdict.LevelOK,
		},
		{
			name:      "up-to-date is ok",
			current:   "1.0.0",
			vr:        vuln.Result{},
			or:        od(outdated.KindUpToDate, "1.0.0"),
			wantLevel: verdict.LevelOK,
		},
		{
			name:      "unknown outdated without vuln is ok",
			current:   "1.0.0",
			vr:        vuln.Result{},
			or:        od(outdated.KindUnknown, ""),
			wantLevel: verdict.LevelOK,
		},
		{
			name:       "non-semver newer is should-update",
			current:    "2.0.1.Final",
			vr:         vuln.Result{},
			or:         od(outdated.KindNewer, "2.0.2.Final"),
			wantLevel:  verdict.LevelShould,
			wantTarget: "2.0.2.Final",
		},
		{
			name:       "vuln without fix plus major lag targets latest",
			current:    "1.0.0",
			vr:         vulnNoFix(),
			or:         od(outdated.KindMajor, "3.0.0"),
			wantLevel:  verdict.LevelShould,
			wantTarget: "3.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := verdict.Decide(comp(tt.current), tt.vr, tt.or)
			if got.Level != tt.wantLevel {
				t.Errorf("Level = %q, want %q", got.Level, tt.wantLevel)
			}
			if got.TargetVersion != tt.wantTarget {
				t.Errorf("TargetVersion = %q, want %q", got.TargetVersion, tt.wantTarget)
			}
		})
	}
}

func TestDecide_RecommendedFixPicksMinimumAboveCurrent(t *testing.T) {
	t.Parallel()

	// Multiple fixed versions across ranges; recommend the smallest that is
	// strictly newer than the current version.
	vr := vuln.Result{Vulns: []vuln.Vuln{{
		ID:            "CVE-X",
		FixedVersions: []string{"4.17.21", "3.0.0", "5.0.0"},
		HasFix:        true,
	}}}
	got := verdict.Decide(comp("4.17.20"), vr, od(outdated.KindUnknown, ""))
	if got.Level != verdict.LevelMust {
		t.Fatalf("Level = %q, want must-update", got.Level)
	}
	if got.TargetVersion != "4.17.21" {
		t.Errorf("TargetVersion = %q, want 4.17.21 (min fix > current)", got.TargetVersion)
	}
}

func TestDecide_Reasons(t *testing.T) {
	t.Parallel()

	got := verdict.Decide(comp("4.17.20"), vulnWithFix("4.17.21"), od(outdated.KindMajor, "5.0.0"))
	if len(got.Reasons) == 0 {
		t.Fatal("expected reasons, got none")
	}
}
