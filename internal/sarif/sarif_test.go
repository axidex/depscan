package sarif_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/axidex/depscan/internal/outdated"
	"github.com/axidex/depscan/internal/sarif"
	"github.com/axidex/depscan/internal/sbom"
	"github.com/axidex/depscan/internal/verdict"
	"github.com/axidex/depscan/internal/vuln"
)

func sampleVerdicts() []verdict.Verdict {
	return []verdict.Verdict{
		{
			Component: sbom.Component{PURL: "pkg:npm/lodash@4.17.20", Name: "lodash", Version: "4.17.20"},
			Level:     verdict.LevelMust,
			Vulns: []vuln.Vuln{{
				ID:            "GHSA-29mw-wpgm-hmr9",
				CVEs:          []string{"CVE-2021-23337"},
				HasFix:        true,
				FixedVersions: []string{"4.17.21"},
			}},
			Outdated:      outdated.Result{Kind: outdated.KindPatch, Latest: "4.17.21"},
			TargetVersion: "4.17.21",
			HasFix:        true,
			Reasons:       []string{"1 known vulnerability"},
		},
		{
			Component:     sbom.Component{PURL: "pkg:maven/com.google.guava/guava@30.0-jre", Name: "guava", Version: "30.0-jre"},
			Level:         verdict.LevelShould,
			Outdated:      outdated.Result{Kind: outdated.KindMajor, Latest: "33.4.8-jre"},
			TargetVersion: "33.4.8-jre",
			Reasons:       []string{"major update available"},
		},
		{
			Component: sbom.Component{PURL: "pkg:npm/safe@1.0.0", Name: "safe", Version: "1.0.0"},
			Level:     verdict.LevelOK,
			Outdated:  outdated.Result{Kind: outdated.KindUpToDate, Latest: "1.0.0"},
		},
	}
}

func TestBuild_Structure(t *testing.T) {
	t.Parallel()

	log := sarif.Build(sampleVerdicts(), sarif.ToolMeta{Name: "depscan", Version: "test", InformationURI: "https://example.test"})

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if log.Schema != sarif.SchemaURI {
		t.Errorf("schema = %q, want %q", log.Schema, sarif.SchemaURI)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "depscan" {
		t.Errorf("driver name = %q, want depscan", run.Tool.Driver.Name)
	}

	// ok verdict is excluded -> 2 results.
	if len(run.Results) != 2 {
		t.Fatalf("results = %d, want 2 (ok excluded)", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(run.Tool.Driver.Rules))
	}

	byRule := map[string]sarif.Result{}
	for _, r := range run.Results {
		byRule[r.RuleID] = r
		// ruleIndex must point at the matching rule.
		if r.RuleIndex < 0 || r.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Fatalf("ruleIndex %d out of range", r.RuleIndex)
		}
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("ruleIndex %d -> rule %q, want %q", r.RuleIndex, run.Tool.Driver.Rules[r.RuleIndex].ID, r.RuleID)
		}
	}

	vulnRes, ok := byRule["vulnerable-dependency/pkg:npm/lodash"]
	if !ok {
		t.Fatalf("missing vuln result; rules: %v", byRule)
	}
	if vulnRes.Level != "error" {
		t.Errorf("vuln level = %q, want error", vulnRes.Level)
	}
	if vulnRes.Properties["recommendedVersion"] != "4.17.21" {
		t.Errorf("recommendedVersion = %v, want 4.17.21", vulnRes.Properties["recommendedVersion"])
	}
	if vulnRes.Properties["hasFix"] != true {
		t.Errorf("hasFix = %v, want true", vulnRes.Properties["hasFix"])
	}
	if cves, _ := vulnRes.Properties["cveIds"].([]string); len(cves) != 1 || cves[0] != "CVE-2021-23337" {
		t.Errorf("cveIds = %v, want [CVE-2021-23337]", vulnRes.Properties["cveIds"])
	}
	if len(vulnRes.PartialFingerprints) == 0 {
		t.Error("expected partialFingerprints for dedup")
	}

	outRes, ok := byRule["outdated-dependency/pkg:maven/com.google.guava/guava"]
	if !ok {
		t.Fatal("missing outdated result")
	}
	if outRes.Level != "warning" {
		t.Errorf("outdated level = %q, want warning", outRes.Level)
	}
	if outRes.Properties["updateType"] != "major" {
		t.Errorf("updateType = %v, want major", outRes.Properties["updateType"])
	}
}

func TestBuild_RuleDeduplication(t *testing.T) {
	t.Parallel()

	// Two verdicts for the same package (different versions) share one rule.
	verdicts := []verdict.Verdict{
		{
			Component: sbom.Component{PURL: "pkg:npm/lodash@4.17.20", Name: "lodash", Version: "4.17.20"},
			Level:     verdict.LevelMust,
			Vulns:     []vuln.Vuln{{ID: "CVE-1", HasFix: true, FixedVersions: []string{"4.17.21"}}},
		},
		{
			Component: sbom.Component{PURL: "pkg:npm/lodash@4.17.19", Name: "lodash", Version: "4.17.19"},
			Level:     verdict.LevelMust,
			Vulns:     []vuln.Vuln{{ID: "CVE-1", HasFix: true, FixedVersions: []string{"4.17.21"}}},
		},
	}
	log := sarif.Build(verdicts, sarif.ToolMeta{Name: "depscan"})
	if got := len(log.Runs[0].Tool.Driver.Rules); got != 1 {
		t.Errorf("rules = %d, want 1 (deduped by version-less purl)", got)
	}
	if got := len(log.Runs[0].Results); got != 2 {
		t.Errorf("results = %d, want 2", got)
	}
}

func TestRender_ValidJSONAndLevels(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := sarif.Render(&buf, sampleVerdicts(), sarif.ToolMeta{Name: "depscan"}); err != nil {
		t.Fatalf("Render: %v", err)
	}

	// Must be valid JSON.
	var generic map[string]any
	if err := json.Unmarshal(buf.Bytes(), &generic); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Re-decode strongly and assert level enum compliance.
	var log sarif.Log
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("decode Log: %v", err)
	}
	allowed := map[string]bool{"error": true, "warning": true, "note": true, "none": true}
	for _, r := range log.Runs[0].Results {
		if !allowed[r.Level] {
			t.Errorf("invalid SARIF level %q", r.Level)
		}
		if r.Message.Text == "" {
			t.Error("result missing message.text")
		}
		if len(r.Locations) == 0 || len(r.Locations[0].LogicalLocations) == 0 {
			t.Error("result missing logical location")
		}
	}
}

func TestBuild_FingerprintIdentity(t *testing.T) {
	t.Parallel()

	fp := func(v verdict.Verdict) string {
		log := sarif.Build([]verdict.Verdict{v}, sarif.ToolMeta{Name: "depscan"})
		return log.Runs[0].Results[0].PartialFingerprints["depscan/v1"]
	}

	// Different versions of the same package must get distinct fingerprints, so
	// neither is silently deduplicated away by a code host.
	v1 := verdict.Verdict{
		Component: sbom.Component{PURL: "pkg:npm/foo@1.0.0", Name: "foo", Version: "1.0.0"},
		Level:     verdict.LevelShould,
		Outdated:  outdated.Result{Kind: outdated.KindMajor, Latest: "2.0.0"},
	}
	v2 := v1
	v2.Component = sbom.Component{PURL: "pkg:npm/foo@1.5.0", Name: "foo", Version: "1.5.0"}
	if fp(v1) == fp(v2) {
		t.Errorf("fingerprints collide across versions: %q", fp(v1))
	}

	// The same package@version must keep a STABLE fingerprint even as its vuln
	// set grows or its update kind changes, preserving alert continuity.
	base := verdict.Verdict{
		Component: sbom.Component{PURL: "pkg:npm/bar@1.0.0", Name: "bar", Version: "1.0.0"},
		Level:     verdict.LevelMust,
		Vulns:     []vuln.Vuln{{ID: "CVE-1", HasFix: true, FixedVersions: []string{"1.0.1"}}},
		Outdated:  outdated.Result{Kind: outdated.KindPatch, Latest: "1.0.1"},
	}
	grown := base
	grown.Vulns = []vuln.Vuln{
		{ID: "CVE-1", HasFix: true, FixedVersions: []string{"1.0.1"}},
		{ID: "CVE-2", HasFix: true, FixedVersions: []string{"1.0.1"}},
	}
	grown.Outdated = outdated.Result{Kind: outdated.KindMinor, Latest: "1.5.0"}
	if fp(base) != fp(grown) {
		t.Errorf("fingerprint changed when only vuln set/kind changed: %q != %q", fp(base), fp(grown))
	}
}

func TestBuild_Empty(t *testing.T) {
	t.Parallel()

	log := sarif.Build(nil, sarif.ToolMeta{Name: "depscan"})
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("results = %d, want 0", len(log.Runs[0].Results))
	}
	// rules must serialize as [] not null.
	var buf bytes.Buffer
	if err := sarif.Write(&buf, log); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"rules": []`)) {
		t.Errorf("expected empty rules array in output, got:\n%s", buf.String())
	}
}
