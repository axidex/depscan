package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/axidex/depscan/internal/outdated"
	"github.com/axidex/depscan/internal/report"
	"github.com/axidex/depscan/internal/sbom"
	"github.com/axidex/depscan/internal/verdict"
	"github.com/axidex/depscan/internal/vuln"
)

func TestTable(t *testing.T) {
	t.Parallel()

	verdicts := []verdict.Verdict{
		{
			Component: sbom.Component{Name: "safe", Version: "1.0.0"},
			Level:     verdict.LevelOK,
			Outdated:  outdated.Result{Kind: outdated.KindUpToDate, Latest: "1.0.0"},
		},
		{
			Component:     sbom.Component{Name: "guava", Version: "30.0"},
			Level:         verdict.LevelShould,
			Outdated:      outdated.Result{Kind: outdated.KindMajor, Latest: "33.0"},
			TargetVersion: "33.0",
		},
		{
			Component:     sbom.Component{Name: "lodash", Version: "4.17.20"},
			Level:         verdict.LevelMust,
			Vulns:         []vuln.Vuln{{ID: "GHSA-x", CVEs: []string{"CVE-2021-23337"}, HasFix: true}},
			Outdated:      outdated.Result{Kind: outdated.KindMinor, Latest: "4.18.1"},
			TargetVersion: "4.17.21",
		},
	}

	var buf bytes.Buffer
	if err := report.Table(&buf, verdicts); err != nil {
		t.Fatalf("Table: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "VERDICT") || !strings.Contains(out, "TARGET") {
		t.Errorf("missing header row:\n%s", out)
	}

	// must-update must sort above should-update above ok.
	lodash := strings.Index(out, "lodash")
	guava := strings.Index(out, "guava")
	safe := strings.Index(out, "safe")
	if !(lodash < guava && guava < safe) {
		t.Errorf("rows not sorted by severity (lodash<guava<safe): %d %d %d\n%s", lodash, guava, safe, out)
	}

	if !strings.Contains(out, "CVE-2021-23337") {
		t.Errorf("missing CVE id:\n%s", out)
	}
	if !strings.Contains(out, "4.17.21") {
		t.Errorf("missing target version:\n%s", out)
	}
}

func TestTable_Empty(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := report.Table(&buf, nil); err != nil {
		t.Fatalf("Table(nil): %v", err)
	}
	if !strings.Contains(buf.String(), "VERDICT") {
		t.Error("expected header even with no verdicts")
	}
}
