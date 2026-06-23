//go:build e2e

// This live end-to-end test runs the full depscan pipeline against the real
// OSV.dev and Maven Central APIs. It is gated behind the "e2e" build tag so the
// default `go test ./...` stays hermetic and fast. Run it with:
//
//	go test -tags=e2e -timeout=10m ./e2e/...
//
// Assertions are about structure and SARIF validity, not exact CVE counts,
// which drift over time as advisories are published.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/axidex/depscan/internal/outdated"
	"github.com/axidex/depscan/internal/sarif"
	"github.com/axidex/depscan/internal/scan"
	"github.com/axidex/depscan/internal/verdict"
	"github.com/axidex/depscan/internal/vuln"
)

func TestKotlinSBOM_LiveScan(t *testing.T) {
	components := loadKotlinComponents(t)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	scanner := scan.New(
		vuln.NewOSVClient(vuln.WithConcurrency(8)),
		outdated.NewChecker(outdated.DefaultRegistries(nil)...),
	)

	rep, err := scanner.Scan(ctx, components, scan.Options{Concurrency: 8})
	if err != nil {
		t.Fatalf("live scan failed: %v", err)
	}
	if len(rep.Verdicts) != len(components) {
		t.Fatalf("got %d verdicts, want %d (one per component)", len(rep.Verdicts), len(components))
	}
	for _, w := range rep.Warnings {
		t.Logf("scan warning: %s", w)
	}

	// Summarize for the developer running the e2e.
	var must, should, ok int
	for _, v := range rep.Verdicts {
		switch v.Level {
		case verdict.LevelMust:
			must++
		case verdict.LevelShould:
			should++
		default:
			ok++
		}
	}
	t.Logf("verdicts: %d must-update, %d should-update, %d ok (of %d components)",
		must, should, ok, len(rep.Verdicts))

	// A real, aging Kotlin/Maven dependency set must surface some findings.
	if must+should == 0 {
		t.Errorf("expected at least one non-ok verdict for a real-world SBOM")
	}

	// Render SARIF and persist it as a test artifact for inspection.
	var buf bytes.Buffer
	meta := sarif.ToolMeta{Name: "depscan", Version: "e2e", InformationURI: "https://github.com/axidex/depscan"}
	if err := sarif.Render(&buf, rep.Verdicts, meta); err != nil {
		t.Fatalf("render SARIF: %v", err)
	}
	artifact := filepath.Join(t.ArtifactDir(), "CdxSbomKotlin.sarif")
	if err := os.WriteFile(artifact, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	t.Logf("SARIF artifact: %s (%d bytes)", artifact, buf.Len())

	validateSARIF(t, buf.Bytes(), must+should)
}

// validateSARIF decodes the report and checks SARIF 2.1.0 invariants that must
// hold regardless of the specific vulnerability data returned.
func validateSARIF(t *testing.T, data []byte, wantResults int) {
	t.Helper()

	// Must be valid JSON.
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}

	var log sarif.Log
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if log.Schema != sarif.SchemaURI {
		t.Errorf("schema = %q, want canonical OASIS URL", log.Schema)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	run := log.Runs[0]

	if len(run.Results) != wantResults {
		t.Errorf("results = %d, want %d (one per non-ok verdict)", len(run.Results), wantResults)
	}

	allowed := map[string]bool{"error": true, "warning": true, "note": true, "none": true}
	fingerprints := map[string]bool{}
	for i, r := range run.Results {
		if !allowed[r.Level] {
			t.Errorf("result %d: invalid SARIF level %q", i, r.Level)
		}
		if r.Message.Text == "" {
			t.Errorf("result %d: empty message.text", i)
		}
		if r.RuleIndex < 0 || r.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Errorf("result %d: ruleIndex %d out of range", i, r.RuleIndex)
			continue
		}
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("result %d: ruleIndex points at wrong rule", i)
		}
		if r.Properties["ecosystem"] != "maven" {
			t.Errorf("result %d: ecosystem = %v, want maven", i, r.Properties["ecosystem"])
		}
		if r.Properties["purl"] == "" || r.Properties["purl"] == nil {
			t.Errorf("result %d: missing purl property", i)
		}
		fp := r.PartialFingerprints["depscan/v1"]
		if fp == "" {
			t.Errorf("result %d: missing partial fingerprint", i)
		}
		if fingerprints[fp] {
			t.Errorf("result %d: duplicate fingerprint %q (collision)", i, fp)
		}
		fingerprints[fp] = true
	}
}
