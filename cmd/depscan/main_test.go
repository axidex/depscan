package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/axidex/depscan/internal/outdated"
	"github.com/axidex/depscan/internal/purl"
	"github.com/axidex/depscan/internal/scan"
	"github.com/axidex/depscan/internal/verdict"
	"github.com/axidex/depscan/internal/vuln"
)

// --- command-level (cobra + viper) tests ---

// executeCmd runs the root command with the given args and returns captured
// stdout, stderr, and the process exit code.
func executeCmd(args ...string) (string, string, int) {
	root := newRootCmd()
	root.SetArgs(args)
	var out, errb bytes.Buffer
	code := runRoot(root, &out, &errb)
	return out.String(), errb.String(), code
}

func TestCommand_Validation(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
	}{
		{name: "missing sbom", args: []string{"--out", "r.sarif"}, wantCode: 2},
		{name: "bad fail-on", args: []string{"--sbom", "b.json", "--fail-on", "critical"}, wantCode: 2},
		{name: "bad format", args: []string{"--sbom", "b.json", "--format", "yaml"}, wantCode: 2},
		{name: "table with stdout out", args: []string{"--sbom", "b.json", "--format", "table", "--out", "-"}, wantCode: 2},
		{name: "unknown flag", args: []string{"--sbom", "b.json", "--bogus"}, wantCode: 2},
		{name: "unexpected positional arg", args: []string{"--sbom", "b.json", "extra"}, wantCode: 2},
		{name: "version", args: []string{"--version"}, wantCode: 0},
		{name: "help", args: []string{"--help"}, wantCode: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, code := executeCmd(tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
		})
	}
}

func TestCommand_Version(t *testing.T) {
	out, _, code := executeCmd("--version")
	if code != 0 || !strings.Contains(out, "depscan") {
		t.Errorf("--version: code=%d out=%q", code, out)
	}
}

// TestCommand_EnvFailOn proves DEPSCAN_* env binding works end-to-end: the gate
// level is supplied purely via the environment, not a flag.
func TestCommand_EnvFailOn(t *testing.T) {
	withFakeScanner(t)
	t.Setenv("DEPSCAN_FAIL_ON", "must-update")

	out := filepath.Join(t.TempDir(), "r.sarif")
	_, stderr, code := executeCmd("--sbom", "testdata/bom.json", "--out", out)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (env-set fail-on must-update); stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "fail-on=must-update") {
		t.Errorf("expected gate message in stderr:\n%s", stderr)
	}
}

func TestGateTriggered(t *testing.T) {
	t.Parallel()

	must := verdict.Verdict{Level: verdict.LevelMust}
	should := verdict.Verdict{Level: verdict.LevelShould}
	ok := verdict.Verdict{Level: verdict.LevelOK}

	tests := []struct {
		name     string
		verdicts []verdict.Verdict
		failOn   string
		want     bool
	}{
		{name: "no gate", verdicts: []verdict.Verdict{must}, failOn: "", want: false},
		{name: "must gate hit", verdicts: []verdict.Verdict{should, must}, failOn: "must-update", want: true},
		{name: "must gate miss", verdicts: []verdict.Verdict{should, ok}, failOn: "must-update", want: false},
		{name: "should gate hit by should", verdicts: []verdict.Verdict{ok, should}, failOn: "should-update", want: true},
		{name: "should gate hit by must", verdicts: []verdict.Verdict{must}, failOn: "should-update", want: true},
		{name: "should gate miss", verdicts: []verdict.Verdict{ok}, failOn: "should-update", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := gateTriggered(tt.verdicts, tt.failOn); got != tt.want {
				t.Errorf("gateTriggered = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- runScan end-to-end with an injected scanner (no network) ---

type fakeVuln struct{ results map[string]vuln.Result }

func (f fakeVuln) Query(_ context.Context, _ []string) (map[string]vuln.Result, error) {
	return f.results, nil
}

type fakeRegistry struct{ latest map[string]string }

func (f fakeRegistry) Ecosystem() string { return "npm" }
func (f fakeRegistry) Latest(_ context.Context, p purl.PURL) (string, error) {
	if v, ok := f.latest[p.Name]; ok {
		return v, nil
	}
	return "", outdated.ErrNotFound
}

// withFakeScanner swaps newScanner for one backed by fakes and restores it.
func withFakeScanner(t *testing.T) {
	t.Helper()
	prev := newScanner
	t.Cleanup(func() { newScanner = prev })
	newScanner = func(config) *scan.Scanner {
		v := fakeVuln{results: map[string]vuln.Result{
			"pkg:npm/lodash@4.17.20": {Vulns: []vuln.Vuln{{
				ID:            "CVE-2021-23337",
				CVEs:          []string{"CVE-2021-23337"},
				HasFix:        true,
				FixedVersions: []string{"4.17.21"},
			}}},
		}}
		reg := fakeRegistry{latest: map[string]string{"lodash": "4.17.21", "safe": "1.0.0"}}
		return scan.New(v, outdated.NewChecker(reg))
	}
}

func baseConfig(out string) config {
	return config{sbomPath: "testdata/bom.json", outPath: out, format: "sarif", concurrency: 4, timeout: time.Minute}
}

func TestRunScan_WritesSARIF(t *testing.T) {
	withFakeScanner(t)

	out := filepath.Join(t.TempDir(), "results.sarif")
	var stdout, stderr bytes.Buffer
	if err := runScan(context.Background(), baseConfig(out), &stdout, &stderr); err != nil {
		t.Fatalf("runScan: %v; stderr:\n%s", err, stderr.String())
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read sarif: %v", err)
	}
	var log map[string]any
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("sarif not valid JSON: %v", err)
	}
	if log["version"] != "2.1.0" {
		t.Errorf("sarif version = %v, want 2.1.0", log["version"])
	}
	if !strings.Contains(string(data), "CVE-2021-23337") {
		t.Errorf("sarif missing expected CVE; got:\n%s", data)
	}
	if !strings.Contains(stderr.String(), "1 must-update") {
		t.Errorf("summary missing from stderr:\n%s", stderr.String())
	}
}

func TestRunScan_FailOnGate(t *testing.T) {
	withFakeScanner(t)

	cfg := baseConfig(filepath.Join(t.TempDir(), "r.sarif"))
	cfg.failOn = string(verdict.LevelMust)

	var stdout, stderr bytes.Buffer
	err := runScan(context.Background(), cfg, &stdout, &stderr)
	if !errors.Is(err, errGate) {
		t.Fatalf("runScan err = %v, want errGate", err)
	}
}

func TestRunScan_TableFormat(t *testing.T) {
	withFakeScanner(t)

	cfg := baseConfig(filepath.Join(t.TempDir(), "r.sarif"))
	cfg.format = "table"

	var stdout, stderr bytes.Buffer
	if err := runScan(context.Background(), cfg, &stdout, &stderr); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if !strings.Contains(stdout.String(), "VERDICT") || !strings.Contains(stdout.String(), "lodash") {
		t.Errorf("table output missing expected content:\n%s", stdout.String())
	}
}

func TestRunScan_DebugLogging(t *testing.T) {
	withFakeScanner(t)

	cfg := baseConfig(filepath.Join(t.TempDir(), "r.sarif"))
	cfg.debug = true

	var stdout, stderr bytes.Buffer
	if err := runScan(context.Background(), cfg, &stdout, &stderr); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if !strings.Contains(stderr.String(), "level=DEBUG") {
		t.Errorf("expected debug records in stderr, got:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "configuration resolved") {
		t.Errorf("expected config debug line in stderr:\n%s", stderr.String())
	}
	// Debug output must never leak into stdout (which may carry SARIF).
	if strings.Contains(stdout.String(), "DEBUG") {
		t.Errorf("debug logs leaked into stdout:\n%s", stdout.String())
	}
}

func TestRunScan_NoDebugByDefault(t *testing.T) {
	withFakeScanner(t)

	var stdout, stderr bytes.Buffer
	if err := runScan(context.Background(), baseConfig(filepath.Join(t.TempDir(), "r.sarif")), &stdout, &stderr); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if strings.Contains(stderr.String(), "level=DEBUG") {
		t.Errorf("debug logs present without --debug:\n%s", stderr.String())
	}
}

func TestRunScan_BadSBOMPath(t *testing.T) {
	withFakeScanner(t)

	cfg := baseConfig("-")
	cfg.sbomPath = "testdata/does-not-exist.json"

	var stdout, stderr bytes.Buffer
	err := runScan(context.Background(), cfg, &stdout, &stderr)
	if err == nil || errors.Is(err, errGate) {
		t.Fatalf("runScan err = %v, want a runtime error", err)
	}
}
