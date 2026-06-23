// Package sarif renders depscan verdicts into a SARIF 2.1.0 report so results
// surface in code-host security tabs. Only components with a non-ok verdict
// produce a result; must-update maps to error, should-update to warning.
package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/axidex/depscan/internal/purl"
	"github.com/axidex/depscan/internal/verdict"
)

// SchemaURI is the canonical OASIS SARIF 2.1.0 schema URL.
const SchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

const (
	ruleVuln     = "vulnerable-dependency"
	ruleOutdated = "outdated-dependency"
)

// ToolMeta describes the analysis tool in the SARIF driver block.
type ToolMeta struct {
	Name           string
	Version        string
	InformationURI string
}

// --- SARIF document model ---

// Log is the root SARIF object.
type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name,omitempty"`
	ShortDescription     *Message       `json:"shortDescription,omitempty"`
	FullDescription      *Message       `json:"fullDescription,omitempty"`
	HelpURI              string         `json:"helpUri,omitempty"`
	DefaultConfiguration *RuleConfig    `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any `json:"properties,omitempty"`
}

type RuleConfig struct {
	Level string `json:"level"`
}

type Result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             Message           `json:"message"`
	Locations           []Location        `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type Message struct {
	Text string `json:"text"`
}

type Location struct {
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
}

type LogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

// Build assembles a SARIF Log from the verdicts. Verdicts with LevelOK are
// omitted. Rules are de-duplicated by (problem type, version-less purl).
func Build(verdicts []verdict.Verdict, meta ToolMeta) Log {
	rules := []Rule{}
	ruleIndex := map[string]int{}
	results := []Result{}

	for _, v := range verdicts {
		if v.Level == verdict.LevelOK {
			continue
		}

		problemType := ruleOutdated
		if len(v.Vulns) > 0 {
			problemType = ruleVuln
		}

		base := versionlessPURL(v.Component.PURL, v.Component.Name)
		ruleID := problemType + "/" + base

		idx, ok := ruleIndex[ruleID]
		if !ok {
			idx = len(rules)
			ruleIndex[ruleID] = idx
			rules = append(rules, buildRule(ruleID, problemType, base))
		}

		results = append(results, buildResult(v, ruleID, idx, problemType))
	}

	return Log{
		Schema:  SchemaURI,
		Version: "2.1.0",
		Runs: []Run{
			{
				Tool: Tool{Driver: Driver{
					Name:           meta.Name,
					Version:        meta.Version,
					InformationURI: meta.InformationURI,
					Rules:          rules,
				}},
				Results: results,
			},
		},
	}
}

// Write marshals a Log as indented JSON to w.
func Write(w io.Writer, log Log) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("sarif: encode: %w", err)
	}
	return nil
}

// Render builds and writes a SARIF report in one step.
func Render(w io.Writer, verdicts []verdict.Verdict, meta ToolMeta) error {
	return Write(w, Build(verdicts, meta))
}

func buildRule(ruleID, problemType, base string) Rule {
	rule := Rule{
		ID:                   ruleID,
		DefaultConfiguration: &RuleConfig{Level: "warning"},
		Properties:           map[string]any{"problem.type": problemType, "package": base},
	}
	if problemType == ruleVuln {
		rule.Name = "VulnerableDependency"
		rule.ShortDescription = &Message{Text: "Dependency has known vulnerabilities"}
		rule.FullDescription = &Message{Text: fmt.Sprintf("%s has one or more known vulnerabilities reported by OSV.dev.", base)}
		rule.HelpURI = "https://osv.dev/list"
		rule.DefaultConfiguration.Level = "error"
	} else {
		rule.Name = "OutdatedDependency"
		rule.ShortDescription = &Message{Text: "A newer version of the dependency is available"}
		rule.FullDescription = &Message{Text: fmt.Sprintf("%s is behind the latest version published in its registry.", base)}
		rule.HelpURI = "https://github.com/axidex/depscan"
	}
	return rule
}

func buildResult(v verdict.Verdict, ruleID string, ruleIdx int, problemType string) Result {
	cves := verdict.CVEs(v.Vulns)
	vulnIDs := verdict.VulnIDs(v.Vulns)

	props := map[string]any{
		"currentVersion": v.Component.Version,
		"updateType":     string(v.Outdated.Kind),
		"hasFix":         v.HasFix,
		"ecosystem":      ecosystemOf(v.Component.PURL),
		"purl":           v.Component.PURL,
	}
	if v.Outdated.Known() {
		props["latestVersion"] = v.Outdated.Latest
	}
	if v.TargetVersion != "" {
		props["recommendedVersion"] = v.TargetVersion
	}
	if len(cves) > 0 {
		props["cveIds"] = cves
	}
	if len(vulnIDs) > 0 {
		props["vulnIds"] = vulnIDs
	}

	return Result{
		RuleID:    ruleID,
		RuleIndex: ruleIdx,
		Level:     levelFor(v.Level),
		Message:   Message{Text: messageFor(v)},
		Locations: []Location{
			{LogicalLocations: []LogicalLocation{{Name: locationName(v), Kind: "package"}}},
		},
		PartialFingerprints: map[string]string{
			"depscan/v1": fingerprint(problemType, locationName(v)),
		},
		Properties: props,
	}
}

func levelFor(l verdict.Level) string {
	if l == verdict.LevelMust {
		return "error"
	}
	return "warning"
}

func messageFor(v verdict.Verdict) string {
	coord := v.Component.Name
	if v.Component.Version != "" {
		coord += "@" + v.Component.Version
	}
	reasons := strings.Join(v.Reasons, "; ")
	if reasons == "" {
		reasons = string(v.Level)
	}
	return fmt.Sprintf("%s: %s", coord, reasons)
}

func locationName(v verdict.Verdict) string {
	if v.Component.PURL != "" {
		return v.Component.PURL
	}
	if v.Component.Version != "" {
		return v.Component.Name + "@" + v.Component.Version
	}
	return v.Component.Name
}

func versionlessPURL(raw, fallback string) string {
	if p, err := purl.Parse(raw); err == nil {
		return p.WithoutVersion()
	}
	return fallback
}

func ecosystemOf(raw string) string {
	if p, err := purl.Parse(raw); err == nil {
		return p.Type
	}
	return ""
}

// fingerprint derives a stable dedup key for a finding. It is keyed only on the
// problem type and the component's versioned identity — deliberately NOT on the
// vuln-ID set or update kind — so that (a) two versions of the same package
// produce distinct fingerprints, and (b) the fingerprint stays constant for an
// unchanged dependency even as OSV adds CVEs or a newer release ships, keeping
// code-host alert continuity intact.
func fingerprint(problemType, identity string) string {
	h := sha256.New()
	io.WriteString(h, problemType)
	io.WriteString(h, "|")
	io.WriteString(h, identity)
	return hex.EncodeToString(h.Sum(nil))[:16]
}
