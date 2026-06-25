package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/axidex/craftnovate/internal/versioning"
)

// maven is the versioning used across config tests (Maven semantics).
var maven = versioning.Maven{}

func TestLoadAndMerge(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	cfgJSON := `{
		"ignoreUnstable": false,
		"ignoreDeps": ["com.example:legacy"],
		"groupStrategy": "ecosystem",
		"packageRules": [
			{"matchUpdateTypes": ["major"], "enabled": false},
			{"matchPackagePrefixes": ["org.junit"], "allowedVersions": "<5.13"}
		]
	}`
	if err := os.WriteFile(filepath.Join(root, "craftnovate.json"), []byte(cfgJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// file overrides default ignoreUnstable; enabled default (true) preserved.
	if deref(cfg.IgnoreUnstable, true) != false {
		t.Error("ignoreUnstable should be false after merge")
	}
	if deref(cfg.Enabled, false) != true {
		t.Error("enabled should default to true")
	}
	if len(cfg.PackageRules) != 2 {
		t.Fatalf("got %d rules, want 2", len(cfg.PackageRules))
	}
	if cfg.GroupStrategy != "ecosystem" {
		t.Errorf("groupStrategy = %q, want ecosystem", cfg.GroupStrategy)
	}
}

func TestLoad_NoFile(t *testing.T) {
	t.Parallel()
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !deref(cfg.Enabled, false) || !deref(cfg.IgnoreUnstable, false) {
		t.Errorf("missing config should yield defaults, got %+v", cfg)
	}
}

func TestRuleMatches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule PackageRule
		pc   PackageContext
		want bool
	}{
		{"exact name", PackageRule{MatchPackageNames: []string{"io.netty:netty-codec"}}, PackageContext{Name: "io.netty:netty-codec"}, true},
		{"artifact tail", PackageRule{MatchPackageNames: []string{"netty-codec"}}, PackageContext{Name: "io.netty:netty-codec"}, true},
		{"regex", PackageRule{MatchPackageNames: []string{"/^io\\.netty:/"}}, PackageContext{Name: "io.netty:netty-codec"}, true},
		{"prefix", PackageRule{MatchPackagePrefixes: []string{"org.junit"}}, PackageContext{Name: "org.junit.jupiter:junit-jupiter"}, true},
		{"prefix miss", PackageRule{MatchPackagePrefixes: []string{"org.junit"}}, PackageContext{Name: "io.netty:x"}, false},
		{"updateType major", PackageRule{MatchUpdateTypes: []string{"major"}}, PackageContext{Name: "g:a", Current: "1.0.0", Target: "2.0.0"}, true},
		{"updateType mismatch", PackageRule{MatchUpdateTypes: []string{"major"}}, PackageContext{Name: "g:a", Current: "1.0.0", Target: "1.1.0"}, false},
		{"AND across selectors", PackageRule{MatchManagers: []string{"gradle"}, MatchPackagePrefixes: []string{"org.junit"}}, PackageContext{Manager: "gradle", Name: "org.junit:x"}, true},
		{"AND fails one", PackageRule{MatchManagers: []string{"npm"}, MatchPackagePrefixes: []string{"org.junit"}}, PackageContext{Manager: "gradle", Name: "org.junit:x"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.rule.Matches(maven, tt.pc); got != tt.want {
				t.Errorf("Matches = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllowedVersionsMatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		constraint, version string
		want                bool
	}{
		{"", "9.9", true},
		{"<5.13", "5.12.2", true},
		{"<5.13", "5.13.0", false}, // 5.13.0 == 5.13, not strictly less
		{"<5.13", "5.13.1", false},
		{"<5.13", "5.13.0-M3", true}, // a pre-release of 5.13 sorts BELOW 5.13 in Maven order
		{"<=1.84", "1.84", true},
		{">=2.0", "1.9", false},
		{"=1.2.3", "1.2.3", true},
		{"=1.2.3", "1.2.4", false},
		{"/.*\\.Final$/", "4.2.15.Final", true},
		{"/.*\\.Final$/", "4.2.15.CR1", false},
	}
	for _, tt := range tests {
		if got := AllowedVersionsMatch(maven, tt.constraint, tt.version); got != tt.want {
			t.Errorf("AllowedVersionsMatch(%q, %q) = %v, want %v", tt.constraint, tt.version, got, tt.want)
		}
	}
}

func TestSelector(t *testing.T) {
	t.Parallel()

	candidates := []string{"5.10.0", "5.12.2", "5.13.0-M3", "6.0.0"}

	tests := []struct {
		name    string
		cfg     Config
		current string
		want    string
	}{
		{
			name:    "default: newest stable (rejects M3 milestone), allows major",
			cfg:     Defaults(),
			current: "5.10.0",
			want:    "6.0.0",
		},
		{
			name:    "disable major bumps via matchUpdateTypes",
			cfg:     Defaults().Merge(Config{PackageRules: []PackageRule{{MatchUpdateTypes: []string{"major"}, Enabled: new(false)}}}),
			current: "5.10.0",
			want:    "5.12.2", // major (6.0.0) disabled; M3 unstable; → 5.12.2
		},
		{
			name:    "allowedVersions caps below 6",
			cfg:     Defaults().Merge(Config{AllowedVersions: "<6"}),
			current: "5.10.0",
			want:    "5.12.2",
		},
		{
			name:    "ignoreUnstable=false lets the milestone through when it is newest under cap",
			cfg:     Defaults().Merge(Config{IgnoreUnstable: new(false), AllowedVersions: "<6"}),
			current: "5.10.0",
			want:    "5.13.0-M3",
		},
		{
			name:    "ignoreDeps disables entirely",
			cfg:     Defaults().Merge(Config{IgnoreDeps: []string{"org.junit.jupiter:junit-jupiter"}}),
			current: "5.10.0",
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sel := NewSelector(tt.cfg, "gradle")
			got, ok := sel.Select(maven, "org.junit.jupiter:junit-jupiter", tt.current, candidates)
			if tt.want == "" {
				if ok {
					t.Errorf("expected skip, got %q", got)
				}
				return
			}
			if !ok || got != tt.want {
				t.Errorf("Select = %q (ok=%v), want %q", got, ok, tt.want)
			}
		})
	}
}
