package vuln

import (
	"reflect"
	"testing"
)

func TestToVuln_SemverFix(t *testing.T) {
	t.Parallel()

	record := osvVuln{
		ID:      "GHSA-29mw-wpgm-hmr9",
		Aliases: []string{"CVE-2021-23337"},
		Summary: "Command injection in lodash",
		Severity: []osvSeverity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
		Affected: []osvAffected{
			{
				Package: osvAffectedPackage{Ecosystem: "npm", Name: "lodash", PURL: "pkg:npm/lodash"},
				Ranges: []osvRange{
					{
						Type:   "SEMVER",
						Events: []osvEvent{{Introduced: "0"}, {Fixed: "4.17.21"}},
					},
				},
			},
			{
				// Different ecosystem in the same advisory must be ignored.
				Package: osvAffectedPackage{Ecosystem: "Maven", Name: "other", PURL: "pkg:maven/x/other"},
				Ranges: []osvRange{
					{Type: "ECOSYSTEM", Events: []osvEvent{{Fixed: "9.9.9"}}},
				},
			},
		},
	}

	got := toVuln(record, "pkg:npm/lodash@4.17.20")

	if !got.HasFix {
		t.Error("HasFix = false, want true")
	}
	if !reflect.DeepEqual(got.FixedVersions, []string{"4.17.21"}) {
		t.Errorf("FixedVersions = %v, want [4.17.21] (must not include other-ecosystem fix)", got.FixedVersions)
	}
	if !reflect.DeepEqual(got.CVEs, []string{"CVE-2021-23337"}) {
		t.Errorf("CVEs = %v, want [CVE-2021-23337]", got.CVEs)
	}
	if got.Severity == "" {
		t.Error("Severity is empty, want CVSS string")
	}
}

func TestToVuln_GitRangeFix(t *testing.T) {
	t.Parallel()

	// GIT ranges carry a commit SHA in events.fixed but a real version in
	// database_specific.versions.
	record := osvVuln{
		ID: "CVE-2023-26159",
		Affected: []osvAffected{
			{
				Package: osvAffectedPackage{Ecosystem: "npm", Name: "follow-redirects", PURL: "pkg:npm/follow-redirects"},
				Ranges: []osvRange{
					{
						Type:   "GIT",
						Events: []osvEvent{{Introduced: "0"}, {Fixed: "65858205e59f1e23c9bf173348a7a7cbb8ac47f5"}},
						DatabaseSpecific: osvRangeDatabaseExtra{
							Versions: []osvEvent{{Introduced: "0"}, {Fixed: "1.15.4"}},
						},
					},
				},
			},
		},
	}

	got := toVuln(record, "pkg:npm/follow-redirects@1.15.0")

	if !got.HasFix {
		t.Error("HasFix = false, want true")
	}
	// Must pick up the version, never the commit SHA.
	if !reflect.DeepEqual(got.FixedVersions, []string{"1.15.4"}) {
		t.Errorf("FixedVersions = %v, want [1.15.4]", got.FixedVersions)
	}
}

func TestToVuln_NoFix(t *testing.T) {
	t.Parallel()

	record := osvVuln{
		ID: "GHSA-nofix",
		Affected: []osvAffected{
			{
				Package: osvAffectedPackage{Ecosystem: "npm", Name: "lodash", PURL: "pkg:npm/lodash"},
				Ranges: []osvRange{
					{Type: "SEMVER", Events: []osvEvent{{Introduced: "0"}}}, // introduced only
				},
			},
		},
	}

	got := toVuln(record, "pkg:npm/lodash@4.17.20")
	if got.HasFix {
		t.Errorf("HasFix = true, want false (no fixed event); FixedVersions=%v", got.FixedVersions)
	}
}

func TestToVuln_MavenNoPurlMatch(t *testing.T) {
	t.Parallel()

	// OSV Maven affected entries identify the package as "groupId:artifactId"
	// and may omit the optional purl field. The fix version must still match.
	record := osvVuln{
		ID: "CVE-2023-2976",
		Affected: []osvAffected{
			{
				Package: osvAffectedPackage{Ecosystem: "Maven", Name: "com.google.guava:guava"},
				Ranges: []osvRange{
					{Type: "ECOSYSTEM", Events: []osvEvent{{Introduced: "1.0"}, {Fixed: "32.0.0-android"}}},
				},
			},
		},
	}

	got := toVuln(record, "pkg:maven/com.google.guava/guava@30.0-jre")
	if !got.HasFix {
		t.Errorf("HasFix = false, want true (maven colon-form name should match)")
	}
	if len(got.FixedVersions) != 1 || got.FixedVersions[0] != "32.0.0-android" {
		t.Errorf("FixedVersions = %v, want [32.0.0-android]", got.FixedVersions)
	}
}

func TestToVuln_PyPINameNormalization(t *testing.T) {
	t.Parallel()

	// PyPI names are PEP 503 normalized by OSV (dots/underscores -> dash).
	// The queried purl may carry a dotted name; matching must normalize both.
	for _, tc := range []struct {
		name        string
		affectedPkg osvAffectedPackage
	}{
		{name: "with purl", affectedPkg: osvAffectedPackage{Ecosystem: "PyPI", Name: "flask-sqlalchemy", PURL: "pkg:pypi/flask-sqlalchemy"}},
		{name: "no purl", affectedPkg: osvAffectedPackage{Ecosystem: "PyPI", Name: "flask-sqlalchemy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			record := osvVuln{
				ID: "GHSA-pypi",
				Affected: []osvAffected{
					{
						Package: tc.affectedPkg,
						Ranges:  []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Fixed: "3.0.0"}}}},
					},
				},
			}
			got := toVuln(record, "pkg:pypi/Flask.SQLAlchemy@2.0.0")
			if !got.HasFix || len(got.FixedVersions) != 1 || got.FixedVersions[0] != "3.0.0" {
				t.Errorf("PyPI dotted-name match failed: HasFix=%v FixedVersions=%v", got.HasFix, got.FixedVersions)
			}
		})
	}
}

func TestEcosystemToType(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"npm":           "npm",
		"PyPI":          "pypi",
		"Maven":         "maven",
		"Go":            "golang",
		"crates.io":     "cargo",
		"RubyGems":      "gem",
		"NuGet":         "nuget",
		"Packagist":     "composer",
		"Alpine:v3.16":  "alpine",
		"Unknown-Thing": "unknown-thing",
	}
	for in, want := range tests {
		if got := ecosystemToType(in); got != want {
			t.Errorf("ecosystemToType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBestSeverity(t *testing.T) {
	t.Parallel()

	sev := []osvSeverity{
		{Type: "CVSS_V2", Score: "v2"},
		{Type: "CVSS_V4", Score: "v4"},
		{Type: "CVSS_V3", Score: "v3"},
	}
	if got := bestSeverity(sev); got != "v4" {
		t.Errorf("bestSeverity = %q, want v4 (highest CVSS version)", got)
	}
	if got := bestSeverity(nil); got != "" {
		t.Errorf("bestSeverity(nil) = %q, want empty", got)
	}
}
