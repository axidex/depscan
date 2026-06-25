package remediate

import "testing"

func dep(group, artifact, version, datasource, file string, line int) DeclaredDependency {
	return DeclaredDependency{Group: group, Artifact: artifact, Version: version, Datasource: datasource, File: file, Line: line}
}

func TestPlanSecurity(t *testing.T) {
	t.Parallel()

	netty := dep("io.netty", "netty-codec-http", "4.1.133.Final", "maven", "build.gradle.kts", 1)
	okio := dep("com.squareup.okio", "okio", "3.10.2", "maven", "build.gradle.kts", 2)
	safe := dep("com.example", "safe", "1.0", "maven", "build.gradle.kts", 3)
	declared := []DeclaredDependency{netty, okio, safe}

	// Normal upgrades: netty → 4.2.20 (latest), okio → 3.12.0.
	normal := []Upgrade{
		{Dep: netty, Target: "4.2.20.Final"},
		{Dep: okio, Target: "3.12.0"},
	}
	// netty is vulnerable, fixed in 4.1.135 and 4.2.15 → minimal upgrade = 4.1.135.
	advisories := map[string]VulnAdvisory{
		AdvisoryKey("maven", "io.netty:netty-codec-http", "4.1.133.Final"): {
			VulnIDs:       []string{"GHSA-x"},
			FixedVersions: []string{"4.2.15.Final", "4.1.135.Final"},
		},
	}

	ups := PlanSecurity(declared, normal, advisories)

	byCoord := map[string]Upgrade{}
	for _, u := range ups {
		byCoord[u.Dep.Coordinate()] = u
	}
	// netty: security upgrade to the MINIMAL fix, flagged, with vuln IDs.
	n := byCoord["io.netty:netty-codec-http"]
	if !n.Security || n.Target != "4.1.135.Final" || len(n.VulnIDs) != 1 {
		t.Errorf("netty = %+v, want security → 4.1.135.Final with vulnIDs", n)
	}
	// okio: untouched normal upgrade.
	if o := byCoord["com.squareup.okio:okio"]; o.Security || o.Target != "3.12.0" {
		t.Errorf("okio = %+v, want plain 3.12.0", o)
	}
	// safe: no advisory, no normal upgrade → absent.
	if _, ok := byCoord["com.example:safe"]; ok {
		t.Error("safe should not be upgraded")
	}
	if len(ups) != 2 {
		t.Fatalf("got %d upgrades, want 2", len(ups))
	}
}
