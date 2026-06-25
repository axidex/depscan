package worker

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/mock/gomock"

	"github.com/axidex/depscan/internal/remediate"
	"github.com/axidex/depscan/internal/sourcecraft"
)

func up(group, artifact, version, target, file string, line int) remediate.Upgrade {
	return remediate.Upgrade{
		Dep:    remediate.DeclaredDependency{Group: group, Artifact: artifact, Version: version, File: file, Line: line},
		Target: target,
	}
}

func TestGroupUpgrades(t *testing.T) {
	t.Parallel()

	ups := []remediate.Upgrade{
		up("com.squareup.okio", "okio", "3.10.2", "3.12.0", "appsec-backend/build.gradle.kts", 171),
		up("com.squareup.okio", "okio", "3.10.2", "3.12.0", "appsec-common/build.gradle.kts", 14),
		up("org.bouncycastle", "bcpkix-jdk18on", "1.79", "1.80", "appsec-backend/build.gradle.kts", 197),
	}

	groups := GroupUpgrades(ups)
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2 (one per coordinate)", len(groups))
	}

	// Deterministic, sorted by coordinate: okio before org.bouncycastle.
	okio := groups[0]
	if okio.Coordinate != "com.squareup.okio:okio" {
		t.Fatalf("first group = %q", okio.Coordinate)
	}
	if okio.Branch != "depscan/com.squareup.okio-okio-3.12.0" {
		t.Errorf("okio branch = %q", okio.Branch)
	}
	if !strings.Contains(okio.Title, "com.squareup.okio:okio") || !strings.Contains(okio.Title, "3.12.0") {
		t.Errorf("okio title = %q", okio.Title)
	}
	// Body must list both occurrence sites.
	if !strings.Contains(okio.Body, "appsec-backend/build.gradle.kts:171") ||
		!strings.Contains(okio.Body, "appsec-common/build.gradle.kts:14") {
		t.Errorf("okio body missing a site:\n%s", okio.Body)
	}
	if len(okio.Upgrades) != 2 {
		t.Errorf("okio group has %d upgrades, want 2", len(okio.Upgrades))
	}
}

func TestSanitizeRef(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"io.netty:netty-codec-http": "io.netty-netty-codec-http",
		"4.2.15.Final":              "4.2.15.Final",
		"g:a:b":                     "g-a-b",
	}
	for in, want := range tests {
		if got := sanitizeRef(in); got != want {
			t.Errorf("sanitizeRef(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseRemoteURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		raw, org, repo string
	}{
		{"ssh://git.example.com/org/repo.git", "org", "repo"},
		{"ssh://ssh.o.cloud-preprod.yandex.net/pub-axidex/appsec-mirror.git", "pub-axidex", "appsec-mirror"},
		{"git@github.com:axidex/depscan.git", "axidex", "depscan"},
		{"https://host/org/repo", "org", "repo"},
	}
	for _, tt := range tests {
		org, repo, err := parseRemoteURL(tt.raw)
		if err != nil {
			t.Errorf("parseRemoteURL(%q): %v", tt.raw, err)
			continue
		}
		if org != tt.org || repo != tt.repo {
			t.Errorf("parseRemoteURL(%q) = %s/%s, want %s/%s", tt.raw, org, repo, tt.org, tt.repo)
		}
	}
}

// TestOpenPRs_Idempotency verifies that a group whose branch already has an open
// PR is skipped: ListMyPulls reports it and CreatePullRequest is never expected,
// so gomock fails the test if the orchestrator tries to open a duplicate.
func TestOpenPRs_Idempotency(t *testing.T) {
	t.Parallel()

	groups := GroupUpgrades([]remediate.Upgrade{
		up("org.bouncycastle", "bcpkix-jdk18on", "1.79", "1.80", "build.gradle.kts", 1),
	})

	ctrl := gomock.NewController(t)
	plat := NewMockPlatform(ctrl)
	plat.EXPECT().ListMyPulls(gomock.Any()).Return([]sourcecraft.PullRequest{
		{ID: "existing", Status: "open", Source: sourcecraft.PullRequestBranch{Ref: groups[0].Branch}},
	}, nil)
	// No CreatePullRequest expectation: gomock fails if it is called.

	results := OpenPRs(context.Background(), nil, plat, "repo1", "main", "origin", groups, 0)
	if len(results) != 1 || results[0].Action != ActionExists {
		t.Fatalf("results = %+v, want one ActionExists", results)
	}
}

// TestOpenPRs_RateLimit verifies that, with an open-PR limit already reached, a
// new group is skipped without creating a PR.
func TestOpenPRs_RateLimit(t *testing.T) {
	t.Parallel()

	groups := GroupUpgrades([]remediate.Upgrade{
		up("com.squareup.okio", "okio", "3.10.2", "3.12.0", "build.gradle.kts", 1),
	})

	ctrl := gomock.NewController(t)
	plat := NewMockPlatform(ctrl)
	// One of our PRs is already open (a different branch) → count = 1, limit = 1.
	plat.EXPECT().ListMyPulls(gomock.Any()).Return([]sourcecraft.PullRequest{
		{ID: "x", Status: "open", Source: sourcecraft.PullRequestBranch{Ref: BranchPrefix + "other-1.0"}},
	}, nil)

	results := OpenPRs(context.Background(), nil, plat, "repo1", "main", "origin", groups, 1)
	if len(results) != 1 || results[0].Action != ActionRateLimited {
		t.Fatalf("results = %+v, want one ActionRateLimited", results)
	}
}
