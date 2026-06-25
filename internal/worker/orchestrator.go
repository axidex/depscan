package worker

import (
	"context"
	"strings"

	"github.com/axidex/craftnovate/internal/remediate"
	"github.com/axidex/craftnovate/internal/sourcecraft"
)

// Action is the outcome of processing one PR group.
type Action string

// Outcomes of processing one PR group.
const (
	ActionCreated     Action = "created"
	ActionExists      Action = "skipped (PR already open)"
	ActionRateLimited Action = "skipped (PR limit reached)"
	ActionError       Action = "error"
)

// PRResult records what happened for one group.
type PRResult struct {
	Group  PRGroup
	Action Action
	PR     *sourcecraft.PullRequest
	Err    error
}

// Platform is the subset of the Sourcecraft client the orchestrator needs (a
// small interface so it can be mocked in tests).
//
//go:generate mockgen -destination mock_platform_test.go -package worker github.com/axidex/craftnovate/internal/worker Platform
type Platform interface {
	ListMyPulls(ctx context.Context) ([]sourcecraft.PullRequest, error)
	CreatePullRequest(ctx context.Context, repoID string, body sourcecraft.CreatePullRequestBody) (*sourcecraft.PullRequest, error)
	SetLabels(ctx context.Context, prID string, slugs []string) error
}

// OpenPRs processes each group: skip if a PR for its branch is already open, or
// if the open-PR limit is reached; otherwise push the branch (edits applied in a
// worktree), open the PR, and apply its labels. maxOpen <= 0 means no limit. The
// authored-PR list is fetched once for both idempotency and the limit count. One
// group's failure never aborts the rest.
func OpenPRs(ctx context.Context, git *Git, plat Platform, repoID, base, remote string, groups []PRGroup, maxOpen int) []PRResult {
	results := make([]PRResult, 0, len(groups))

	openByBranch, openCount, listErr := openState(ctx, plat)

	for _, grp := range groups {
		res := PRResult{Group: grp}
		switch {
		case listErr != nil:
			res.Action, res.Err = ActionError, listErr
		case openByBranch[grp.Branch]:
			res.Action = ActionExists
		case maxOpen > 0 && openCount >= maxOpen:
			res.Action = ActionRateLimited
		default:
			pr, err := open(ctx, git, plat, repoID, base, remote, grp)
			if err != nil {
				res.Action, res.Err = ActionError, err
			} else {
				res.Action, res.PR = ActionCreated, pr
				openCount++
			}
		}
		results = append(results, res)
	}
	return results
}

// openState fetches the caller's open craftnovate PRs once: the set of open
// source branches and how many of our branches are open (for the limit).
func openState(ctx context.Context, plat Platform) (byBranch map[string]bool, count int, err error) {
	pulls, err := plat.ListMyPulls(ctx)
	if err != nil {
		return nil, 0, err
	}
	byBranch = map[string]bool{}
	for _, p := range pulls {
		if !p.IsOpen() {
			continue
		}
		b := p.SourceBranchName()
		byBranch[b] = true
		if strings.HasPrefix(b, BranchPrefix) {
			count++
		}
	}
	return byBranch, count, nil
}

func open(ctx context.Context, git *Git, plat Platform, repoID, base, remote string, grp PRGroup) (*sourcecraft.PullRequest, error) {
	if err := git.PushBranchWithEdits(ctx, base, grp.Branch, grp.Title, remote, func(dir string) error {
		return remediate.ApplyUpgrades(dir, grp.Upgrades)
	}); err != nil {
		return nil, err
	}
	pr, err := plat.CreatePullRequest(ctx, repoID, sourcecraft.CreatePullRequestBody{
		Title:        grp.Title,
		Description:  grp.Body,
		SourceBranch: grp.Branch,
		TargetBranch: base,
		Publish:      true,
	})
	if err != nil {
		return nil, err
	}
	if len(grp.Labels) > 0 {
		// Labels are best-effort: a created PR should not be reported as failed
		// just because labelling did.
		_ = plat.SetLabels(ctx, pr.ID, grp.Labels)
	}
	return pr, nil
}
