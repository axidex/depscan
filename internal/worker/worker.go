// Package worker ties the pieces together into the pull-request automation for
// the Sourcecraft platform: it groups dependency upgrades into pull requests
// and, on request, pushes a branch per group (via a throwaway git worktree, so
// the user's checkout is never disturbed) and opens the PR through the
// Sourcecraft REST API.
package worker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/axidex/craftnovate/internal/remediate"
)

// BranchPrefix namespaces every branch this tool creates, so they are easy to
// recognize and the idempotency check can match them.
const BranchPrefix = "craftnovate/"

// PRGroup is one pull request: a set of upgrades sharing a branch, plus the
// labels to apply.
type PRGroup struct {
	Coordinate string // the grouping key: a coordinate, or a config groupName
	Branch     string
	Title      string
	Body       string
	Labels     []string
	Upgrades   []remediate.Upgrade
}

// Update pairs an upgrade with its resolved policy (config groupName + labels)
// and the manager label used for ecosystem grouping.
type Update struct {
	Upgrade   remediate.Upgrade
	GroupName string // when set, all updates with this name share one PR
	Manager   string // ecosystem label (e.g. "gradle"/"pypi"/"npm")
	Labels    []string
}

// GroupUpgrades groups upgrades one PR per dependency (no policy). It is the
// policy-free entry used by tests and the simple flow.
func GroupUpgrades(ups []remediate.Upgrade) []PRGroup {
	updates := make([]Update, len(ups))
	for i, u := range ups {
		updates[i] = Update{Upgrade: u}
	}
	return GroupUpdates(updates)
}

// GroupUpdates groups updates one PR per dependency (honoring an explicit config
// groupName). It is GroupUpdatesWith under the per-dependency strategy.
func GroupUpdates(updates []Update) []PRGroup {
	return GroupUpdatesWith(updates, StrategyPerDependency)
}

// branchPart sanitizes a string for use as the leading component of a branch ref
// and strips leading dashes, so a scoped npm name ("@angular") yields a clean
// component ("angular") instead of one beginning with '-'.
func branchPart(s string) string {
	return strings.TrimLeft(sanitizeRef(s), "-")
}

// sanitizeRef makes a string safe for a git branch ref: anything outside
// [A-Za-z0-9._-] becomes '-'.
func sanitizeRef(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// prBodyGroup renders the body for a named group covering several coordinates.
func prBodyGroup(name string, ups []remediate.Upgrade) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Updates the `%s` group.\n\n", name)
	b.WriteString("Changed:\n")
	for _, u := range ups {
		fmt.Fprintf(&b, "- `%s` `%s:%d` (%s → %s)%s\n", u.Dep.Coordinate(), u.Dep.File, u.Dep.Line, u.Dep.Version, u.Target, vulnNote(u))
	}
	b.WriteString("\n---\nOpened by craftnovate.\n")
	return b.String()
}

func prBody(coord string, ups []remediate.Upgrade) string {
	target := ups[0].Target
	var b strings.Builder
	fmt.Fprintf(&b, "Updates `%s` to `%s`.\n\n", coord, target)
	b.WriteString("Changed:\n")
	for _, u := range ups {
		fmt.Fprintf(&b, "- `%s:%d` (%s → %s)%s\n", u.Dep.File, u.Dep.Line, u.Dep.Version, u.Target, vulnNote(u))
	}
	b.WriteString("\n---\nOpened by craftnovate.\n")
	return b.String()
}

// vulnNote renders a security advisory suffix for an upgrade, or "".
func vulnNote(u remediate.Upgrade) string {
	if !u.Security || len(u.VulnIDs) == 0 {
		return ""
	}
	return " — security fix for " + strings.Join(u.VulnIDs, ", ")
}

// parseRemoteURL extracts the org and repo slug from a Sourcecraft git remote,
// supporting both ssh://host/org/repo(.git) and host:org/repo(.git) forms.
func parseRemoteURL(raw string) (org, repo string, err error) {
	s := strings.TrimSpace(raw)
	s = strings.TrimSuffix(s, ".git")
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	switch i := strings.Index(s, ":"); {
	case i >= 0 && !strings.Contains(s[:i], "/"): // scp-style host:path
		s = s[i+1:]
	default:
		if j := strings.Index(s, "/"); j >= 0 { // strip host before first '/'
			s = s[j+1:]
		}
	}
	parts := strings.Split(strings.Trim(s, "/"), "/")
	if len(parts) < 2 || parts[len(parts)-2] == "" || parts[len(parts)-1] == "" {
		return "", "", fmt.Errorf("worker: cannot parse org/repo from remote %q", raw)
	}
	return parts[len(parts)-2], parts[len(parts)-1], nil
}

// --- git plumbing ---

// Git runs git commands inside a working directory.
type Git struct{ dir string }

// NewGit binds a Git runner to dir.
func NewGit(dir string) *Git { return &Git{dir: dir} }

func (g *Git) run(ctx context.Context, args ...string) (string, error) {
	//nolint:gosec // G204: git is invoked with a fixed program and internally-constructed args
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = g.dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// CurrentBranch returns the checked-out branch name.
func (g *Git) CurrentBranch(ctx context.Context) (string, error) {
	return g.run(ctx, "rev-parse", "--abbrev-ref", "HEAD")
}

// RemoteURL returns the URL of the named remote.
func (g *Git) RemoteURL(ctx context.Context, remote string) (string, error) {
	return g.run(ctx, "remote", "get-url", remote)
}

// RepoFromRemote resolves the Sourcecraft org and repo slug from the named git
// remote's URL.
func RepoFromRemote(ctx context.Context, git *Git, remote string) (org, repo string, err error) {
	url, err := git.RemoteURL(ctx, remote)
	if err != nil {
		return "", "", err
	}
	return parseRemoteURL(url)
}

// PushBranchWithEdits creates a throwaway worktree on a fresh branch off base,
// runs apply to edit files there, commits, and force-pushes the branch — leaving
// the caller's working tree untouched. The worktree is always cleaned up.
func (g *Git) PushBranchWithEdits(ctx context.Context, base, branch, message, remote string, apply func(dir string) error) (err error) {
	tmp, err := os.MkdirTemp("", "craftnovate-*")
	if err != nil {
		return fmt.Errorf("worker: mkdtemp: %w", err)
	}
	defer func() {
		_, _ = g.run(ctx, "worktree", "remove", "--force", tmp)
		_, _ = g.run(ctx, "worktree", "prune")
	}()

	if _, err := g.run(ctx, "worktree", "add", "--force", "-B", branch, tmp, base); err != nil {
		return err
	}
	wt := NewGit(tmp)
	if err := apply(tmp); err != nil {
		return fmt.Errorf("worker: apply edits: %w", err)
	}
	if _, err := wt.run(ctx, "commit", "-am", message); err != nil {
		return err
	}
	if _, err := wt.run(ctx, "push", "--force-with-lease", "-u", remote, branch); err != nil {
		return err
	}
	return nil
}
