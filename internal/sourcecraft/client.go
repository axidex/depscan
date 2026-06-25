// Package sourcecraft is a minimal REST client for the Sourcecraft (Yandex
// Cloud) git platform, scoped to what the remediation tool needs: resolve a
// repository, find an already-open pull request (for idempotency), and create a
// new one. Field names mirror the public OpenAPI spec at
// https://api.sourcecraft.tech/sourcecraft.swagger.json.
//
// Auth is a bearer Personal Access Token (in CI, the SOURCECRAFT_TOKEN
// variable). The client is stdlib-only and never panics on a remote error: it
// returns a wrapped error the caller can surface.
package sourcecraft

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL is the production Sourcecraft REST API root.
const DefaultBaseURL = "https://api.sourcecraft.tech"

// maxResponseBytes caps how much of a response body is buffered.
const maxResponseBytes = 8 << 20

// Client talks to the Sourcecraft REST API.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL overrides the API root (for testing or self-hosted instances).
func WithBaseURL(u string) Option {
	return func(c *Client) {
		if u != "" {
			c.baseURL = strings.TrimRight(u, "/")
		}
	}
}

// WithHTTPClient overrides the HTTP client (timeouts, transport, test servers).
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.httpClient = h
		}
	}
}

// New builds a Client authenticated with the given personal access token.
func New(token string, opts ...Option) *Client {
	c := &Client{
		baseURL:    DefaultBaseURL,
		token:      token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// --- wire types (subset of the OpenAPI definitions) ---

// Repository is a Sourcecraft repository.
type Repository struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	DefaultBranch string `json:"default_branch"`
	WebURL        string `json:"web_url"`
}

// PullRequestBranch is the source/target branch descriptor on a pull request.
type PullRequestBranch struct {
	Ref   string `json:"ref"` // a branch name or a "refs/heads/<name>" ref
	Label string `json:"label"`
}

// PullRequest is a Sourcecraft pull request.
type PullRequest struct {
	ID          string            `json:"id"`
	Slug        string            `json:"slug"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Status      string            `json:"status"`
	Source      PullRequestBranch `json:"source"`
	Target      PullRequestBranch `json:"target"`
	// SourceBranch/TargetBranch are the deprecated flat fields; kept because some
	// responses still populate them instead of source/target.
	SourceBranch string `json:"source_branch"`
	TargetBranch string `json:"target_branch"`
}

// SourceBranchName returns the PR's source branch name, from whichever field the
// API populated, stripping a leading "refs/heads/".
func (p PullRequest) SourceBranchName() string {
	if r := strings.TrimPrefix(p.Source.Ref, "refs/heads/"); r != "" {
		return r
	}
	return p.SourceBranch
}

// IsOpen reports whether the PR is still active (not merged or discarded). An
// unknown/empty status is treated as open, so idempotency errs toward skipping
// rather than duplicating.
func (p PullRequest) IsOpen() bool {
	switch strings.ToLower(p.Status) {
	case "merged", "discarded":
		return false
	default:
		return true
	}
}

// CreatePullRequestBody is the request body for creating a pull request. When
// Publish is false the PR is created as a draft (Sourcecraft is draft-first).
type CreatePullRequestBody struct {
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	SourceBranch string   `json:"source_branch"`
	TargetBranch string   `json:"target_branch"`
	ReviewerIDs  []string `json:"reviewer_ids,omitempty"`
	Publish      bool     `json:"publish"`
}

// UpdatePullRequestBody patches a pull request's title and/or description.
type UpdatePullRequestBody struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
}

// MergePullRequestBody controls how a pull request is merged.
type MergePullRequestBody struct {
	Rebase       bool `json:"rebase,omitempty"`
	Squash       bool `json:"squash,omitempty"`
	DeleteBranch bool `json:"delete_branch,omitempty"`
	Force        bool `json:"force,omitempty"`
}

// modifyLabelsBody sets a pull request's labels by slug.
type modifyLabelsBody struct {
	Slugs []string `json:"slugs,omitempty"`
}

type listPullsResponse struct {
	PullRequests  []PullRequest `json:"pull_requests"`
	NextPageToken string        `json:"next_page_token"`
}

// --- API methods ---

// GetRepo resolves a repository by org and repo slug, yielding its ID (needed by
// the id-keyed endpoints) and default branch.
func (c *Client) GetRepo(ctx context.Context, org, repo string) (*Repository, error) {
	path := "/repos/" + url.PathEscape(org) + "/" + url.PathEscape(repo)
	var out Repository
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreatePullRequest opens a pull request in the repo identified by repoID.
func (c *Client) CreatePullRequest(ctx context.Context, repoID string, body CreatePullRequestBody) (*PullRequest, error) {
	path := "/repos/id:" + url.PathEscape(repoID) + "/pulls"
	var out PullRequest
	if err := c.do(ctx, http.MethodPost, path, nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListMyPulls returns pull requests authored by the authenticated user, across
// all pages. It backs idempotency checks (don't reopen a PR we already have).
func (c *Client) ListMyPulls(ctx context.Context) ([]PullRequest, error) {
	return c.listPulls(ctx, "/me/pulls")
}

// ListRepoPulls returns the pull requests of the repo identified by repoID,
// across all pages.
func (c *Client) ListRepoPulls(ctx context.Context, repoID string) ([]PullRequest, error) {
	return c.listPulls(ctx, "/repos/id:"+url.PathEscape(repoID)+"/pulls")
}

func (c *Client) listPulls(ctx context.Context, path string) ([]PullRequest, error) {
	var all []PullRequest
	pageToken := ""
	for {
		q := url.Values{}
		if pageToken != "" {
			q.Set("page_token", pageToken)
		}
		var resp listPullsResponse
		if err := c.do(ctx, http.MethodGet, path, q, nil, &resp); err != nil {
			return nil, err
		}
		all = append(all, resp.PullRequests...)
		if resp.NextPageToken == "" {
			return all, nil
		}
		pageToken = resp.NextPageToken
	}
}

// UpdatePullRequest patches a pull request's title/description.
func (c *Client) UpdatePullRequest(ctx context.Context, prID string, body UpdatePullRequestBody) (*PullRequest, error) {
	var out PullRequest
	if err := c.do(ctx, http.MethodPatch, "/pulls/id:"+url.PathEscape(prID), nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MergePullRequest merges a pull request.
func (c *Client) MergePullRequest(ctx context.Context, prID string, body MergePullRequestBody) error {
	return c.do(ctx, http.MethodPost, "/pulls/id:"+url.PathEscape(prID)+"/merge", nil, body, nil)
}

// SetLabels sets a pull request's labels by slug.
func (c *Client) SetLabels(ctx context.Context, prID string, slugs []string) error {
	return c.do(ctx, http.MethodPost, "/pulls/id:"+url.PathEscape(prID)+"/labels", nil, modifyLabelsBody{Slugs: slugs}, nil)
}

// FindOpenPRBySourceBranch returns the caller's pull request whose source branch
// matches, or nil if none. Used to update-in-place rather than duplicate a PR.
func (c *Client) FindOpenPRBySourceBranch(ctx context.Context, branch string) (*PullRequest, error) {
	pulls, err := c.ListMyPulls(ctx)
	if err != nil {
		return nil, err
	}
	for i := range pulls {
		if pulls[i].IsOpen() && pulls[i].SourceBranchName() == branch {
			return &pulls[i], nil
		}
	}
	return nil, nil
}

// do performs an authenticated JSON request. A non-2xx status is an error
// carrying a snippet of the response body.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	endpoint := c.baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("sourcecraft: encode request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return fmt.Errorf("sourcecraft: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sourcecraft: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("sourcecraft: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sourcecraft: %s %s: status %d: %s", method, path, resp.StatusCode, snippet(data))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("sourcecraft: decode response: %w", err)
		}
	}
	return nil
}

func snippet(b []byte) string {
	const limit = 256
	s := strings.TrimSpace(string(b))
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}
