package sourcecraft

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return New("test-token", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
}

func TestGetRepo(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/repos/org/repo" {
			t.Errorf("path = %s, want /repos/org/repo", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("auth header = %q, want %q", got, "Bearer test-token")
		}
		_ = json.NewEncoder(w).Encode(Repository{ID: "r1", Slug: "repo", DefaultBranch: "main"})
	})

	repo, err := c.GetRepo(context.Background(), "org", "repo")
	if err != nil {
		t.Fatalf("GetRepo: %v", err)
	}
	if repo.ID != "r1" || repo.DefaultBranch != "main" {
		t.Errorf("repo = %+v, want id=r1 default_branch=main", repo)
	}
}

func TestCreatePullRequest(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/repos/id:r1/pulls" {
			t.Errorf("path = %s, want /repos/id:r1/pulls", r.URL.Path)
		}
		var body CreatePullRequestBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.SourceBranch != "depscan/bump-bcpkix" || body.TargetBranch != "main" {
			t.Errorf("branches = %s -> %s, want depscan/bump-bcpkix -> main", body.SourceBranch, body.TargetBranch)
		}
		if !body.Publish {
			t.Error("publish = false, want true")
		}
		_ = json.NewEncoder(w).Encode(PullRequest{ID: "pr1", Title: body.Title, Status: "OPEN"})
	})

	pr, err := c.CreatePullRequest(context.Background(), "r1", CreatePullRequestBody{
		Title:        "Bump bcpkix",
		SourceBranch: "depscan/bump-bcpkix",
		TargetBranch: "main",
		Publish:      true,
	})
	if err != nil {
		t.Fatalf("CreatePullRequest: %v", err)
	}
	if pr.ID != "pr1" {
		t.Errorf("pr.ID = %q, want pr1", pr.ID)
	}
}

func TestFindOpenPRBySourceBranch_Paginates(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page_token") {
		case "":
			_ = json.NewEncoder(w).Encode(listPullsResponse{
				PullRequests:  []PullRequest{{ID: "a", Source: PullRequestBranch{Ref: "refs/heads/other"}}},
				NextPageToken: "p2",
			})
		case "p2":
			_ = json.NewEncoder(w).Encode(listPullsResponse{
				PullRequests: []PullRequest{{ID: "b", SourceBranch: "depscan/target"}},
			})
		default:
			t.Errorf("unexpected page_token %q", r.URL.Query().Get("page_token"))
		}
	})

	pr, err := c.FindOpenPRBySourceBranch(context.Background(), "depscan/target")
	if err != nil {
		t.Fatalf("FindOpenPRBySourceBranch: %v", err)
	}
	if pr == nil || pr.ID != "b" {
		t.Fatalf("pr = %+v, want id=b (found via deprecated source_branch field on page 2)", pr)
	}
}

func TestUpdatePullRequest(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/pulls/id:pr1" {
			t.Errorf("got %s %s, want PATCH /pulls/id:pr1", r.Method, r.URL.Path)
		}
		var body UpdatePullRequestBody
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Title != "new title" {
			t.Errorf("title = %q", body.Title)
		}
		_ = json.NewEncoder(w).Encode(PullRequest{ID: "pr1", Title: body.Title})
	})
	pr, err := c.UpdatePullRequest(context.Background(), "pr1", UpdatePullRequestBody{Title: "new title"})
	if err != nil || pr.Title != "new title" {
		t.Fatalf("UpdatePullRequest: pr=%+v err=%v", pr, err)
	}
}

func TestMergeAndSetLabels(t *testing.T) {
	t.Parallel()
	var merged, labeled bool
	c := newTestClient(t, func(_ http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pulls/id:pr1/merge":
			merged = true
			var b MergePullRequestBody
			_ = json.NewDecoder(r.Body).Decode(&b)
			if !b.DeleteBranch {
				t.Error("delete_branch should be true")
			}
		case "/pulls/id:pr1/labels":
			labeled = true
			var b modifyLabelsBody
			_ = json.NewDecoder(r.Body).Decode(&b)
			if len(b.Slugs) != 1 || b.Slugs[0] != "dependencies" {
				t.Errorf("slugs = %v", b.Slugs)
			}
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	if err := c.MergePullRequest(context.Background(), "pr1", MergePullRequestBody{DeleteBranch: true}); err != nil {
		t.Fatalf("MergePullRequest: %v", err)
	}
	if err := c.SetLabels(context.Background(), "pr1", []string{"dependencies"}); err != nil {
		t.Fatalf("SetLabels: %v", err)
	}
	if !merged || !labeled {
		t.Errorf("merged=%v labeled=%v, want both true", merged, labeled)
	}
}

func TestListRepoPulls(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/id:r1/pulls" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(listPullsResponse{PullRequests: []PullRequest{{ID: "a"}, {ID: "b"}}})
	})
	pulls, err := c.ListRepoPulls(context.Background(), "r1")
	if err != nil || len(pulls) != 2 {
		t.Fatalf("ListRepoPulls: pulls=%v err=%v", pulls, err)
	}
}

func TestDo_ErrorStatusIncludesBody(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"forbidden"}`)
	})

	_, err := c.GetRepo(context.Background(), "org", "repo")
	if err == nil {
		t.Fatal("expected error on 403")
	}
	if want := "status 403"; !contains(err.Error(), want) {
		t.Errorf("error = %q, want it to contain %q", err.Error(), want)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
