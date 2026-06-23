package vuln_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axidex/depscan/internal/vuln"
)

// osvServer is a configurable fake OSV API.
type osvServer struct {
	srv          *httptest.Server
	hydrateCount int64 // total GET /vulns/{id} calls (to assert caching)
}

func newOSVServer(t *testing.T) *osvServer {
	t.Helper()
	o := &osvServer{}

	// refs returned by querybatch, keyed by purl. Supports one paginated purl.
	refs := map[string][]map[string]string{
		"pkg:npm/lodash@4.17.20":     {{"id": "CVE-2021-23337", "modified": "2023-01-01T00:00:00Z"}},
		"pkg:npm/leftpad@1.0.0":      {{"id": "CVE-2021-23337", "modified": "2023-01-01T00:00:00Z"}}, // shares ID -> cache test
		"pkg:npm/withdrawnpkg@1.0.0": {{"id": "OSV-WITHDRAWN", "modified": "2023-01-01T00:00:00Z"}},
		"pkg:npm/safe@1.0.0":         {},
	}

	vulns := map[string]map[string]any{
		"CVE-2021-23337": {
			"id":      "GHSA-29mw-wpgm-hmr9",
			"aliases": []string{"CVE-2021-23337"},
			"summary": "Command injection in lodash",
			"severity": []map[string]string{
				{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			},
			"affected": []map[string]any{
				{
					"package": map[string]string{"ecosystem": "npm", "name": "lodash", "purl": "pkg:npm/lodash"},
					"ranges": []map[string]any{
						{"type": "SEMVER", "events": []map[string]string{{"introduced": "0"}, {"fixed": "4.17.21"}}},
					},
				},
			},
		},
		"OSV-WITHDRAWN": {
			"id":        "OSV-WITHDRAWN",
			"withdrawn": "2023-02-01T00:00:00Z",
			"affected":  []map[string]any{},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct {
				Package struct {
					PURL string `json:"purl"`
				} `json:"package"`
				PageToken string `json:"page_token"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		type result struct {
			Vulns         []map[string]string `json:"vulns"`
			NextPageToken string              `json:"next_page_token,omitempty"`
		}
		out := struct {
			Results []result `json:"results"`
		}{}
		for _, q := range req.Queries {
			purl := q.Package.PURL
			// Paginated purl: first page has a token, second page completes.
			if purl == "pkg:npm/paged@1.0.0" {
				if q.PageToken == "" {
					out.Results = append(out.Results, result{
						Vulns:         []map[string]string{{"id": "PAGE-1", "modified": "t"}},
						NextPageToken: "tok2",
					})
				} else {
					out.Results = append(out.Results, result{
						Vulns: []map[string]string{{"id": "PAGE-2", "modified": "t"}},
					})
				}
				continue
			}
			out.Results = append(out.Results, result{Vulns: refs[purl]})
		}
		json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&o.hydrateCount, 1)
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		if id == "PAGE-1" || id == "PAGE-2" {
			json.NewEncoder(w).Encode(map[string]any{"id": id})
			return
		}
		rec, ok := vulns[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(rec)
	})

	o.srv = httptest.NewServer(mux)
	t.Cleanup(o.srv.Close)
	return o
}

func (o *osvServer) client(opts ...vuln.Option) *vuln.OSVClient {
	all := append([]vuln.Option{
		vuln.WithEndpoints(o.srv.URL+"/v1/querybatch", o.srv.URL+"/v1/vulns/"),
		vuln.WithRetries(1, time.Millisecond),
	}, opts...)
	return vuln.NewOSVClient(all...)
}

func TestOSVClient_Query(t *testing.T) {
	t.Parallel()

	o := newOSVServer(t)
	c := o.client()

	got, err := c.Query(context.Background(), []string{"pkg:npm/lodash@4.17.20", "pkg:npm/safe@1.0.0"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}

	if _, ok := got["pkg:npm/safe@1.0.0"]; ok {
		t.Error("safe package should have no result entry")
	}

	res, ok := got["pkg:npm/lodash@4.17.20"]
	if !ok || len(res.Vulns) != 1 {
		t.Fatalf("lodash result = %+v, want 1 vuln", res)
	}
	v := res.Vulns[0]
	if !v.HasFix || len(v.FixedVersions) != 1 || v.FixedVersions[0] != "4.17.21" {
		t.Errorf("vuln fix = (HasFix=%v, %v), want true [4.17.21]", v.HasFix, v.FixedVersions)
	}
	if len(v.CVEs) != 1 || v.CVEs[0] != "CVE-2021-23337" {
		t.Errorf("CVEs = %v, want [CVE-2021-23337]", v.CVEs)
	}
}

func TestOSVClient_HydrationCaching(t *testing.T) {
	t.Parallel()

	o := newOSVServer(t)
	c := o.client()

	// Two purls share the same vuln ID; it must be hydrated exactly once.
	_, err := c.Query(context.Background(), []string{"pkg:npm/lodash@4.17.20", "pkg:npm/leftpad@1.0.0"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if n := atomic.LoadInt64(&o.hydrateCount); n != 1 {
		t.Errorf("hydrateCount = %d, want 1 (shared ID hydrated once)", n)
	}
}

func TestOSVClient_WithdrawnExcluded(t *testing.T) {
	t.Parallel()

	o := newOSVServer(t)
	c := o.client()

	got, err := c.Query(context.Background(), []string{"pkg:npm/withdrawnpkg@1.0.0"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if _, ok := got["pkg:npm/withdrawnpkg@1.0.0"]; ok {
		t.Error("withdrawn vuln must be excluded from results")
	}
}

func TestOSVClient_Pagination(t *testing.T) {
	t.Parallel()

	o := newOSVServer(t)
	c := o.client()

	got, err := c.Query(context.Background(), []string{"pkg:npm/paged@1.0.0"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	res := got["pkg:npm/paged@1.0.0"]
	if len(res.Vulns) != 2 {
		t.Errorf("paged result has %d vulns, want 2 (both pages collected)", len(res.Vulns))
	}
}

func TestOSVClient_EmptyInput(t *testing.T) {
	t.Parallel()

	o := newOSVServer(t)
	c := o.client()

	got, err := c.Query(context.Background(), nil)
	if err != nil {
		t.Fatalf("Query(nil): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Query(nil) = %v, want empty", got)
	}
}
