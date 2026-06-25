package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestQuery(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/querybatch"):
			// One query (netty) → one vuln; the other (safe) → none.
			body := readAll(r)
			if !strings.Contains(body, "netty-codec-http") {
				t.Errorf("querybatch missing netty purl: %s", body)
			}
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-x"}]},{}]}`))
		case strings.HasSuffix(r.URL.Path, "/vulns/GHSA-x"):
			_, _ = w.Write([]byte(`{"id":"GHSA-x","affected":[
				{"package":{"ecosystem":"Maven","name":"io.netty:netty-codec-http"},
				 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.2.15.Final"}]}]}
			]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := New(WithHTTPClient(srv.Client()), WithEndpoints(srv.URL+"/v1/querybatch", srv.URL+"/v1/vulns/"))
	adv, err := c.Query(context.Background(), []Coordinate{
		{Ecosystem: "maven", Name: "io.netty:netty-codec-http", Version: "4.1.133.Final"},
		{Ecosystem: "maven", Name: "com.example:safe", Version: "1.0"},
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	key := Coordinate{Ecosystem: "maven", Name: "io.netty:netty-codec-http", Version: "4.1.133.Final"}.Key()
	got, ok := adv[key]
	if !ok {
		t.Fatalf("no advisory for netty; got %v", adv)
	}
	if len(got.VulnIDs) != 1 || got.VulnIDs[0] != "GHSA-x" {
		t.Errorf("vulnIDs = %v", got.VulnIDs)
	}
	if len(got.FixedVersions) != 1 || got.FixedVersions[0] != "4.2.15.Final" {
		t.Errorf("fixed = %v, want [4.2.15.Final]", got.FixedVersions)
	}
	if len(adv) != 1 {
		t.Errorf("expected only netty to be vulnerable, got %d advisories", len(adv))
	}
}

func TestQuery_PyPINormalization(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/querybatch") {
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"PYSEC-1"}]}]}`))
			return
		}
		// OSV name uses underscores; the query used a dotted/normalized name.
		_, _ = w.Write([]byte(`{"id":"PYSEC-1","affected":[
			{"package":{"ecosystem":"PyPI","name":"Flask_Cors"},
			 "ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"4.0.1"}]}]}]}`))
	}))
	defer srv.Close()

	c := New(WithHTTPClient(srv.Client()), WithEndpoints(srv.URL+"/v1/querybatch", srv.URL+"/v1/vulns/"))
	adv, err := c.Query(context.Background(), []Coordinate{{Ecosystem: "pypi", Name: "flask-cors", Version: "4.0.0"}})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(adv) != 1 {
		t.Fatalf("PEP 503 name normalization failed to match: %v", adv)
	}
}

func readAll(r *http.Request) string {
	b := make([]byte, r.ContentLength)
	_, _ = r.Body.Read(b)
	return string(b)
}
