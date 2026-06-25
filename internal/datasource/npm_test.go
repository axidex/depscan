package datasource

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
)

func TestNPMVersions(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lodash" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"name":"lodash","versions":{"4.17.20":{},"4.17.21":{}}}`))
	}))
	defer srv.Close()

	n := NewNPM(WithNPMHTTPClient(srv.Client()), WithNPMBaseURL(srv.URL))
	got, err := n.Versions(context.Background(), "", "lodash")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	sort.Strings(got)
	if len(got) != 2 || got[0] != "4.17.20" || got[1] != "4.17.21" {
		t.Errorf("versions = %v, want [4.17.20 4.17.21]", got)
	}
}

func TestNPMVersions_NotFound(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()
	n := NewNPM(WithNPMHTTPClient(srv.Client()), WithNPMBaseURL(srv.URL))
	if _, err := n.Versions(context.Background(), "", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
