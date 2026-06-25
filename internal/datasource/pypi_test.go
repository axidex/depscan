package datasource

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
)

func TestPyPIVersions(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/requests/json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"info":{"version":"2.33.0"},"releases":{"2.31.0":[],"2.32.5":[],"2.33.0":[]}}`))
	}))
	defer srv.Close()

	p := NewPyPI(WithPyPIHTTPClient(srv.Client()), WithPyPIBaseURL(srv.URL))
	got, err := p.Versions(context.Background(), "", "requests")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	sort.Strings(got)
	want := []string{"2.31.0", "2.32.5", "2.33.0"}
	if len(got) != 3 || got[0] != want[0] || got[2] != want[2] {
		t.Errorf("versions = %v, want %v", got, want)
	}
}

func TestPyPIVersions_NotFound(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()
	p := NewPyPI(WithPyPIHTTPClient(srv.Client()), WithPyPIBaseURL(srv.URL))
	if _, err := p.Versions(context.Background(), "", "no-such-pkg"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
