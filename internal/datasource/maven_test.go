package datasource

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMavenVersions(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if got := q.Get("q"); got != "g:io.netty AND a:netty-codec-http" {
			t.Errorf("q = %q", got)
		}
		if q.Get("core") != "gav" {
			t.Errorf("core = %q, want gav", q.Get("core"))
		}
		_, _ = w.Write([]byte(`{"response":{"numFound":3,"docs":[
			{"v":"4.2.15.Final"},{"v":"4.2.1.Final"},{"v":"4.1.133.Final"}
		]}}`))
	}))
	defer srv.Close()

	m := NewMaven(WithHTTPClient(srv.Client()), WithSearchURL(srv.URL))
	got, err := m.Versions(context.Background(), "io.netty", "netty-codec-http")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	want := []string{"4.2.15.Final", "4.2.1.Final", "4.1.133.Final"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMavenVersions_NotFound(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Maven Central answers 200 with numFound:0 for a missing package.
		_, _ = w.Write([]byte(`{"response":{"numFound":0,"docs":[]}}`))
	}))
	defer srv.Close()

	m := NewMaven(WithHTTPClient(srv.Client()), WithSearchURL(srv.URL))
	_, err := m.Versions(context.Background(), "no.such", "artifact")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
