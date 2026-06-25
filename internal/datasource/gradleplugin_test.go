package datasource

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGradlePluginVersions(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// id "com.diffplug.spotless" → marker artifact at the maven path.
		if r.URL.Path != "/com/diffplug/spotless/com.diffplug.spotless.gradle.plugin/maven-metadata.xml" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`<metadata>
  <versioning>
    <latest>6.25.0</latest>
    <versions>
      <version>6.23.0</version>
      <version>6.25.0</version>
    </versions>
  </versioning>
</metadata>`))
	}))
	defer srv.Close()

	ds := NewGradlePlugin(WithMetaHTTPClient(srv.Client()), WithMetaBaseURL(srv.URL))
	got, err := ds.Versions(context.Background(), "com.diffplug.spotless", "com.diffplug.spotless.gradle.plugin")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(got) != 2 || got[0] != "6.23.0" || got[1] != "6.25.0" {
		t.Errorf("versions = %v, want [6.23.0 6.25.0]", got)
	}
}

func TestGradlePluginVersions_NotFound(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	ds := NewGradlePlugin(WithMetaHTTPClient(srv.Client()), WithMetaBaseURL(srv.URL))
	_, err := ds.Versions(context.Background(), "no.such", "no.such.gradle.plugin")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
