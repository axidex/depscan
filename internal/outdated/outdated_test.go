package outdated_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/axidex/depscan/internal/outdated"
	"github.com/axidex/depscan/internal/purl"
)

func TestClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		current string
		latest  string
		want    outdated.UpdateKind
	}{
		{name: "up to date", current: "1.2.3", latest: "1.2.3", want: outdated.KindUpToDate},
		{name: "current newer", current: "2.0.0", latest: "1.9.9", want: outdated.KindUpToDate},
		{name: "patch", current: "1.2.3", latest: "1.2.9", want: outdated.KindPatch},
		{name: "minor", current: "1.2.3", latest: "1.5.0", want: outdated.KindMinor},
		{name: "major", current: "1.2.3", latest: "3.0.0", want: outdated.KindMajor},
		{name: "leading v", current: "v1.0.0", latest: "v1.0.1", want: outdated.KindPatch},
		{name: "partial current coerced", current: "1.2", latest: "1.2.4", want: outdated.KindPatch},
		{name: "major dominates", current: "1.9.9", latest: "2.0.0", want: outdated.KindMajor},
		{name: "non-semver newer", current: "2.0.1.Final", latest: "2.0.2.Final", want: outdated.KindNewer},
		{name: "non-semver equal", current: "1.0-RELEASE", latest: "1.0-RELEASE", want: outdated.KindUpToDate},
		{name: "empty latest", current: "1.0.0", latest: "", want: outdated.KindUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := outdated.Classify(tt.current, tt.latest); got != tt.want {
				t.Errorf("Classify(%q, %q) = %q, want %q", tt.current, tt.latest, got, tt.want)
			}
		})
	}
}

// rewriteTransport redirects all requests to the test server while preserving
// path and query, so registry checkers exercise their real URL-building logic.
type rewriteTransport struct{ base *url.URL }

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = t.base.Scheme
	req.URL.Host = t.base.Host
	return http.DefaultTransport.RoundTrip(req)
}

func testClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	return &http.Client{Transport: rewriteTransport{base: u}}
}

func registryServer() *httptest.Server {
	mux := http.NewServeMux()
	// npm: /{pkg}/latest
	mux.HandleFunc("/lodash/latest", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"version":"4.17.21"}`))
	})
	mux.HandleFunc("/%40babel/core/latest", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"version":"8.0.1"}`))
	})
	// pypi: /pypi/{pkg}/json
	mux.HandleFunc("/pypi/requests/json", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"info":{"version":"2.34.2"}}`))
	})
	// maven: /solrsearch/select?...
	mux.HandleFunc("/solrsearch/select", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "missing") {
			w.Write([]byte(`{"response":{"numFound":0,"docs":[]}}`))
			return
		}
		w.Write([]byte(`{"response":{"numFound":5,"docs":[{"v":"33.4.8-jre"}]}}`))
	})
	// Anything else: 404
	return httptest.NewServer(mux)
}

func mustParse(t *testing.T, raw string) purl.PURL {
	t.Helper()
	p, err := purl.Parse(raw)
	if err != nil {
		t.Fatalf("purl.Parse(%q): %v", raw, err)
	}
	return p
}

func TestRegistries_Latest(t *testing.T) {
	t.Parallel()

	srv := registryServer()
	t.Cleanup(srv.Close)
	client := testClient(t, srv)

	tests := []struct {
		name    string
		checker outdated.RegistryChecker
		purl    string
		want    string
	}{
		{name: "npm unscoped", checker: outdated.NewNPMRegistry(client), purl: "pkg:npm/lodash@4.17.20", want: "4.17.21"},
		{name: "npm scoped", checker: outdated.NewNPMRegistry(client), purl: "pkg:npm/%40babel/core@7.0.0", want: "8.0.1"},
		{name: "pypi", checker: outdated.NewPyPIRegistry(client), purl: "pkg:pypi/requests@2.20.0", want: "2.34.2"},
		{name: "maven", checker: outdated.NewMavenRegistry(client), purl: "pkg:maven/com.google.guava/guava@30.0-jre", want: "33.4.8-jre"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.checker.Latest(context.Background(), mustParse(t, tt.purl))
			if err != nil {
				t.Fatalf("Latest: %v", err)
			}
			if got != tt.want {
				t.Errorf("Latest = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRegistries_NotFound(t *testing.T) {
	t.Parallel()

	srv := registryServer()
	t.Cleanup(srv.Close)
	client := testClient(t, srv)

	// npm: unknown package -> 404 -> ErrNotFound
	_, err := outdated.NewNPMRegistry(client).Latest(context.Background(), mustParse(t, "pkg:npm/does-not-exist@1.0.0"))
	if !errors.Is(err, outdated.ErrNotFound) {
		t.Errorf("npm unknown: err = %v, want ErrNotFound", err)
	}

	// maven: numFound 0 -> ErrNotFound
	_, err = outdated.NewMavenRegistry(client).Latest(context.Background(), mustParse(t, "pkg:maven/missing.group/missing@1.0.0"))
	if !errors.Is(err, outdated.ErrNotFound) {
		t.Errorf("maven missing: err = %v, want ErrNotFound", err)
	}
}

// fakeRegistry is a stub RegistryChecker for routing tests.
type fakeRegistry struct {
	ecosystem string
	latest    string
	err       error
}

func (f fakeRegistry) Ecosystem() string { return f.ecosystem }
func (f fakeRegistry) Latest(context.Context, purl.PURL) (string, error) {
	return f.latest, f.err
}

func TestChecker_Check(t *testing.T) {
	t.Parallel()

	checker := outdated.NewChecker(
		fakeRegistry{ecosystem: "npm", latest: "2.0.0"},
		fakeRegistry{ecosystem: "pypi", err: errors.New("boom")},
	)

	tests := []struct {
		name     string
		purl     string
		current  string
		wantKind outdated.UpdateKind
	}{
		{name: "supported classifies", purl: "pkg:npm/lodash@1.0.0", current: "1.0.0", wantKind: outdated.KindMajor},
		{name: "unsupported ecosystem unknown", purl: "pkg:cargo/serde@1.0.0", current: "1.0.0", wantKind: outdated.KindUnknown},
		{name: "registry error degrades to unknown", purl: "pkg:pypi/requests@1.0.0", current: "1.0.0", wantKind: outdated.KindUnknown},
		{name: "invalid purl unknown", purl: "garbage", current: "1.0.0", wantKind: outdated.KindUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := checker.Check(context.Background(), tt.purl, tt.current)
			if got.Kind != tt.wantKind {
				t.Errorf("Check(%q).Kind = %q, want %q", tt.purl, got.Kind, tt.wantKind)
			}
		})
	}
}
