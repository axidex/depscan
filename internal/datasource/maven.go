// Package datasource looks up the versions a package registry publishes for a
// dependency — the "datasource" role. Paired with internal/mavenver it
// answers "is there a newer stable version to bump to?". Lookups are read-only
// and never execute a build tool.
package datasource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ErrNotFound means the registry has no record of the package.
var ErrNotFound = errors.New("datasource: package not found")

// maxResponseBytes caps a buffered registry response.
const maxResponseBytes = 8 << 20

// defaultMavenSearchURL is the Maven Central search endpoint.
const defaultMavenSearchURL = "https://search.maven.org/solrsearch/select"

// Maven resolves published versions from Maven Central.
type Maven struct {
	client    *http.Client
	searchURL string
	rows      int
}

// Option configures a Maven datasource.
type Option func(*Maven)

// WithHTTPClient overrides the HTTP client (timeouts, transport, test servers).
func WithHTTPClient(c *http.Client) Option {
	return func(m *Maven) {
		if c != nil {
			m.client = c
		}
	}
}

// WithSearchURL overrides the search endpoint (for tests).
func WithSearchURL(u string) Option {
	return func(m *Maven) {
		if u != "" {
			m.searchURL = u
		}
	}
}

// NewMaven builds a Maven datasource with sensible defaults.
func NewMaven(opts ...Option) *Maven {
	m := &Maven{
		client:    &http.Client{Timeout: 20 * time.Second},
		searchURL: defaultMavenSearchURL,
		rows:      200,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

type mavenSearchResponse struct {
	Response struct {
		NumFound int `json:"numFound"`
		Docs     []struct {
			V string `json:"v"`
		} `json:"docs"`
	} `json:"response"`
}

// Versions returns every version Maven Central publishes for group:artifact,
// newest first. A missing package yields ErrNotFound. The result is capped at
// the configured row count; for prolific artifacts that means the most recent
// releases, which is what an upgrade check needs.
func (m *Maven) Versions(ctx context.Context, group, artifact string) ([]string, error) {
	if group == "" || artifact == "" {
		return nil, errors.New("datasource: maven: empty group/artifact")
	}

	q := url.Values{
		"q":    {fmt.Sprintf("g:%s AND a:%s", group, artifact)},
		"core": {"gav"},
		"rows": {strconv.Itoa(m.rows)},
		"wt":   {"json"},
		"sort": {"timestamp desc"},
	}
	endpoint := m.searchURL + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("datasource: maven: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("datasource: maven: %s:%s: %w", group, artifact, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("datasource: maven: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("datasource: maven: %s:%s: status %d", group, artifact, resp.StatusCode)
	}

	var payload mavenSearchResponse
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("datasource: maven: decode: %w", err)
	}
	// Maven Central returns HTTP 200 with numFound:0 for a missing package.
	if payload.Response.NumFound == 0 || len(payload.Response.Docs) == 0 {
		return nil, ErrNotFound
	}

	versions := make([]string, 0, len(payload.Response.Docs))
	for _, d := range payload.Response.Docs {
		if d.V != "" {
			versions = append(versions, d.V)
		}
	}
	return versions, nil
}
