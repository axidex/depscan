package datasource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultNPMBase is the public npm registry.
const defaultNPMBase = "https://registry.npmjs.org"

// NPM lists published versions from an npm registry packument.
type NPM struct {
	client  *http.Client
	baseURL string
}

// NPMOption configures an NPM datasource.
type NPMOption func(*NPM)

// WithNPMHTTPClient overrides the HTTP client (for tests).
func WithNPMHTTPClient(c *http.Client) NPMOption {
	return func(n *NPM) {
		if c != nil {
			n.client = c
		}
	}
}

// WithNPMBaseURL overrides the registry base URL (for tests).
func WithNPMBaseURL(u string) NPMOption {
	return func(n *NPM) {
		if u != "" {
			n.baseURL = strings.TrimRight(u, "/")
		}
	}
}

// NewNPM builds an npm datasource.
func NewNPM(opts ...NPMOption) *NPM {
	n := &NPM{client: &http.Client{Timeout: 20 * time.Second}, baseURL: defaultNPMBase}
	for _, opt := range opts {
		opt(n)
	}
	return n
}

// Versions returns every published version of an npm package. The group is
// unused (an npm scope is part of the name, e.g. "@babel/core"); artifact is the
// package name.
func (n *NPM) Versions(ctx context.Context, group, artifact string) ([]string, error) {
	_ = group
	if artifact == "" {
		return nil, errors.New("datasource: npm: empty package name")
	}
	endpoint := n.baseURL + "/" + url.PathEscape(artifact) // PathEscape encodes the scope '/'

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("datasource: npm: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("datasource: npm: %s: %w", artifact, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("datasource: npm: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("datasource: npm: %s: status %d", artifact, resp.StatusCode)
	}

	var payload struct {
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("datasource: npm: decode: %w", err)
	}
	if len(payload.Versions) == 0 {
		return nil, ErrNotFound
	}
	versions := make([]string, 0, len(payload.Versions))
	for v := range payload.Versions {
		versions = append(versions, v)
	}
	return versions, nil
}
