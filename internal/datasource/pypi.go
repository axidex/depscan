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

// defaultPyPIBase is the PyPI JSON API root.
const defaultPyPIBase = "https://pypi.org/pypi"

// PyPI lists published versions from the PyPI JSON API.
type PyPI struct {
	client  *http.Client
	baseURL string
}

// PyPIOption configures a PyPI datasource.
type PyPIOption func(*PyPI)

// WithPyPIHTTPClient overrides the HTTP client (for tests).
func WithPyPIHTTPClient(c *http.Client) PyPIOption {
	return func(p *PyPI) {
		if c != nil {
			p.client = c
		}
	}
}

// WithPyPIBaseURL overrides the API root (for tests).
func WithPyPIBaseURL(u string) PyPIOption {
	return func(p *PyPI) {
		if u != "" {
			p.baseURL = strings.TrimRight(u, "/")
		}
	}
}

// NewPyPI builds a PyPI datasource.
func NewPyPI(opts ...PyPIOption) *PyPI {
	p := &PyPI{client: &http.Client{Timeout: 20 * time.Second}, baseURL: defaultPyPIBase}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Versions returns every published version of a PyPI package. The group is
// unused (PyPI packages are flat); artifact is the package name.
func (p *PyPI) Versions(ctx context.Context, group, artifact string) ([]string, error) {
	_ = group
	if artifact == "" {
		return nil, errors.New("datasource: pypi: empty package name")
	}
	endpoint := p.baseURL + "/" + url.PathEscape(artifact) + "/json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("datasource: pypi: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("datasource: pypi: %s: %w", artifact, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("datasource: pypi: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("datasource: pypi: %s: status %d", artifact, resp.StatusCode)
	}

	var payload struct {
		Releases map[string]json.RawMessage `json:"releases"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("datasource: pypi: decode: %w", err)
	}
	if len(payload.Releases) == 0 {
		return nil, ErrNotFound
	}
	versions := make([]string, 0, len(payload.Releases))
	for v := range payload.Releases {
		versions = append(versions, v)
	}
	return versions, nil
}
