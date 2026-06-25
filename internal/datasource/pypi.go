package datasource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"resty.dev/v3"
)

// defaultPyPIBase is the PyPI JSON API root.
const defaultPyPIBase = "https://pypi.org/pypi"

// PyPI lists published versions from the PyPI JSON API.
type PyPI struct {
	client     *resty.Client
	httpClient *http.Client
	baseURL    string
}

// PyPIOption configures a PyPI datasource.
type PyPIOption func(*PyPI)

// WithPyPIHTTPClient overrides the HTTP client (for tests).
func WithPyPIHTTPClient(c *http.Client) PyPIOption {
	return func(p *PyPI) {
		if c != nil {
			p.httpClient = c
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
	p := &PyPI{baseURL: defaultPyPIBase}
	for _, opt := range opts {
		opt(p)
	}
	p.client = newRestyClient(p.httpClient, 20*time.Second)
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

	res, err := p.client.R().SetContext(ctx).Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("datasource: pypi: %s: %w", artifact, err)
	}
	if res.StatusCode() == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if res.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("datasource: pypi: %s: status %d", artifact, res.StatusCode())
	}

	var payload struct {
		Releases map[string]json.RawMessage `json:"releases"`
	}
	if err := json.Unmarshal(res.Bytes(), &payload); err != nil {
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
