// Package osv queries OSV.dev for known vulnerabilities of declared
// dependencies and reports the fixed versions, so the worker can raise
// security-priority upgrade PRs. It is B-native: it asks OSV about the exact
// declared coordinate@version, no SBOM involved.
package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"resty.dev/v3"
)

const (
	defaultBatchURL = "https://api.osv.dev/v1/querybatch"
	defaultVulnURL  = "https://api.osv.dev/v1/vulns/"
	maxResponse     = 32 << 20

	ecoMaven = "maven"
	ecoPyPI  = "pypi"
)

// Coordinate is a dependency to check: its OSV ecosystem, name, and version.
// Name is "group:artifact" for Maven, the package name for PyPI.
type Coordinate struct {
	Ecosystem string // "maven" | "pypi"
	Name      string
	Version   string
}

// Key is the stable map key for a coordinate.
func (c Coordinate) Key() string { return c.Ecosystem + "|" + c.Name + "|" + c.Version }

func (c Coordinate) purl() string {
	switch c.Ecosystem {
	case ecoMaven:
		g, a, ok := strings.Cut(c.Name, ":")
		if !ok {
			return ""
		}
		return fmt.Sprintf("pkg:maven/%s/%s@%s", g, a, c.Version)
	case ecoPyPI:
		return fmt.Sprintf("pkg:pypi/%s@%s", normalizePyPI(c.Name), c.Version)
	default:
		return ""
	}
}

// Advisory is the vulnerability outcome for one coordinate.
type Advisory struct {
	VulnIDs       []string
	FixedVersions []string
}

// Client talks to OSV.dev.
type Client struct {
	rest        *resty.Client
	httpClient  *http.Client
	batchURL    string
	vulnURL     string
	concurrency int

	mu    sync.Mutex
	cache map[string]osvRecord
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the HTTP client.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.httpClient = h
		}
	}
}

// WithEndpoints overrides the batch and vuln URLs (for tests). vulnBase must end
// with a trailing slash.
func WithEndpoints(batchURL, vulnBase string) Option {
	return func(c *Client) { c.batchURL, c.vulnURL = batchURL, vulnBase }
}

// New builds an OSV client.
func New(opts ...Option) *Client {
	c := &Client{
		batchURL:    defaultBatchURL,
		vulnURL:     defaultVulnURL,
		concurrency: 8,
		cache:       map[string]osvRecord{},
	}
	for _, opt := range opts {
		opt(c)
	}
	rc := resty.New()
	if c.httpClient != nil {
		rc = resty.NewWithClient(c.httpClient)
	}
	c.rest = rc.
		SetTimeout(30*time.Second).
		SetResponseBodyLimit(maxResponse).
		SetHeader("Accept", "application/json")
	return c
}

// --- OSV wire types ---

type batchRequest struct {
	Queries []query `json:"queries"`
}
type query struct {
	Package pkg `json:"package"`
}
type pkg struct {
	PURL string `json:"purl"`
}
type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}
type osvRecord struct {
	ID        string     `json:"id"`
	Withdrawn string     `json:"withdrawn"`
	Affected  []affected `json:"affected"`
}
type affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		PURL      string `json:"purl"`
	} `json:"package"`
	Ranges []struct {
		Type             string  `json:"type"`
		Events           []event `json:"events"`
		DatabaseSpecific struct {
			Versions []event `json:"versions"`
		} `json:"database_specific"`
	} `json:"ranges"`
}
type event struct {
	Fixed string `json:"fixed"`
}

// Query checks each coordinate against OSV and returns advisories for those that
// are affected and have at least one fixed version (keyed by Coordinate.Key()).
func (c *Client) Query(ctx context.Context, coords []Coordinate) (map[string]Advisory, error) {
	purlToKey := map[string]Coordinate{}
	var purls []string
	for _, co := range coords {
		if p := co.purl(); p != "" {
			purlToKey[p] = co
			purls = append(purls, p)
		}
	}
	if len(purls) == 0 {
		return map[string]Advisory{}, nil
	}

	idsByPURL, err := c.discover(ctx, purls)
	if err != nil {
		return nil, err
	}
	if err := c.hydrate(ctx, uniqueIDs(idsByPURL)); err != nil {
		return nil, err
	}

	out := map[string]Advisory{}
	for p, ids := range idsByPURL {
		co := purlToKey[p]
		var adv Advisory
		seen := map[string]bool{}
		for _, id := range ids {
			c.mu.Lock()
			rec, ok := c.cache[id]
			c.mu.Unlock()
			if !ok || rec.Withdrawn != "" || seen[id] {
				continue
			}
			seen[id] = true
			fixes := fixedVersionsFor(rec, co)
			if len(fixes) == 0 {
				continue
			}
			adv.VulnIDs = append(adv.VulnIDs, id)
			adv.FixedVersions = append(adv.FixedVersions, fixes...)
		}
		if len(adv.VulnIDs) > 0 {
			out[co.Key()] = adv
		}
	}
	return out, nil
}

func (c *Client) discover(ctx context.Context, purls []string) (map[string][]string, error) {
	req := batchRequest{Queries: make([]query, len(purls))}
	for i, p := range purls {
		req.Queries[i] = query{Package: pkg{PURL: p}}
	}
	var resp batchResponse
	if err := c.doJSON(ctx, http.MethodPost, c.batchURL, req, &resp); err != nil {
		return nil, fmt.Errorf("osv: querybatch: %w", err)
	}
	if len(resp.Results) != len(purls) {
		return nil, fmt.Errorf("osv: querybatch returned %d results for %d queries", len(resp.Results), len(purls))
	}
	out := map[string][]string{}
	for i, r := range resp.Results {
		for _, v := range r.Vulns {
			out[purls[i]] = append(out[purls[i]], v.ID)
		}
	}
	return out, nil
}

func (c *Client) hydrate(ctx context.Context, ids []string) error {
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(c.concurrency)
	for _, id := range ids {
		c.mu.Lock()
		_, cached := c.cache[id]
		c.mu.Unlock()
		if cached {
			continue
		}
		g.Go(func() error {
			var rec osvRecord
			notFound, err := c.getVuln(gctx, id, &rec)
			if err != nil {
				return fmt.Errorf("osv: hydrate %s: %w", id, err)
			}
			if notFound {
				return nil
			}
			c.mu.Lock()
			c.cache[id] = rec
			c.mu.Unlock()
			return nil
		})
	}
	return g.Wait()
}

func (c *Client) getVuln(ctx context.Context, id string, out *osvRecord) (notFound bool, err error) {
	status, body, err := c.do(ctx, http.MethodGet, c.vulnURL+id, nil)
	if err != nil {
		return false, err
	}
	if status == http.StatusNotFound {
		return true, nil
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("status %d", status)
	}
	return false, json.Unmarshal(body, out)
}

func (c *Client) doJSON(ctx context.Context, method, url string, body, out any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	status, respBody, err := c.do(ctx, method, url, encoded)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("status %d", status)
	}
	return json.Unmarshal(respBody, out)
}

func (c *Client) do(ctx context.Context, method, url string, body []byte) (int, []byte, error) {
	req := c.rest.R().SetContext(ctx)
	if body != nil {
		req.SetHeader("Content-Type", "application/json").SetBody(body)
	}
	res, err := req.Execute(method, url)
	if err != nil {
		return 0, nil, err
	}
	return res.StatusCode(), res.Bytes(), nil
}

// fixedVersionsFor extracts fixed versions from the affected entries that match
// the queried coordinate. For GIT ranges the version lives in
// database_specific.versions.
func fixedVersionsFor(rec osvRecord, co Coordinate) []string {
	var out []string
	for _, aff := range rec.Affected {
		if !affectedMatches(aff, co) {
			continue
		}
		for _, r := range aff.Ranges {
			if !strings.EqualFold(r.Type, "GIT") {
				for _, e := range r.Events {
					if e.Fixed != "" {
						out = append(out, e.Fixed)
					}
				}
			}
			for _, e := range r.DatabaseSpecific.Versions {
				if e.Fixed != "" {
					out = append(out, e.Fixed)
				}
			}
		}
	}
	return out
}

func affectedMatches(aff affected, co Coordinate) bool {
	name := aff.Package.Name
	switch co.Ecosystem {
	case ecoMaven:
		// OSV Maven names are "group:artifact".
		return strings.EqualFold(name, co.Name)
	case ecoPyPI:
		return normalizePyPI(name) == normalizePyPI(co.Name)
	default:
		return false
	}
}

var pep503 = regexp.MustCompile(`[-_.]+`)

// normalizePyPI applies PEP 503 normalization for name matching.
func normalizePyPI(name string) string {
	return pep503.ReplaceAllString(strings.ToLower(name), "-")
}

func uniqueIDs(byPURL map[string][]string) []string {
	seen := map[string]bool{}
	var ids []string
	for _, list := range byPURL {
		for _, id := range list {
			if id != "" && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids
}
