package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

const (
	defaultBatchURL = "https://api.osv.dev/v1/querybatch"
	defaultVulnURL  = "https://api.osv.dev/v1/vulns/"

	// maxBatchSize is the OSV-documented ceiling of queries per querybatch call.
	maxBatchSize = 1000
	// maxPages bounds per-query pagination so a pathological response cannot
	// loop forever.
	maxPages = 20
	// maxResponseBytes caps how much of an HTTP response body is buffered so a
	// buggy or hostile endpoint cannot exhaust memory. OSV batch responses are
	// documented up to ~32 MiB; this leaves generous headroom.
	maxResponseBytes = 48 << 20
)

// OSVClient is the production Client backed by api.osv.dev.
type OSVClient struct {
	httpClient  *http.Client
	batchURL    string
	vulnURL     string
	concurrency int
	maxRetries  int
	baseBackoff time.Duration
	logger      *slog.Logger

	mu    sync.Mutex
	cache map[string]osvVuln // hydrated record keyed by vuln ID
}

// Option configures an OSVClient.
type Option func(*OSVClient)

// WithHTTPClient overrides the HTTP client (timeouts, transport, test servers).
func WithHTTPClient(c *http.Client) Option { return func(o *OSVClient) { o.httpClient = c } }

// WithConcurrency sets the maximum in-flight hydration requests.
func WithConcurrency(n int) Option {
	return func(o *OSVClient) {
		if n > 0 {
			o.concurrency = n
		}
	}
}

// WithEndpoints overrides the OSV endpoints (used in tests). vulnBase must end
// with a trailing slash; the vuln ID is appended directly.
func WithEndpoints(batchURL, vulnBase string) Option {
	return func(o *OSVClient) {
		o.batchURL = batchURL
		o.vulnURL = vulnBase
	}
}

// WithRetries sets the retry budget and base backoff for transient failures.
func WithRetries(maxRetries int, baseBackoff time.Duration) Option {
	return func(o *OSVClient) {
		o.maxRetries = maxRetries
		o.baseBackoff = baseBackoff
	}
}

// WithLogger sets a slog.Logger for debug diagnostics. A nil logger is ignored.
func WithLogger(l *slog.Logger) Option {
	return func(o *OSVClient) {
		if l != nil {
			o.logger = l
		}
	}
}

// NewOSVClient builds an OSVClient with sensible defaults.
func NewOSVClient(opts ...Option) *OSVClient {
	c := &OSVClient{
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		batchURL:    defaultBatchURL,
		vulnURL:     defaultVulnURL,
		concurrency: 8,
		maxRetries:  3,
		baseBackoff: 250 * time.Millisecond,
		logger:      slog.New(slog.DiscardHandler),
		cache:       map[string]osvVuln{},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// --- OSV wire types ---

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package   osvQueryPackage `json:"package"`
	PageToken string          `json:"page_token,omitempty"`
}

type osvQueryPackage struct {
	PURL string `json:"purl"`
}

type osvBatchResponse struct {
	Results []osvBatchResult `json:"results"`
}

type osvBatchResult struct {
	Vulns         []osvVulnRef `json:"vulns"`
	NextPageToken string       `json:"next_page_token"`
}

type osvVulnRef struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

type osvVuln struct {
	ID        string        `json:"id"`
	Summary   string        `json:"summary"`
	Details   string        `json:"details"`
	Modified  string        `json:"modified"`
	Withdrawn string        `json:"withdrawn"`
	Aliases   []string      `json:"aliases"`
	Severity  []osvSeverity `json:"severity"`
	Affected  []osvAffected `json:"affected"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package  osvAffectedPackage `json:"package"`
	Ranges   []osvRange         `json:"ranges"`
	Versions []string           `json:"versions"`
	Severity []osvSeverity      `json:"severity"`
}

type osvAffectedPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl"`
}

type osvRange struct {
	Type             string                `json:"type"`
	Events           []osvEvent            `json:"events"`
	DatabaseSpecific osvRangeDatabaseExtra `json:"database_specific"`
}

type osvRangeDatabaseExtra struct {
	// Versions carries human-readable version events alongside GIT commit
	// hashes, e.g. {"fixed": "1.15.4"} paired with a SHA fixed event.
	Versions []osvEvent `json:"versions"`
}

type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

// Query implements Client.
func (c *OSVClient) Query(ctx context.Context, purls []string) (map[string]Result, error) {
	out := map[string]Result{}
	if len(purls) == 0 {
		return out, nil
	}

	unique := dedupeStrings(purls)
	c.logger.DebugContext(ctx, "osv: querying",
		"purls", len(purls), "unique", len(unique),
		"chunks", len(chunkStrings(unique, maxBatchSize)))

	// Step 1: discover vuln IDs per purl via querybatch (+ pagination).
	refsByPURL, err := c.discover(ctx, unique)
	if err != nil {
		return nil, err
	}

	// Step 2: hydrate every unique vuln ID exactly once.
	ids := uniqueIDs(refsByPURL)
	c.logger.DebugContext(ctx, "osv: discovered vulnerabilities",
		"purlsAffected", len(refsByPURL), "uniqueVulnIDs", len(ids))
	if err := c.hydrate(ctx, ids); err != nil {
		return nil, err
	}

	// Step 3: assemble per-purl results, computing fix data per package.
	for _, raw := range unique {
		refs := refsByPURL[raw]
		if len(refs) == 0 {
			continue
		}
		result := Result{Vulns: make([]Vuln, 0, len(refs))}
		seen := map[string]bool{}
		for _, ref := range refs {
			if seen[ref.ID] {
				continue
			}
			seen[ref.ID] = true

			c.mu.Lock()
			record, ok := c.cache[ref.ID]
			c.mu.Unlock()
			if !ok || record.Withdrawn != "" {
				continue
			}
			result.Vulns = append(result.Vulns, toVuln(record, raw))
		}
		if len(result.Vulns) > 0 {
			out[raw] = result
		}
	}

	return out, nil
}

// discover runs querybatch over chunks of purls and follows per-query
// pagination, returning the full vuln-ref list for each purl.
func (c *OSVClient) discover(ctx context.Context, purls []string) (map[string][]osvVulnRef, error) {
	refs := make(map[string][]osvVulnRef, len(purls))
	for _, chunk := range chunkStrings(purls, maxBatchSize) {
		if err := c.discoverChunk(ctx, chunk, refs); err != nil {
			return nil, err
		}
	}
	return refs, nil
}

// discoverChunk handles a single ≤1000 purl chunk, following next_page_token
// for any query whose results span multiple pages.
func (c *OSVClient) discoverChunk(ctx context.Context, chunk []string, refs map[string][]osvVulnRef) error {
	tokens := make([]string, len(chunk)) // page token per purl ("" = first page)
	active := make([]int, len(chunk))    // indices still needing a page
	for i := range chunk {
		active[i] = i
	}

	for page := 0; page < maxPages && len(active) > 0; page++ {
		queries := make([]osvQuery, len(active))
		for j, idx := range active {
			queries[j] = osvQuery{
				Package:   osvQueryPackage{PURL: chunk[idx]},
				PageToken: tokens[idx],
			}
		}

		var resp osvBatchResponse
		if err := c.doJSON(ctx, http.MethodPost, c.batchURL, osvBatchRequest{Queries: queries}, &resp); err != nil {
			return fmt.Errorf("osv: querybatch: %w", err)
		}
		if len(resp.Results) != len(active) {
			return fmt.Errorf("osv: querybatch returned %d results for %d queries", len(resp.Results), len(active))
		}

		next := active[:0:0]
		for j, idx := range active {
			res := resp.Results[j]
			purl := chunk[idx]
			refs[purl] = append(refs[purl], res.Vulns...)
			if res.NextPageToken != "" {
				tokens[idx] = res.NextPageToken
				next = append(next, idx)
			}
		}
		active = next
	}
	return nil
}

// hydrate fetches and caches every vuln ID not already cached, with bounded
// concurrency. A 404 (record gone) is tolerated; transport errors fail.
func (c *OSVClient) hydrate(ctx context.Context, ids []string) error {
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
			var record osvVuln
			notFound, err := c.getVuln(gctx, id, &record)
			if err != nil {
				return fmt.Errorf("osv: hydrate %s: %w", id, err)
			}
			if notFound {
				return nil
			}
			c.mu.Lock()
			c.cache[id] = record
			c.mu.Unlock()
			return nil
		})
	}

	return g.Wait()
}

// getVuln GETs a single vuln record. It returns notFound=true on HTTP 404.
func (c *OSVClient) getVuln(ctx context.Context, id string, out *osvVuln) (notFound bool, err error) {
	url := c.vulnURL + id
	status, body, err := c.do(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	if status == http.StatusNotFound {
		return true, nil
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("unexpected status %d: %s", status, snippet(body))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return false, fmt.Errorf("decode body: %w", err)
	}
	return false, nil
}

// doJSON sends body as JSON and decodes a JSON response, treating any non-2xx
// as an error.
func (c *OSVClient) doJSON(ctx context.Context, method, url string, body, out any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	status, respBody, err := c.do(ctx, method, url, encoded)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("unexpected status %d: %s", status, snippet(respBody))
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// do performs an HTTP request with retries and exponential backoff on transport
// errors, 429, and 5xx responses. It returns the final status and body.
func (c *OSVClient) do(ctx context.Context, method, url string, body []byte) (int, []byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			c.logger.DebugContext(ctx, "osv: retrying request",
				"url", url, "attempt", attempt+1, "lastErr", lastErr)
			if err := sleepBackoff(ctx, c.baseBackoff, attempt); err != nil {
				return 0, nil, err
			}
		}

		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, reader)
		if err != nil {
			return 0, nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue // transport error: retry
		}
		data, readErr := readBody(resp.Body, maxResponseBytes)
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("status %d: %s", resp.StatusCode, snippet(data))
			continue // transient server-side: retry
		}
		return resp.StatusCode, data, nil
	}
	return 0, nil, fmt.Errorf("after %d attempts: %w", c.maxRetries+1, lastErr)
}

// sleepBackoff waits baseBackoff*2^(attempt-1), respecting context cancellation.
func sleepBackoff(ctx context.Context, base time.Duration, attempt int) error {
	wait := base << (attempt - 1)
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func uniqueIDs(refsByPURL map[string][]osvVulnRef) []string {
	seen := map[string]bool{}
	ids := []string{}
	for _, refs := range refsByPURL {
		for _, ref := range refs {
			if ref.ID != "" && !seen[ref.ID] {
				seen[ref.ID] = true
				ids = append(ids, ref.ID)
			}
		}
	}
	return ids
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func chunkStrings(in []string, size int) [][]string {
	if size <= 0 {
		return [][]string{in}
	}
	chunks := make([][]string, 0, (len(in)+size-1)/size)
	for i := 0; i < len(in); i += size {
		end := min(i+size, len(in))
		chunks = append(chunks, in[i:end])
	}
	return chunks
}

// readBody reads up to limit bytes from r, returning an error if the body is
// larger so an oversized response is treated as a (retryable) failure rather
// than silently truncated.
func readBody(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return data, nil
}

func snippet(b []byte) string {
	const limit = 256
	s := strings.TrimSpace(string(b))
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}
