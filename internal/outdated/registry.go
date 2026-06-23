package outdated

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

	"github.com/axidex/depscan/internal/purl"
)

// ErrNotFound indicates the registry has no record of the package.
var ErrNotFound = errors.New("outdated: package not found in registry")

// maxResponseBytes caps how much of a registry response body is buffered, so a
// buggy or hostile endpoint cannot exhaust memory. Registry "latest version"
// payloads are small; npm full packuments are the largest realistic case.
const maxResponseBytes = 16 << 20

// httpRegistry holds the shared HTTP plumbing for registry checkers.
type httpRegistry struct {
	client      *http.Client
	maxRetries  int
	baseBackoff time.Duration
}

func newHTTPRegistry(client *http.Client) httpRegistry {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return httpRegistry{client: client, maxRetries: 2, baseBackoff: 200 * time.Millisecond}
}

// getJSON GETs url and decodes JSON into out. HTTP 404 maps to ErrNotFound;
// transport errors, 429 and 5xx are retried with exponential backoff.
func (h httpRegistry) getJSON(ctx context.Context, url string, out any) error {
	var lastErr error
	for attempt := 0; attempt <= h.maxRetries; attempt++ {
		if attempt > 0 {
			wait := h.baseBackoff << (attempt - 1)
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Accept", "application/json")

		resp, err := h.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := readBody(resp.Body, maxResponseBytes)
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		switch {
		case resp.StatusCode == http.StatusNotFound:
			return ErrNotFound
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			continue
		case resp.StatusCode != http.StatusOK:
			return fmt.Errorf("unexpected status %d", resp.StatusCode)
		}
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		return nil
	}
	return fmt.Errorf("after %d attempts: %w", h.maxRetries+1, lastErr)
}

// --- npm ---

// NPMRegistry resolves latest versions from registry.npmjs.org.
type NPMRegistry struct{ httpRegistry }

// NewNPMRegistry constructs an npm registry checker.
func NewNPMRegistry(client *http.Client) *NPMRegistry {
	return &NPMRegistry{newHTTPRegistry(client)}
}

func (r *NPMRegistry) Ecosystem() string { return "npm" }

func (r *NPMRegistry) Latest(ctx context.Context, p purl.PURL) (string, error) {
	// Scoped packages must carry an encoded "@": @scope/name -> %40scope/name.
	pkgPath := strings.ReplaceAll(p.Coordinates(), "@", "%40")
	endpoint := "https://registry.npmjs.org/" + pkgPath + "/latest"

	var payload struct {
		Version string `json:"version"`
	}
	if err := r.getJSON(ctx, endpoint, &payload); err != nil {
		return "", err
	}
	if payload.Version == "" {
		return "", fmt.Errorf("npm: empty version for %q", p.Coordinates())
	}
	return payload.Version, nil
}

// --- PyPI ---

// PyPIRegistry resolves latest versions from pypi.org.
type PyPIRegistry struct{ httpRegistry }

// NewPyPIRegistry constructs a PyPI registry checker.
func NewPyPIRegistry(client *http.Client) *PyPIRegistry {
	return &PyPIRegistry{newHTTPRegistry(client)}
}

func (r *PyPIRegistry) Ecosystem() string { return "pypi" }

func (r *PyPIRegistry) Latest(ctx context.Context, p purl.PURL) (string, error) {
	endpoint := "https://pypi.org/pypi/" + url.PathEscape(p.Name) + "/json"

	var payload struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := r.getJSON(ctx, endpoint, &payload); err != nil {
		return "", err
	}
	if payload.Info.Version == "" {
		return "", fmt.Errorf("pypi: empty version for %q", p.Name)
	}
	return payload.Info.Version, nil
}

// --- Maven Central ---

// MavenRegistry resolves latest versions from the Maven Central search API.
type MavenRegistry struct{ httpRegistry }

// NewMavenRegistry constructs a Maven Central registry checker.
func NewMavenRegistry(client *http.Client) *MavenRegistry {
	return &MavenRegistry{newHTTPRegistry(client)}
}

func (r *MavenRegistry) Ecosystem() string { return "maven" }

func (r *MavenRegistry) Latest(ctx context.Context, p purl.PURL) (string, error) {
	// purl maps groupId -> namespace, artifactId -> name.
	if p.Namespace == "" {
		return "", fmt.Errorf("maven: missing groupId in purl %q", p.Raw)
	}
	query := fmt.Sprintf("g:%s AND a:%s", p.Namespace, p.Name)
	params := url.Values{
		"q":    {query},
		"core": {"gav"},
		"rows": {"1"},
		"wt":   {"json"},
	}
	endpoint := "https://search.maven.org/solrsearch/select?" + params.Encode()

	var payload struct {
		Response struct {
			NumFound int `json:"numFound"`
			Docs     []struct {
				V string `json:"v"`
			} `json:"docs"`
		} `json:"response"`
	}
	if err := r.getJSON(ctx, endpoint, &payload); err != nil {
		return "", err
	}
	if payload.Response.NumFound == 0 || len(payload.Response.Docs) == 0 {
		return "", ErrNotFound
	}
	return payload.Response.Docs[0].V, nil
}

// readBody reads up to limit bytes from r, erroring if the body is larger so an
// oversized response is treated as a failure rather than silently truncated.
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

// DefaultRegistries returns the production registry checkers depscan ships with.
func DefaultRegistries(client *http.Client) []RegistryChecker {
	return []RegistryChecker{
		NewNPMRegistry(client),
		NewPyPIRegistry(client),
		NewMavenRegistry(client),
	}
}
