package datasource

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// defaultGradlePluginBase is the Gradle Plugin Portal's Maven repository.
const defaultGradlePluginBase = "https://plugins.gradle.org/m2"

// MavenMetadata lists versions from any Maven repository via maven-metadata.xml.
// It backs the Gradle Plugin Portal datasource, where a plugin id "com.x" is
// resolved through its marker artifact "com.x:com.x.gradle.plugin".
type MavenMetadata struct {
	client  *http.Client
	baseURL string
}

// MetaOption configures a MavenMetadata datasource.
type MetaOption func(*MavenMetadata)

// WithMetaHTTPClient overrides the HTTP client (for tests).
func WithMetaHTTPClient(c *http.Client) MetaOption {
	return func(m *MavenMetadata) {
		if c != nil {
			m.client = c
		}
	}
}

// WithMetaBaseURL overrides the repository base URL (for tests).
func WithMetaBaseURL(u string) MetaOption {
	return func(m *MavenMetadata) {
		if u != "" {
			m.baseURL = strings.TrimRight(u, "/")
		}
	}
}

// NewGradlePlugin builds a datasource for the Gradle Plugin Portal.
func NewGradlePlugin(opts ...MetaOption) *MavenMetadata {
	m := &MavenMetadata{
		client:  &http.Client{Timeout: 20 * time.Second},
		baseURL: defaultGradlePluginBase,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

type mavenMetadataXML struct {
	Versioning struct {
		Versions struct {
			Version []string `xml:"version"`
		} `xml:"versions"`
	} `xml:"versioning"`
}

// Versions returns the versions published for group:artifact, by fetching
// <base>/<group-as-path>/<artifact>/maven-metadata.xml. A missing artifact
// yields ErrNotFound.
func (m *MavenMetadata) Versions(ctx context.Context, group, artifact string) ([]string, error) {
	if group == "" || artifact == "" {
		return nil, errors.New("datasource: maven-metadata: empty group/artifact")
	}
	endpoint := m.baseURL + "/" + strings.ReplaceAll(group, ".", "/") + "/" + artifact + "/maven-metadata.xml"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("datasource: maven-metadata: build request: %w", err)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("datasource: maven-metadata: %s:%s: %w", group, artifact, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("datasource: maven-metadata: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("datasource: maven-metadata: %s:%s: status %d", group, artifact, resp.StatusCode)
	}

	var meta mavenMetadataXML
	if err := xml.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("datasource: maven-metadata: decode: %w", err)
	}
	if len(meta.Versioning.Versions.Version) == 0 {
		return nil, ErrNotFound
	}
	return meta.Versioning.Versions.Version, nil
}
