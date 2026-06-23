// Package sbom parses CycloneDX JSON SBOMs into the flat list of components
// depscan analyzes. It does not generate SBOMs — input only.
package sbom

import (
	"fmt"
	"io"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// Component is a single dependency extracted from an SBOM.
type Component struct {
	// PURL is the raw Package URL string, e.g. "pkg:npm/lodash@4.17.20".
	// May be empty for components the producer did not assign a purl.
	PURL string
	// Name is the component name.
	Name string
	// Version is the pinned version.
	Version string
	// Group is the CycloneDX group/namespace (e.g. maven groupId).
	Group string
	// BOMRef is the component's bom-ref, useful for SARIF correlation.
	BOMRef string
}

// Parse decodes a CycloneDX JSON BOM from r and returns its components, with
// nested components (Component.Components) flattened into a single list.
//
// Only components carrying a PURL are returned: depscan's entire pipeline is
// purl-driven (OSV queries and registry routing both require it), so a
// component without one cannot be scanned and is silently skipped. The skipped
// count is returned so callers can surface it.
func Parse(r io.Reader) (components []Component, skipped int, err error) {
	bom := &cyclonedx.BOM{}
	if decErr := cyclonedx.NewBOMDecoder(r, cyclonedx.BOMFileFormatJSON).Decode(bom); decErr != nil {
		return nil, 0, fmt.Errorf("sbom: decode CycloneDX JSON: %w", decErr)
	}

	components = []Component{}
	if bom.Components == nil {
		return components, 0, nil
	}

	skipped = collect(*bom.Components, &components)
	return components, skipped, nil
}

// collect appends scannable components from src (recursing into nested
// components) to dst and returns how many were skipped for lacking a purl.
func collect(src []cyclonedx.Component, dst *[]Component) int {
	skipped := 0
	for _, c := range src {
		if c.PackageURL == "" {
			skipped++
		} else {
			*dst = append(*dst, Component{
				PURL:    c.PackageURL,
				Name:    c.Name,
				Version: c.Version,
				Group:   c.Group,
				BOMRef:  c.BOMRef,
			})
		}

		if c.Components != nil {
			skipped += collect(*c.Components, dst)
		}
	}
	return skipped
}
