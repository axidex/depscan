// Package outdated compares a component's pinned version against the latest
// version published in its ecosystem registry and classifies the gap as
// patch/minor/major. Registries are reached through the RegistryChecker
// interface so unsupported ecosystems degrade to "unknown" rather than failing
// the scan.
package outdated

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/axidex/depscan/internal/purl"
)

// UpdateKind classifies the distance between the current and latest version.
type UpdateKind string

const (
	// KindUnknown means the latest version could not be determined (unsupported
	// ecosystem or an unreachable/erroring registry).
	KindUnknown UpdateKind = "unknown"
	// KindUpToDate means the current version is the latest (or newer).
	KindUpToDate UpdateKind = "up-to-date"
	// KindPatch means only the patch component is behind.
	KindPatch UpdateKind = "patch"
	// KindMinor means the minor component is behind.
	KindMinor UpdateKind = "minor"
	// KindMajor means the major component is behind.
	KindMajor UpdateKind = "major"
	// KindNewer means a newer version exists but the gap could not be classified
	// because one of the versions is not valid semver (e.g. some Maven versions).
	KindNewer UpdateKind = "newer"
)

// ErrUnsupported is returned by registry checkers for ecosystems not yet
// implemented.
var ErrUnsupported = errors.New("outdated: unsupported ecosystem")

// Result is the outcome of an outdated check for one component.
type Result struct {
	Current string
	Latest  string
	Kind    UpdateKind
	// Err holds the (non-fatal) reason a check could not complete, if any.
	Err error
}

// Known reports whether the latest version was successfully determined.
func (r Result) Known() bool {
	return r.Kind != KindUnknown
}

// Classify compares current against latest and reports the kind of update gap.
// Both versions are parsed leniently; when either is not valid semver it
// degrades to a string comparison ("newer exists" vs "up-to-date").
func Classify(current, latest string) UpdateKind {
	current = strings.TrimSpace(current)
	latest = strings.TrimSpace(latest)
	if latest == "" {
		return KindUnknown
	}

	cv, cerr := semver.NewVersion(current)
	lv, lerr := semver.NewVersion(latest)
	if cerr != nil || lerr != nil {
		if strings.EqualFold(current, latest) {
			return KindUpToDate
		}
		return KindNewer
	}

	if lv.Compare(cv) <= 0 {
		return KindUpToDate
	}
	switch {
	case lv.Major() > cv.Major():
		return KindMajor
	case lv.Minor() > cv.Minor():
		return KindMinor
	default:
		return KindPatch
	}
}

// RegistryChecker resolves the latest published version of a package for a
// single ecosystem.
type RegistryChecker interface {
	// Ecosystem is the purl type this checker handles (e.g. "npm").
	Ecosystem() string
	// Latest returns the latest version string for the given package.
	Latest(ctx context.Context, p purl.PURL) (string, error)
}

// Checker routes components to per-ecosystem registry checkers and classifies
// the version gap. It never returns an error from Check: failures are folded
// into a KindUnknown result so a single flaky registry cannot fail the scan.
type Checker struct {
	registries map[string]RegistryChecker
	logger     *slog.Logger
}

// NewChecker builds a Checker from the given registry checkers, keyed by their
// reported ecosystem.
func NewChecker(registries ...RegistryChecker) *Checker {
	m := make(map[string]RegistryChecker, len(registries))
	for _, r := range registries {
		m[r.Ecosystem()] = r
	}
	return &Checker{registries: m, logger: slog.New(slog.DiscardHandler)}
}

// WithLogger attaches a slog.Logger for debug diagnostics and returns the
// Checker for chaining. A nil logger is ignored.
func (c *Checker) WithLogger(l *slog.Logger) *Checker {
	if l != nil {
		c.logger = l
	}
	return c
}

// Check resolves the latest version for rawPURL/current and classifies the gap.
func (c *Checker) Check(ctx context.Context, rawPURL, current string) Result {
	p, err := purl.Parse(rawPURL)
	if err != nil {
		return Result{Current: current, Kind: KindUnknown, Err: err}
	}

	reg, ok := c.registries[p.Type]
	if !ok {
		c.logger.DebugContext(ctx, "outdated: unsupported ecosystem",
			"purl", rawPURL, "ecosystem", p.Type)
		return Result{Current: current, Kind: KindUnknown, Err: ErrUnsupported}
	}

	latest, err := reg.Latest(ctx, p)
	if err != nil {
		c.logger.DebugContext(ctx, "outdated: registry lookup failed (degrading to unknown)",
			"purl", rawPURL, "ecosystem", p.Type, "err", err)
		return Result{Current: current, Kind: KindUnknown, Err: err}
	}

	kind := Classify(current, latest)
	c.logger.DebugContext(ctx, "outdated: resolved",
		"purl", rawPURL, "current", current, "latest", latest, "kind", string(kind))
	return Result{
		Current: current,
		Latest:  latest,
		Kind:    kind,
	}
}
