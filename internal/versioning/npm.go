package versioning

import (
	"regexp"
	"strconv"
	"strings"
)

// NPM implements npm/semver version ordering and the range-operator preservation
// needed to rewrite a package.json constraint when bumping (e.g. "^1.2.3" with a
// new version 1.5.0 → "^1.5.0").
type NPM struct{}

var semverRe = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

type semver struct {
	valid               bool
	major, minor, patch int
	pre                 []string
}

func parseSemver(s string) semver {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return semver{}
	}
	v := semver{valid: true}
	v.major, _ = strconv.Atoi(m[1])
	v.minor, _ = strconv.Atoi(m[2])
	v.patch, _ = strconv.Atoi(m[3])
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
	}
	return v
}

// stripRange removes a leading npm range operator or "v" prefix, leaving the base
// version ("^1.2.3" → "1.2.3", ">=2.0.0" → "2.0.0").
func stripRange(s string) string {
	return strings.TrimPrefix(strings.TrimLeft(strings.TrimSpace(s), "^~>=< "), "v")
}

func cmpSemver(a, b semver) int {
	if c := sign(a.major - b.major); c != 0 {
		return c
	}
	if c := sign(a.minor - b.minor); c != 0 {
		return c
	}
	if c := sign(a.patch - b.patch); c != 0 {
		return c
	}
	return cmpPrerelease(a.pre, b.pre)
}

// cmpPrerelease orders semver pre-release identifiers: a version with a
// pre-release is lower than one without; numeric identifiers compare numerically
// and below alphanumeric ones.
func cmpPrerelease(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := range min(len(a), len(b)) {
		an, aerr := strconv.Atoi(a[i])
		bn, berr := strconv.Atoi(b[i])
		switch {
		case aerr == nil && berr == nil:
			if c := sign(an - bn); c != 0 {
				return c
			}
		case aerr == nil:
			return -1
		case berr == nil:
			return 1
		default:
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		}
	}
	return sign(len(a) - len(b))
}

// Compare orders two npm version values (range operators stripped). Unparseable
// inputs fall back to a byte comparison.
func (NPM) Compare(a, b string) int {
	sa, sb := stripRange(a), stripRange(b)
	pa, pb := parseSemver(sa), parseSemver(sb)
	if !pa.valid || !pb.valid {
		return sign(strings.Compare(sa, sb))
	}
	return cmpSemver(pa, pb)
}

// IsStable reports whether v has no pre-release identifier.
func (NPM) IsStable(v string) bool {
	p := parseSemver(stripRange(v))
	return p.valid && len(p.pre) == 0
}

// IsUpgrade reports whether candidate is newer than current and acceptable.
func (e NPM) IsUpgrade(current, candidate string) bool {
	if e.Compare(candidate, current) <= 0 {
		return false
	}
	return e.IsStable(candidate) || !e.IsStable(current)
}

// UpdateType classifies the bump by the first differing semver component.
func (e NPM) UpdateType(current, target string) string {
	if e.Compare(target, current) <= 0 {
		return ""
	}
	c, t := parseSemver(stripRange(current)), parseSemver(stripRange(target))
	switch {
	case t.major != c.major:
		return mavenMajor
	case t.minor != c.minor:
		return mavenMinor
	default:
		return mavenPatch
	}
}

// SelectUpgrade returns the newest candidate that is a valid upgrade, or "".
func (e NPM) SelectUpgrade(current string, candidates []string) string {
	best := ""
	for _, c := range candidates {
		if !e.IsUpgrade(current, c) {
			continue
		}
		if best == "" || e.Compare(c, best) > 0 {
			best = c
		}
	}
	return best
}

// NewValue preserves a leading "^" or "~" from currentValue; an exact constraint
// stays exact.
func (NPM) NewValue(currentValue, newVersion string) string {
	switch cv := strings.TrimSpace(currentValue); {
	case strings.HasPrefix(cv, "^"):
		return "^" + newVersion
	case strings.HasPrefix(cv, "~"):
		return "~" + newVersion
	default:
		return newVersion
	}
}
