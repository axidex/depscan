package versioning

import (
	"regexp"
	"strconv"
	"strings"
)

// PEP440 implements Python (PEP 440) version ordering and stability. It mirrors
// the comparison key used by the `packaging` library: epoch, release (trailing
// zeros stripped), then pre / post / dev components with the right "before /
// after the release" semantics.
type PEP440 struct{}

var pep440Re = regexp.MustCompile(`(?i)^\s*v?(?:(\d+)!)?(\d+(?:\.\d+)*)` +
	`(?:[._-]?(a|b|c|rc|alpha|beta|pre|preview)[._-]?(\d*))?` +
	`(?:[._-]?(post|rev|r)[._-]?(\d*))?` +
	`(?:[._-]?(dev)[._-]?(\d*))?` +
	`(?:\+[a-z0-9][a-z0-9._-]*)?\s*$`)

type pep440Ver struct {
	valid   bool
	epoch   int
	release []int
	hasPre  bool
	preRank int
	preNum  int
	hasPost bool
	postNum int
	hasDev  bool
	devNum  int
}

func parsePEP440(s string) pep440Ver {
	m := pep440Re.FindStringSubmatch(s)
	if m == nil {
		return pep440Ver{}
	}
	v := pep440Ver{valid: true, epoch: atoiOr(m[1], 0)}
	for p := range strings.SplitSeq(m[2], ".") {
		v.release = append(v.release, atoiOr(p, 0))
	}
	if m[3] != "" {
		v.hasPre, v.preRank, v.preNum = true, preRank(m[3]), atoiOr(m[4], 0)
	}
	if m[5] != "" {
		v.hasPost, v.postNum = true, atoiOr(m[6], 0)
	}
	if m[7] != "" {
		v.hasDev, v.devNum = true, atoiOr(m[8], 0)
	}
	return v
}

func preRank(s string) int {
	switch strings.ToLower(s) {
	case "a", "alpha":
		return 1
	case "b", "beta":
		return 2
	default: // c, rc, pre, preview
		return 3
	}
}

func atoiOr(s string, d int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return d
}

// sortKey is one comparable component; kind orders -inf (-1) < tuple (0) < +inf (1).
type sortKey struct{ kind, rank, num int }

func (a sortKey) cmp(b sortKey) int {
	if a.kind != b.kind {
		return sign(a.kind - b.kind)
	}
	if a.rank != b.rank {
		return sign(a.rank - b.rank)
	}
	return sign(a.num - b.num)
}

func (v pep440Ver) preKey() sortKey {
	switch {
	case !v.hasPre && !v.hasPost && v.hasDev:
		return sortKey{kind: -1} // a pure dev release sorts before the release
	case !v.hasPre:
		return sortKey{kind: 1} // a final (or post) release sorts after any pre
	default:
		return sortKey{kind: 0, rank: v.preRank, num: v.preNum}
	}
}

func (v pep440Ver) postKey() sortKey {
	if v.hasPost {
		return sortKey{kind: 0, num: v.postNum}
	}
	return sortKey{kind: -1}
}

func (v pep440Ver) devKey() sortKey {
	if v.hasDev {
		return sortKey{kind: 0, num: v.devNum}
	}
	return sortKey{kind: 1}
}

func (v pep440Ver) cmp(o pep440Ver) int {
	if c := sign(v.epoch - o.epoch); c != 0 {
		return c
	}
	if c := cmpRelease(stripTrailingZeros(v.release), stripTrailingZeros(o.release)); c != 0 {
		return c
	}
	if c := v.preKey().cmp(o.preKey()); c != 0 {
		return c
	}
	if c := v.postKey().cmp(o.postKey()); c != 0 {
		return c
	}
	return v.devKey().cmp(o.devKey())
}

func cmpRelease(a, b []int) int {
	for i := range max(len(a), len(b)) {
		if c := sign(at(a, i) - at(b, i)); c != 0 {
			return c
		}
	}
	return 0
}

func at(s []int, i int) int {
	if i < len(s) {
		return s[i]
	}
	return 0
}

func stripTrailingZeros(r []int) []int {
	end := len(r)
	for end > 1 && r[end-1] == 0 {
		end--
	}
	return r[:end]
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// Compare orders two PEP 440 versions. If either is unparseable it falls back to
// a byte comparison so behavior stays total.
func (PEP440) Compare(a, b string) int {
	pa, pb := parsePEP440(a), parsePEP440(b)
	if !pa.valid || !pb.valid {
		return strings.Compare(a, b)
	}
	return pa.cmp(pb)
}

// IsStable reports whether v is a final/post release (no pre-release or dev).
func (PEP440) IsStable(v string) bool {
	p := parsePEP440(v)
	return p.valid && !p.hasPre && !p.hasDev
}

// IsUpgrade reports whether candidate is newer than current and acceptable to
// ship (a pre-release only when current is itself a pre-release).
func (e PEP440) IsUpgrade(current, candidate string) bool {
	if e.Compare(candidate, current) <= 0 {
		return false
	}
	return e.IsStable(candidate) || !e.IsStable(current)
}

// UpdateType classifies an upgrade by the first differing release segment.
func (e PEP440) UpdateType(current, target string) string {
	if e.Compare(target, current) <= 0 {
		return ""
	}
	c, t := parsePEP440(current).release, parsePEP440(target).release
	switch {
	case at(t, 0) != at(c, 0):
		return mavenMajor
	case at(t, 1) != at(c, 1):
		return mavenMinor
	default:
		return mavenPatch
	}
}

// NewValue returns newVersion unchanged: our PyPI manager edits "==" pins.
func (PEP440) NewValue(_, newVersion string) string { return newVersion }

// SelectUpgrade returns the newest candidate that is a valid upgrade, or "".
func (e PEP440) SelectUpgrade(current string, candidates []string) string {
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

// Update-type labels, shared with mavenver's values.
const (
	mavenMajor = "major"
	mavenMinor = "minor"
	mavenPatch = "patch"
)
