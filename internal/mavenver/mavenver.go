// Package mavenver compares Maven version strings using the same algorithm as
// Apache Maven's org.apache.maven.artifact.versioning.ComparableVersion. It is a
// clean-room Go port of that public algorithm (Apache-2.0 reference), needed
// because Maven versions ("4.1.133.Final", "5.0.0.CR7", "1.79") are not semver
// and a plain semver/string comparison both misorders them and reports
// downgrades or pre-releases as "newer".
//
// The two operations the remediation tool needs:
//
//	Compare(a, b)   — Maven's total order over version strings.
//	IsStable(v)     — false when v carries a pre-release qualifier
//	                  (alpha/beta/milestone/rc/snapshot), so release-candidate
//	                  and alpha "latest" versions are never proposed as upgrades.
package mavenver

import (
	"math/big"
	"slices"
	"strconv"
	"strings"
)

// Update types returned by UpdateType.
const (
	UpdateMajor = "major"
	UpdateMinor = "minor"
	UpdatePatch = "patch"
)

// kind tags the three item types Maven tokenizes a version into.
type kind int

const (
	kindInt kind = iota
	kindString
	kindList
)

// item is one token in a parsed version. The other item passed to compareTo may
// be nil, modeling Maven's comparison of a present item against an absent one
// (the shorter version is padded with nulls).
type item interface {
	kind() kind
	isNull() bool
	compareTo(item) int
}

// qualifiers is Maven's ordered list of well-known version qualifiers. The empty
// string is the release ("") slot; anything before it is a pre-release, "sp"
// (service pack) sorts after a release.
var qualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

// releaseIndex is the position of the release ("") qualifier.
var releaseIndex = indexOf(qualifiers, "")

// aliases maps qualifier synonyms onto their canonical form, exactly as Maven
// does: ga/final/release are releases; cr is a release candidate.
var aliases = map[string]string{
	"ga":      "",
	"final":   "",
	"release": "",
	"cr":      "rc",
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

// comparableQualifier yields a sortable key for a qualifier: its index among the
// known qualifiers, or len(qualifiers)+"-"+q for an unknown one (which therefore
// sorts after every known qualifier, including the release). Keys are compared
// as strings, matching Maven; single-digit indices keep numeric order and the
// "7-foo" form for unknowns stays greater than any "0".."6".
func comparableQualifier(q string) string {
	if i := indexOf(qualifiers, q); i != -1 {
		return strconv.Itoa(i)
	}
	return strconv.Itoa(len(qualifiers)) + "-" + q
}

// --- intItem ---

type intItem struct{ v *big.Int }

var intZero = &intItem{v: big.NewInt(0)}

func (it *intItem) kind() kind   { return kindInt }
func (it *intItem) isNull() bool { return it.v.Sign() == 0 }

func (it *intItem) compareTo(o item) int {
	if o == nil {
		// 1.0 == 1, but 1.1 > 1.
		if it.v.Sign() == 0 {
			return 0
		}
		return 1
	}
	switch o.kind() {
	case kindInt:
		oi, _ := o.(*intItem)
		return it.v.Cmp(oi.v)
	default:
		// 1.1 > 1-sp and 1.1 > 1-1: an int outranks a string or a sub-list.
		return 1
	}
}

// --- stringItem ---

type stringItem struct{ value string }

// newStringItem applies Maven's qualifier normalization: a lone a/b/m directly
// followed by a digit is alpha/beta/milestone, then synonyms collapse via
// aliases.
func newStringItem(value string, followedByDigit bool) *stringItem {
	if followedByDigit && len(value) == 1 {
		switch value[0] {
		case 'a':
			value = "alpha"
		case 'b':
			value = "beta"
		case 'm':
			value = "milestone"
		}
	}
	if a, ok := aliases[value]; ok {
		value = a
	}
	return &stringItem{value: value}
}

func (it *stringItem) kind() kind { return kindString }

// isNull is true for release-equivalent qualifiers ("", ga, final, release), so
// a trailing ".Final" normalizes away and "1.0.0.Final" == "1.0.0".
func (it *stringItem) isNull() bool {
	return comparableQualifier(it.value) == strconv.Itoa(releaseIndex)
}

func (it *stringItem) compareTo(o item) int {
	if o == nil {
		// 1-rc < 1, 1-ga == 1, 1-sp > 1.
		return strings.Compare(comparableQualifier(it.value), strconv.Itoa(releaseIndex))
	}
	switch o.kind() {
	case kindString:
		si, _ := o.(*stringItem)
		return strings.Compare(comparableQualifier(it.value), comparableQualifier(si.value))
	default:
		// 1.any < 1.1 and 1.any < 1-1: a string ranks below an int or a sub-list.
		return -1
	}
}

// --- listItem ---

type listItem struct{ items []item }

func (l *listItem) kind() kind   { return kindList }
func (l *listItem) isNull() bool { return len(l.items) == 0 }
func (l *listItem) add(it item)  { l.items = append(l.items, it) }

// normalize drops trailing null items so equivalent versions parse equal
// (1, 1.0, 1.0.0). It stops at the first non-null, non-list item.
func (l *listItem) normalize() {
	//nolint:modernize // removes interspersed null items while iterating; slices.Backward unsuitable
	for i := len(l.items) - 1; i >= 0; i-- {
		last := l.items[i]
		if last.isNull() {
			l.items = append(l.items[:i], l.items[i+1:]...)
		} else if last.kind() != kindList {
			break
		}
	}
}

func (l *listItem) compareTo(o item) int {
	if o == nil {
		if len(l.items) == 0 {
			return 0 // 1-0 == 1- == 1
		}
		return l.items[0].compareTo(nil)
	}
	switch o.kind() {
	case kindInt:
		return -1 // 1-1 < 1.0.x: a sub-list ranks below an int.
	case kindString:
		return 1 // 1-1 > 1-sp: a sub-list ranks above a string.
	default:
		ol, _ := o.(*listItem)
		n := max(len(l.items), len(ol.items))
		for i := range n {
			var left, right item
			if i < len(l.items) {
				left = l.items[i]
			}
			if i < len(ol.items) {
				right = ol.items[i]
			}
			var c int
			switch {
			case left == nil && right == nil:
				c = 0
			case left == nil:
				c = -right.compareTo(nil)
			default:
				c = left.compareTo(right)
			}
			if c != 0 {
				return c
			}
		}
		return 0
	}
}

// parse tokenizes a version into the nested item tree. '.' separates items in
// the current list; '-' opens a sub-list; a digit/non-digit boundary also splits
// and opens a sub-list, matching ComparableVersion.parseVersion.
func parse(version string) *listItem {
	version = strings.ToLower(version)
	root := &listItem{}
	cur := root
	stack := []*listItem{root}

	push := func() {
		nl := &listItem{}
		cur.add(nl)
		cur = nl
		stack = append(stack, nl)
	}

	isDigit := false
	start := 0
	for i := range len(version) {
		c := version[i]
		switch {
		case c == '.':
			if i == start {
				cur.add(intZero)
			} else {
				cur.add(parseItem(isDigit, version[start:i]))
			}
			start = i + 1
		case c == '-':
			if i == start {
				cur.add(intZero)
			} else {
				cur.add(parseItem(isDigit, version[start:i]))
			}
			start = i + 1
			push()
		case c >= '0' && c <= '9':
			if !isDigit && i > start {
				cur.add(newStringItem(version[start:i], true))
				start = i
				push()
			}
			isDigit = true
		default:
			if isDigit && i > start {
				cur.add(parseItem(true, version[start:i]))
				start = i
				push()
			}
			isDigit = false
		}
	}
	if len(version) > start {
		cur.add(parseItem(isDigit, version[start:]))
	}

	// Normalize children before parents so an emptied child reads as null to its
	// parent.
	for _, l := range slices.Backward(stack) {
		l.normalize()
	}
	return root
}

func parseItem(isDigit bool, buf string) item {
	if isDigit {
		buf = stripLeadingZeroes(buf)
		n, ok := new(big.Int).SetString(buf, 10)
		if !ok {
			return newStringItem(buf, false)
		}
		return &intItem{v: n}
	}
	return newStringItem(buf, false)
}

func stripLeadingZeroes(s string) string {
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

// Compare returns -1, 0 or +1 as a is older than, equal to, or newer than b,
// using Maven's version ordering.
func Compare(a, b string) int {
	c := parse(a).compareTo(parse(b))
	switch {
	case c < 0:
		return -1
	case c > 0:
		return 1
	default:
		return 0
	}
}

// IsStable reports whether v is a release (no alpha/beta/milestone/rc/snapshot
// qualifier). Service-pack ("sp") and unknown qualifiers are treated as stable,
// matching Maven's "after release" ordering.
func IsStable(v string) bool {
	return !hasPreRelease(parse(v))
}

func hasPreRelease(l *listItem) bool {
	rel := strconv.Itoa(releaseIndex)
	for _, it := range l.items {
		switch v := it.(type) {
		case *stringItem:
			if strings.Compare(comparableQualifier(v.value), rel) < 0 {
				return true
			}
		case *listItem:
			if hasPreRelease(v) {
				return true
			}
		}
	}
	return false
}

// IsUpgrade reports whether candidate is a strictly newer version than current
// that is also acceptable to ship: a pre-release candidate is rejected unless
// current is itself a pre-release (so an rc-on-rc bump is still allowed).
func IsUpgrade(current, candidate string) bool {
	if Compare(candidate, current) <= 0 {
		return false
	}
	return IsStable(candidate) || !IsStable(current)
}

// leadingInts returns the leading numeric components of a version (major, minor,
// patch, ...), stopping at the first non-numeric item. "4.1.133.Final" -> [4 1
// 133], "1.79" -> [1 79], "0.7.0-0.6.x-compat" -> [0 7 0].
func leadingInts(v string) []int64 {
	root := parse(v)
	out := make([]int64, 0, 3)
	for _, it := range root.items {
		ii, ok := it.(*intItem)
		if !ok {
			break
		}
		out = append(out, ii.v.Int64())
	}
	return out
}

func segAt(s []int64, i int) int64 {
	if i < len(s) {
		return s[i]
	}
	return 0
}

// UpdateType classifies an upgrade from current to target as "major", "minor",
// or "patch" by the first differing numeric segment. It returns "" when target
// is not strictly newer than current. This is the bucket key used by config
// (matchUpdateTypes) and the worker (separate branches per update type).
func UpdateType(current, target string) string {
	if Compare(target, current) <= 0 {
		return ""
	}
	c, t := leadingInts(current), leadingInts(target)
	switch {
	case segAt(t, 0) != segAt(c, 0):
		return UpdateMajor
	case segAt(t, 1) != segAt(c, 1):
		return UpdateMinor
	default:
		return UpdatePatch
	}
}

// SelectUpgrade returns the newest candidate that is a valid upgrade over
// current (per IsUpgrade), or "" when none qualifies. This is the datasource ->
// versioning step: given every version a registry knows, pick the bump target.
func SelectUpgrade(current string, candidates []string) string {
	best := ""
	for _, c := range candidates {
		if !IsUpgrade(current, c) {
			continue
		}
		if best == "" || Compare(c, best) > 0 {
			best = c
		}
	}
	return best
}
