package mavenver

import "testing"

// TestCompareOrdering walks Maven's canonical version order and asserts every
// adjacent pair compares strictly less-than, plus the reverse and equality.
func TestCompareOrdering(t *testing.T) {
	t.Parallel()

	// Each inner slice is a strictly ascending run per Maven's ComparableVersion.
	ascending := [][]string{
		{"1", "1.1"},
		{"1-snapshot", "1", "1-sp"},
		{"1-foo2", "1-foo10"},
		{"1.foo", "1-foo", "1-1", "1.1"},
		{
			"1.0-alpha-1", "1.0-alpha-2",
			"1.0-beta-1",
			"1.0-milestone-1",
			"1.0-rc-1",
			"1.0-snapshot",
			"1.0",
			"1.0-sp",
		},
		// Real findings from the appsec scan.
		{"4.1.133.Final", "4.2.1.Final", "4.2.15.Final"},
		{"6.6.18.Final", "7.3.4.Final"},
		{"1.79", "1.80", "1.84"},
		{"5.0.0.CR7", "5.0.0"}, // a release outranks its own release candidate
	}

	for _, run := range ascending {
		for i := range run {
			for j := i + 1; j < len(run); j++ {
				a, b := run[i], run[j]
				if got := Compare(a, b); got != -1 {
					t.Errorf("Compare(%q, %q) = %d, want -1", a, b, got)
				}
				if got := Compare(b, a); got != 1 {
					t.Errorf("Compare(%q, %q) = %d, want 1", b, a, got)
				}
			}
		}
	}
}

func TestCompareEqual(t *testing.T) {
	t.Parallel()

	equal := [][2]string{
		{"1", "1.0"},
		{"1", "1.0.0"},
		{"1.0.0", "1.0.0.Final"},
		{"1.0.0", "1.0.0.GA"},
		{"1.0.0", "1.0.0-release"},
		{"1-ga", "1"},
		{"1-cr1", "1-rc1"},
		{"1-alpha1", "1-a1"},
		{"1-beta1", "1-b1"},
		{"1-milestone1", "1-m1"},
		{"4.1.133.FINAL", "4.1.133.Final"}, // case-insensitive
	}
	for _, pair := range equal {
		if got := Compare(pair[0], pair[1]); got != 0 {
			t.Errorf("Compare(%q, %q) = %d, want 0", pair[0], pair[1], got)
		}
	}
}

func TestIsStable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		v    string
		want bool
	}{
		{"4.2.15.Final", true},
		{"1.84", true},
		{"5.0.0", true},
		{"1.0.0-sp1", true}, // service pack sorts after release → stable
		{"5.0.0.CR7", false},
		{"5.0.0-rc7", false},
		{"2.0.0.Alpha3", false},
		{"6.0.0-alpha-1", false},
		{"1.0.0-beta", false},
		{"3.0.0-milestone-2", false},
		{"1.0.0-SNAPSHOT", false},
	}
	for _, tt := range tests {
		if got := IsStable(tt.v); got != tt.want {
			t.Errorf("IsStable(%q) = %v, want %v", tt.v, got, tt.want)
		}
	}
}

// TestUpdateType checks major/minor/patch bucketing, including non-semver Maven
// versions (.Final) and non-upgrades (equal/downgrade -> "").
func TestUpdateType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		current, target, want string
	}{
		{"1.2.3", "2.0.0", UpdateMajor},
		{"1.2.3", "1.3.0", UpdateMinor},
		{"1.2.3", "1.2.4", UpdatePatch},
		{"4.1.133.Final", "4.2.15.Final", UpdateMinor},
		{"4.1.133.Final", "5.0.0.Final", UpdateMajor},
		{"1.79", "1.80", UpdateMinor}, // 1.79 = major 1, minor 79 → 1.80 bumps minor
		{"1.2", "1.2.1", UpdatePatch},
		{"1.2.3", "1.2.3", ""}, // equal: not an upgrade
		{"2.0.0", "1.9.9", ""}, // downgrade: not an upgrade
		{"3.6.0.Final", "3.6.1.Final", UpdatePatch},
	}
	for _, tt := range tests {
		if got := UpdateType(tt.current, tt.target); got != tt.want {
			t.Errorf("UpdateType(%q, %q) = %q, want %q", tt.current, tt.target, got, tt.want)
		}
	}
}

func TestSelectUpgrade(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		current    string
		candidates []string
		want       string
	}{
		{
			name:       "picks newest stable, ignores rc/alpha and older",
			current:    "4.1.133.Final",
			candidates: []string{"4.1.119.Final", "4.1.133.Final", "4.2.1.Final", "4.2.15.Final", "5.0.0.CR1", "4.2.16.Alpha1"},
			want:       "4.2.15.Final",
		},
		{
			name:       "no upgrade when only downgrades/equal/prerelease offered",
			current:    "7.3.4.Final",
			candidates: []string{"6.6.18.Final", "7.3.4.Final", "8.0.0.CR1"},
			want:       "",
		},
		{
			name:       "empty candidates",
			current:    "1.0",
			candidates: nil,
			want:       "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := SelectUpgrade(tt.current, tt.candidates); got != tt.want {
				t.Errorf("SelectUpgrade(%q, %v) = %q, want %q", tt.current, tt.candidates, got, tt.want)
			}
		})
	}
}

func TestIsUpgrade(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		current, latest string
		want            bool
	}{
		{"genuine minor bump", "4.1.133.Final", "4.2.15.Final", true},
		{"genuine patch bump", "1.79", "1.84", true},
		{"registry returned a downgrade", "7.3.4.Final", "6.6.18.Final", false},
		{"registry returned a release candidate", "4.5.27", "5.0.0.CR7", false},
		{"registry returned an alpha", "2.1.1", "2.0.0.Alpha3", false},
		{"already latest", "1.84", "1.84", false},
		{"rc-on-rc allowed", "5.0.0.CR6", "5.0.0.CR7", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsUpgrade(tt.current, tt.latest); got != tt.want {
				t.Errorf("IsUpgrade(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
			}
		})
	}
}
