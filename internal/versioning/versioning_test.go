package versioning

import "testing"

func TestGet(t *testing.T) {
	t.Parallel()
	if _, ok := Get("pypi").(PEP440); !ok {
		t.Error("Get(pypi) should be PEP440")
	}
	for _, ds := range []string{"maven", "gradle-plugin", "unknown", ""} {
		if _, ok := Get(ds).(Maven); !ok {
			t.Errorf("Get(%q) should be Maven", ds)
		}
	}
}

func TestPEP440Ordering(t *testing.T) {
	t.Parallel()
	e := PEP440{}
	// Canonical PEP 440 ascending order.
	asc := []string{
		"1.0.dev1", "1.0a1", "1.0b1", "1.0rc1", "1.0", "1.0.post1", "1.0.1", "1.1", "2.0",
	}
	for i := range asc {
		for j := i + 1; j < len(asc); j++ {
			if e.Compare(asc[i], asc[j]) != -1 {
				t.Errorf("Compare(%q,%q) != -1", asc[i], asc[j])
			}
			if e.Compare(asc[j], asc[i]) != 1 {
				t.Errorf("Compare(%q,%q) != 1", asc[j], asc[i])
			}
		}
	}
	for _, eq := range [][2]string{{"1.0", "1.0.0"}, {"1.0", "v1.0"}, {"1.0rc1", "1.0c1"}, {"2.0", "2.0+local"}} {
		if e.Compare(eq[0], eq[1]) != 0 {
			t.Errorf("Compare(%q,%q) != 0", eq[0], eq[1])
		}
	}
}

func TestPEP440Stability(t *testing.T) {
	t.Parallel()
	e := PEP440{}
	stable := []string{"1.0", "1.0.0", "2.33.0", "1.0.post1"}
	unstable := []string{"1.0rc1", "1.0a1", "1.0b2", "1.0.dev1", "2.0.0rc1"}
	for _, v := range stable {
		if !e.IsStable(v) {
			t.Errorf("IsStable(%q) = false, want true", v)
		}
	}
	for _, v := range unstable {
		if e.IsStable(v) {
			t.Errorf("IsStable(%q) = true, want false", v)
		}
	}
}

func TestPEP440UpgradeAndType(t *testing.T) {
	t.Parallel()
	e := PEP440{}
	// requests 2.32.5 → 2.33.0 is a minor upgrade; an rc is not proposed.
	if got := e.SelectUpgrade("2.32.5", []string{"2.31.0", "2.32.5", "2.33.0", "3.0.0rc1"}); got != "2.33.0" {
		t.Errorf("SelectUpgrade = %q, want 2.33.0", got)
	}
	if e.IsUpgrade("2.0", "1.9") {
		t.Error("downgrade must not be an upgrade")
	}
	cases := map[[2]string]string{
		{"1.0", "2.0"}:       "major",
		{"1.0", "1.1"}:       "minor",
		{"1.0.0", "1.0.1"}:   "patch",
		{"2.32.5", "2.33.0"}: "minor",
		{"1.0", "1.0"}:       "",
	}
	for in, want := range cases {
		if got := e.UpdateType(in[0], in[1]); got != want {
			t.Errorf("UpdateType(%q,%q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

// TestMavenDelegation sanity-checks the Maven wrapper delegates to mavenver.
func TestMavenDelegation(t *testing.T) {
	t.Parallel()
	m := Maven{}
	if m.Compare("4.1.133.Final", "4.2.15.Final") != -1 {
		t.Error("Maven.Compare delegation broken")
	}
	if m.SelectUpgrade("1.79", []string{"1.80", "1.79"}) != "1.80" {
		t.Error("Maven.SelectUpgrade delegation broken")
	}
}
