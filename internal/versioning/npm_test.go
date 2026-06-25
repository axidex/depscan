package versioning

import "testing"

func TestNPMOrderingAndStability(t *testing.T) {
	t.Parallel()
	e := NPM{}
	asc := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0"}
	for i := range asc {
		for j := i + 1; j < len(asc); j++ {
			if e.Compare(asc[i], asc[j]) != -1 {
				t.Errorf("Compare(%q,%q) != -1", asc[i], asc[j])
			}
		}
	}
	// Range operators are stripped before comparison.
	if e.Compare("^1.2.3", "1.2.3") != 0 || e.Compare("~1.2.0", "1.5.0") != -1 {
		t.Error("range operators not stripped for comparison")
	}
	if !e.IsStable("1.2.3") || e.IsStable("1.2.3-rc.1") || !e.IsStable("^4.17.20") {
		t.Error("IsStable wrong")
	}
}

func TestNPMSelectAndType(t *testing.T) {
	t.Parallel()
	e := NPM{}
	if got := e.SelectUpgrade("^4.17.0", []string{"4.17.20", "4.17.21", "5.0.0-rc.1"}); got != "4.17.21" {
		t.Errorf("SelectUpgrade = %q, want 4.17.21 (rc rejected, newest stable)", got)
	}
	cases := map[[2]string]string{
		{"^1.2.3", "2.0.0"}: "major",
		{"^1.2.3", "1.3.0"}: "minor",
		{"~1.2.3", "1.2.5"}: "patch",
	}
	for in, want := range cases {
		if got := e.UpdateType(in[0], in[1]); got != want {
			t.Errorf("UpdateType(%q,%q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestNPMNewValue(t *testing.T) {
	t.Parallel()
	e := NPM{}
	tests := map[[2]string]string{
		{"^1.2.3", "1.5.0"}: "^1.5.0",
		{"~1.2.3", "1.2.9"}: "~1.2.9",
		{"1.2.3", "1.5.0"}:  "1.5.0",
	}
	for in, want := range tests {
		if got := e.NewValue(in[0], in[1]); got != want {
			t.Errorf("NewValue(%q,%q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}
