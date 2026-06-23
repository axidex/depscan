package purl_test

import (
	"testing"

	"github.com/axidex/depscan/internal/purl"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		raw       string
		wantType  string
		wantNS    string
		wantName  string
		wantVer   string
		wantError bool
	}{
		{
			name:     "npm simple",
			raw:      "pkg:npm/lodash@4.17.20",
			wantType: "npm",
			wantName: "lodash",
			wantVer:  "4.17.20",
		},
		{
			name:     "npm scoped",
			raw:      "pkg:npm/%40babel/core@7.0.0",
			wantType: "npm",
			wantNS:   "@babel",
			wantName: "core",
			wantVer:  "7.0.0",
		},
		{
			name:     "maven group and artifact",
			raw:      "pkg:maven/com.google.guava/guava@30.0-jre",
			wantType: "maven",
			wantNS:   "com.google.guava",
			wantName: "guava",
			wantVer:  "30.0-jre",
		},
		{
			name:     "pypi no version",
			raw:      "pkg:pypi/requests",
			wantType: "pypi",
			wantName: "requests",
		},
		{
			name:      "empty",
			raw:       "",
			wantError: true,
		},
		{
			name:      "garbage",
			raw:       "not-a-purl",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := purl.Parse(tt.raw)
			if tt.wantError {
				if err == nil {
					t.Fatalf("Parse(%q) = %+v, want error", tt.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.raw, err)
			}
			if got.Type != tt.wantType || got.Namespace != tt.wantNS || got.Name != tt.wantName || got.Version != tt.wantVer {
				t.Errorf("Parse(%q) = {Type:%q NS:%q Name:%q Ver:%q}, want {Type:%q NS:%q Name:%q Ver:%q}",
					tt.raw, got.Type, got.Namespace, got.Name, got.Version,
					tt.wantType, tt.wantNS, tt.wantName, tt.wantVer)
			}
		})
	}
}

func TestPURL_Coordinates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "no namespace", raw: "pkg:npm/lodash@4.17.20", want: "lodash"},
		{name: "scoped npm", raw: "pkg:npm/%40babel/core@7.0.0", want: "@babel/core"},
		{name: "maven", raw: "pkg:maven/com.google.guava/guava@30.0-jre", want: "com.google.guava/guava"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := purl.Parse(tt.raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := p.Coordinates(); got != tt.want {
				t.Errorf("Coordinates() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPURL_WithoutVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "npm", raw: "pkg:npm/lodash@4.17.20", want: "pkg:npm/lodash"},
		{name: "scoped npm", raw: "pkg:npm/%40babel/core@7.0.0", want: "pkg:npm/@babel/core"},
		{name: "maven", raw: "pkg:maven/com.google.guava/guava@30.0-jre", want: "pkg:maven/com.google.guava/guava"},
		{name: "pypi", raw: "pkg:pypi/requests@2.20.0", want: "pkg:pypi/requests"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := purl.Parse(tt.raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := p.WithoutVersion(); got != tt.want {
				t.Errorf("WithoutVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}
