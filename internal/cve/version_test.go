package cve

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   int
	}{
		{"3.9.4", "3.9.4", 0},
		{"3.9.4", "3.9.5", -1},
		{"3.10.0", "3.9.9", 1}, // numeric, not lexicographic
		{"4.0.0", "3.99.99", 1},
		{"3.9", "3.9.0", 0},
		{"v3.9.4", "3.9.4", 0},
		{"5.0.3", "5.0.10", -1},
	}

	for _, tc := range tests {
		if got := CompareVersions(tc.v1, tc.v2); got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.v1, tc.v2, got, tc.want)
		}
	}
}

// TestIsVersionComplete guards the bug where an imprecise version like "3.x"
// parsed as 0 and therefore matched every CVE range starting at 0.0.0.
func TestIsVersionComplete(t *testing.T) {
	tests := []struct {
		v    string
		want bool
	}{
		{"3.9.4", true},
		{"4.2", true},
		{"3.x", false},
		{"x", false},
		{"", false},
		{"3", false},
		{"unknown", false},
	}

	for _, tc := range tests {
		if got := IsVersionComplete(tc.v); got != tc.want {
			t.Errorf("IsVersionComplete(%q) = %v, want %v", tc.v, got, tc.want)
		}
	}
}

func TestMatchConstraintRange(t *testing.T) {
	tests := []struct {
		version, expr string
		want          bool
	}{
		{"4.2.0", ">= 4.0.0, < 4.2.8", true},
		{"4.2.8", ">= 4.0.0, < 4.2.8", false},
		{"3.9.0", ">= 4.0.0, < 4.2.8", false},
		{"3.10.11", "<= 3.10.11", true},
		{"3.10.12", "<= 3.10.11", false},
		{"3.9.4", "= 3.9.4", true},
		{"3.x", ">= 3.0.0", false}, // imprecise version never matches
		{"3.9.4", "", false},       // empty constraint never matches
		{"3.9.4", "~> 3.9", false}, // unparseable operator is not a match
	}

	for _, tc := range tests {
		if got := MatchConstraintRange(tc.version, tc.expr); got != tc.want {
			t.Errorf("MatchConstraintRange(%q, %q) = %v, want %v", tc.version, tc.expr, got, tc.want)
		}
	}
}

func TestVersionRangeContains(t *testing.T) {
	tests := []struct {
		name    string
		r       VersionRange
		version string
		want    bool
	}{
		{"inside fixed range", VersionRange{Introduced: "4.0.0", Fixed: "4.2.8"}, "4.2.7", true},
		{"at fixed boundary", VersionRange{Introduced: "4.0.0", Fixed: "4.2.8"}, "4.2.8", false},
		{"below introduced", VersionRange{Introduced: "4.0.0", Fixed: "4.2.8"}, "3.10.0", false},
		{"last affected inclusive", VersionRange{Introduced: "1.5.0", LastAffected: "3.9.4"}, "3.9.4", true},
		{"beyond last affected", VersionRange{Introduced: "1.5.0", LastAffected: "3.9.4"}, "3.9.5", false},
		{"open upper bound", VersionRange{LastAffected: "3.6.3"}, "3.6.0", true},
		// An entirely unbounded range must never match, or every advisory
		// would be reported against every target.
		{"unbounded", VersionRange{}, "3.9.4", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.Contains(tc.version); got != tc.want {
				t.Errorf("Contains(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}
