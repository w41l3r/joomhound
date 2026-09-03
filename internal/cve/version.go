package cve

import (
	"strconv"
	"strings"
)

// CompareVersions compares two dotted version strings.
// Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
//
// Non-numeric segments are handled: a numeric prefix is used when present
// ("10-beta" -> 10) and a purely alphabetic segment sorts before a numeric one
// (so "3.9.0-rc" < "3.9.0"). This replaces the old fmt.Sscanf approach, which
// silently returned 0 for anything non-numeric and therefore treated
// "3.x" as "0" - matching every CVE range that started at 0.
func CompareVersions(v1, v2 string) int {
	p1 := splitVersion(v1)
	p2 := splitVersion(v2)

	n := len(p1)
	if len(p2) > n {
		n = len(p2)
	}

	for i := 0; i < n; i++ {
		var a, b int
		if i < len(p1) {
			a = p1[i]
		}
		if i < len(p2) {
			b = p2[i]
		}
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
	}
	return 0
}

func splitVersion(v string) []int {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return nil
	}
	raw := strings.Split(v, ".")
	out := make([]int, 0, len(raw))
	for _, seg := range raw {
		out = append(out, parseSegment(seg))
	}
	return out
}

// parseSegment extracts the leading integer of a version segment.
// "10" -> 10, "10rc1" -> 10, "x" -> -1 (wildcard/unknown sorts low).
func parseSegment(seg string) int {
	seg = strings.TrimSpace(seg)
	end := 0
	for end < len(seg) && seg[end] >= '0' && seg[end] <= '9' {
		end++
	}
	if end == 0 {
		return -1
	}
	n, err := strconv.Atoi(seg[:end])
	if err != nil {
		return -1
	}
	return n
}

// IsVersionComplete reports whether a version string is precise enough to
// compare against CVE ranges. Values like "3.x" or "" are not, and matching
// them against ranges produces garbage, so callers should skip range checks
// and fall back to a lower-confidence signal.
func IsVersionComplete(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	segs := splitVersion(v)
	if len(segs) < 2 {
		return false
	}
	for _, s := range segs {
		if s < 0 {
			return false
		}
	}
	return true
}

// MatchConstraintRange evaluates a comma-separated constraint expression of
// the form used by the GitHub Advisory Database, e.g.:
//
//	">= 4.0.0, < 4.2.8"
//	"<= 3.10.11"
//	"= 3.9.4"
//
// All constraints must hold (logical AND). An unparseable expression returns
// false rather than a false positive.
func MatchConstraintRange(version, expr string) bool {
	if !IsVersionComplete(version) || strings.TrimSpace(expr) == "" {
		return false
	}

	parts := strings.Split(expr, ",")
	matched := 0

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		op, operand := splitConstraint(part)
		if operand == "" {
			return false
		}

		c := CompareVersions(version, operand)
		ok := false
		switch op {
		case ">=":
			ok = c >= 0
		case ">":
			ok = c > 0
		case "<=":
			ok = c <= 0
		case "<":
			ok = c < 0
		case "=", "==":
			ok = c == 0
		default:
			return false
		}
		if !ok {
			return false
		}
		matched++
	}

	return matched > 0
}

func splitConstraint(part string) (op, operand string) {
	for _, candidate := range []string{">=", "<=", "==", ">", "<", "="} {
		if strings.HasPrefix(part, candidate) {
			return candidate, strings.TrimSpace(strings.TrimPrefix(part, candidate))
		}
	}
	// Bare version means exact match.
	return "=", strings.TrimSpace(part)
}
