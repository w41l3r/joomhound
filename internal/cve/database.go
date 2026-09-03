package cve

import (
	"sort"
	"strings"
	"sync"
)

// CVEEntry is an offline vulnerability record shipped with the binary.
type CVEEntry struct {
	CVE         string
	Title       string
	Description string
	CVSS        float64
	Severity    string

	// Ranges are the affected-version windows. An entry with no ranges is
	// never reported by SearchByVersion: an unbounded entry would match every
	// target and generate a false positive in a client report.
	Ranges []VersionRange

	// AffectedComponents lists the Joomla extensions involved, with or
	// without the "com_" prefix (e.g. "com_fields" or "fields").
	AffectedComponents []string

	PublishedDate string
	UpdatedDate   string
	References    []string
	PoC           string
	// IsPublic reports whether a public exploit/PoC is known.
	IsPublic bool
}

// Affects reports whether version falls in any of the entry's ranges.
func (e CVEEntry) Affects(version string) bool {
	if !IsVersionComplete(version) {
		return false
	}
	for _, r := range e.Ranges {
		if r.Contains(version) {
			return true
		}
	}
	return false
}

// PrimaryReference returns the first reference, or "" when there are none.
// The scanner previously indexed References[0] directly, which panics on any
// entry without references.
func (e CVEEntry) PrimaryReference() string {
	if len(e.References) == 0 {
		return ""
	}
	return e.References[0]
}

// SeverityLabel returns the stored severity or derives one from the CVSS.
func (e CVEEntry) SeverityLabel() string {
	if e.Severity != "" {
		return strings.ToUpper(e.Severity)
	}
	return Advisory{CVSS: e.CVSS}.SeverityLabel()
}

// ToAdvisory converts the offline entry into the normalized Advisory shape
// used by the online providers, so both paths feed one reporting pipeline.
func (e CVEEntry) ToAdvisory() Advisory {
	return Advisory{
		ID:          strings.ToUpper(e.CVE),
		Title:       e.Title,
		Description: e.Description,
		CVSS:        e.CVSS,
		Severity:    e.SeverityLabel(),
		References:  e.References,
		Ranges:      e.Ranges,
		Source:      "offline",
	}
}

// Database is the built-in CVE store. It is safe for concurrent use.
type Database struct {
	mu      sync.RWMutex
	entries map[string]CVEEntry
}

// NewDatabase creates a database seeded with the built-in entries.
func NewDatabase() *Database {
	db := &Database{entries: make(map[string]CVEEntry)}
	for _, e := range builtinEntries() {
		db.entries[strings.ToUpper(e.CVE)] = e
	}
	return db
}

// NewEmptyDatabase creates a database with no entries (useful in tests).
func NewEmptyDatabase() *Database {
	return &Database{entries: make(map[string]CVEEntry)}
}

// GetByCVE returns an entry by CVE ID.
func (db *Database) GetByCVE(cveID string) (CVEEntry, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	e, ok := db.entries[strings.ToUpper(strings.TrimSpace(cveID))]
	return e, ok
}

// All returns every entry, sorted by descending CVSS.
func (db *Database) All() []CVEEntry {
	db.mu.RLock()
	out := make([]CVEEntry, 0, len(db.entries))
	for _, e := range db.entries {
		out = append(out, e)
	}
	db.mu.RUnlock()

	sortEntries(out)
	return out
}

// SearchByVersion returns entries whose affected ranges cover version.
// An imprecise version (""/"3.x") returns nothing rather than everything.
func (db *Database) SearchByVersion(version string) []CVEEntry {
	if !IsVersionComplete(version) {
		return nil
	}

	db.mu.RLock()
	var out []CVEEntry
	for _, e := range db.entries {
		if e.Affects(version) {
			out = append(out, e)
		}
	}
	db.mu.RUnlock()

	sortEntries(out)
	return out
}

// SearchByComponent returns entries that explicitly name the component.
//
// The previous implementation did a substring match against the CVE
// description, so a component named "content" matched every advisory whose
// text happened to contain the word "content". Matching is now restricted to
// the curated AffectedComponents list.
func (db *Database) SearchByComponent(componentName string) []CVEEntry {
	want := normalizeComponent(componentName)
	if want == "" {
		return nil
	}

	db.mu.RLock()
	var out []CVEEntry
	for _, e := range db.entries {
		for _, c := range e.AffectedComponents {
			if normalizeComponent(c) == want {
				out = append(out, e)
				break
			}
		}
	}
	db.mu.RUnlock()

	sortEntries(out)
	return out
}

// GetCriticalVulnerabilities returns entries with CVSS >= 8.0.
func (db *Database) GetCriticalVulnerabilities() []CVEEntry {
	db.mu.RLock()
	var out []CVEEntry
	for _, e := range db.entries {
		if e.CVSS >= 8.0 {
			out = append(out, e)
		}
	}
	db.mu.RUnlock()

	sortEntries(out)
	return out
}

// AddEntry inserts or replaces an entry.
func (db *Database) AddEntry(entry CVEEntry) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.entries[strings.ToUpper(entry.CVE)] = entry
}

// Count returns the number of entries.
func (db *Database) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.entries)
}

// normalizeComponent strips the com_ prefix and lowercases, so "com_Fields",
// "com_fields" and "fields" all compare equal.
func normalizeComponent(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimPrefix(s, "com_")
	return s
}

func sortEntries(in []CVEEntry) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].CVSS != in[j].CVSS {
			return in[i].CVSS > in[j].CVSS
		}
		return in[i].CVE < in[j].CVE
	})
}
