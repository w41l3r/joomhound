package cve

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBuiltinEntriesAreWellFormed guards the data-quality regression: the
// previous dataset contained CVEs belonging to Linux, Drupal, WordPress and
// ImageMagick, entries with invented CVSS scores, and one nonexistent CVE ID.
func TestBuiltinEntriesAreWellFormed(t *testing.T) {
	entries := builtinEntries()
	if len(entries) == 0 {
		t.Fatal("no builtin entries")
	}

	seen := make(map[string]bool)
	for _, e := range entries {
		if !strings.HasPrefix(e.CVE, "CVE-") {
			t.Errorf("%s: malformed CVE ID", e.CVE)
		}
		if seen[e.CVE] {
			t.Errorf("%s: duplicate entry", e.CVE)
		}
		seen[e.CVE] = true

		if e.CVSS <= 0 || e.CVSS > 10 {
			t.Errorf("%s: CVSS %v out of range", e.CVE, e.CVSS)
		}
		if e.Title == "" || e.Description == "" {
			t.Errorf("%s: missing title or description", e.CVE)
		}
		// Every entry must have at least one bounded range, otherwise it
		// would be reported against every target version.
		if len(e.Ranges) == 0 {
			t.Errorf("%s: no affected version ranges", e.CVE)
		}
		for _, r := range e.Ranges {
			if r.Introduced == "" && r.Fixed == "" && r.LastAffected == "" && r.Constraint == "" {
				t.Errorf("%s: unbounded version range", e.CVE)
			}
		}
		// References must exist: the scanner used to index References[0]
		// unconditionally, panicking on an entry without any.
		if len(e.References) == 0 {
			t.Errorf("%s: no references", e.CVE)
		}
	}
}

// TestPrimaryReferenceNoPanic covers the index-out-of-range crash.
func TestPrimaryReferenceNoPanic(t *testing.T) {
	e := CVEEntry{CVE: "CVE-0000-0000"}
	if got := e.PrimaryReference(); got != "" {
		t.Fatalf("PrimaryReference() = %q, want empty string", got)
	}
}

func TestSearchByVersion(t *testing.T) {
	db := NewDatabase()

	// Joomla 3.7.0 is the only version affected by CVE-2017-8917.
	got := db.SearchByVersion("3.7.0")
	found := false
	for _, e := range got {
		if e.CVE == "CVE-2017-8917" {
			found = true
		}
	}
	if !found {
		t.Error("CVE-2017-8917 should match version 3.7.0")
	}

	// 3.7.1 is patched.
	for _, e := range db.SearchByVersion("3.7.1") {
		if e.CVE == "CVE-2017-8917" {
			t.Error("CVE-2017-8917 must not match the patched 3.7.1")
		}
	}
}

// TestSearchByVersionRejectsImpreciseVersion is the regression for treating
// "3.x" as 0.0.0 and therefore matching everything.
func TestSearchByVersionRejectsImpreciseVersion(t *testing.T) {
	db := NewDatabase()

	for _, v := range []string{"3.x", "", "unknown"} {
		if got := db.SearchByVersion(v); len(got) != 0 {
			t.Errorf("SearchByVersion(%q) returned %d entries, want 0", v, len(got))
		}
	}
}

// TestSearchByComponentIsPrecise guards against the old substring match
// against the description, which made a component named "content" match every
// advisory whose text contained that word.
func TestSearchByComponentIsPrecise(t *testing.T) {
	db := NewDatabase()

	got := db.SearchByComponent("com_fields")
	if len(got) == 0 {
		t.Fatal("com_fields should match CVE-2017-8917")
	}
	for _, e := range got {
		if e.CVE != "CVE-2017-8917" {
			t.Errorf("unexpected match for com_fields: %s", e.CVE)
		}
	}

	// A prefix-less name must resolve the same way.
	if len(db.SearchByComponent("fields")) != len(got) {
		t.Error("component matching should normalize the com_ prefix")
	}

	// A component nothing references must return nothing.
	if got := db.SearchByComponent("com_totally_made_up"); len(got) != 0 {
		t.Errorf("unknown component returned %d entries, want 0", len(got))
	}
}

func TestDatabaseConcurrentAccess(t *testing.T) {
	db := NewDatabase()
	done := make(chan struct{})

	// Run with -race to prove the mutex is doing its job.
	go func() {
		for i := 0; i < 100; i++ {
			db.AddEntry(CVEEntry{CVE: "CVE-9999-0001", CVSS: 1})
		}
		close(done)
	}()
	for i := 0; i < 100; i++ {
		_ = db.SearchByVersion("3.9.4")
		_ = db.Count()
	}
	<-done
}

func TestDiskCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()

	cache, err := NewDiskCache(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}

	advs := []Advisory{{ID: "CVE-2017-8917", CVSS: 9.8, Title: "SQLi"}}
	if err := cache.Put("joomla|3.7.0|", advs); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, ok := cache.Get("joomla|3.7.0|")
	if !ok {
		t.Fatal("Get returned a miss for a freshly written entry")
	}
	if len(got) != 1 || got[0].ID != "CVE-2017-8917" {
		t.Fatalf("Get returned %+v", got)
	}

	if _, ok := cache.Get("joomla|4.0.0|"); ok {
		t.Error("Get returned a hit for a key that was never written")
	}
}

func TestDiskCacheExpires(t *testing.T) {
	dir := t.TempDir()

	cache, err := NewDiskCache(dir, time.Nanosecond)
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}
	if err := cache.Put("k", []Advisory{{ID: "CVE-1"}}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	time.Sleep(2 * time.Millisecond)

	if _, ok := cache.Get("k"); ok {
		t.Error("expired entry should be a miss")
	}
}

func TestDiskCacheIgnoresCorruptEntry(t *testing.T) {
	dir := t.TempDir()

	cache, err := NewDiskCache(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewDiskCache: %v", err)
	}
	if err := cache.Put("k", []Advisory{{ID: "CVE-1"}}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Corrupt every file on disk and drop the in-memory layer.
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, f := range files {
		if err := os.WriteFile(f, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cache.mem = nil
	cache.mem = map[string]cacheEnvelope{}

	if _, ok := cache.Get("k"); ok {
		t.Error("corrupt entry should be treated as a miss, not returned")
	}
}

func TestOfflineFetcherFetch(t *testing.T) {
	f := NewOfflineFetcher(nil)

	advs, err := f.Fetch(context.Background(), Query{Product: "joomla", Version: "3.7.0"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(advs) == 0 {
		t.Fatal("expected at least one advisory for 3.7.0")
	}
	for _, a := range advs {
		if a.Source != "offline" {
			t.Errorf("Source = %q, want offline", a.Source)
		}
	}
}
