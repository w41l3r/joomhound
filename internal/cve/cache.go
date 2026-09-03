package cve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultCacheTTL is how long an online CVE lookup stays fresh. CVE data
// changes slowly; a day avoids hammering NVD across repeated scans.
const DefaultCacheTTL = 24 * time.Hour

// cacheEnvelope is the on-disk format.
type cacheEnvelope struct {
	Key        string     `json:"key"`
	StoredAt   time.Time  `json:"stored_at"`
	TTLSeconds int64      `json:"ttl_seconds"`
	Advisories []Advisory `json:"advisories"`
}

// DiskCache is a TTL'd JSON cache for CVE lookups, backed by one file per
// query key. It is safe for concurrent use and never returns an error from
// Get: a corrupt or unreadable entry is simply a miss.
type DiskCache struct {
	dir string
	ttl time.Duration

	mu  sync.RWMutex
	mem map[string]cacheEnvelope // in-process layer, avoids re-reading files
}

// NewDiskCache creates a cache rooted at dir. An empty dir resolves to
// $HOME/.joomhound/cache/cve (falling back to the OS temp dir).
func NewDiskCache(dir string, ttl time.Duration) (*DiskCache, error) {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			dir = filepath.Join(os.TempDir(), "joomhound", "cve")
		} else {
			dir = filepath.Join(home, ".joomhound", "cache", "cve")
		}
	}
	// 0700: cached advisory data is harmless, but the cache directory sits in
	// the operator's home and should not be world-writable.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating CVE cache dir %s: %w", dir, err)
	}
	return &DiskCache{
		dir: dir,
		ttl: ttl,
		mem: make(map[string]cacheEnvelope),
	}, nil
}

// Dir returns the cache directory.
func (c *DiskCache) Dir() string { return c.dir }

func (c *DiskCache) path(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:])+".json")
}

// Get returns cached advisories when a fresh entry exists.
func (c *DiskCache) Get(key string) ([]Advisory, bool) {
	c.mu.RLock()
	env, ok := c.mem[key]
	c.mu.RUnlock()
	if ok {
		if c.fresh(env) {
			return env.Advisories, true
		}
		return nil, false
	}

	data, err := os.ReadFile(c.path(key))
	if err != nil {
		return nil, false
	}

	if err := json.Unmarshal(data, &env); err != nil {
		// Corrupt entry: drop it so the next run rewrites it cleanly.
		_ = os.Remove(c.path(key))
		return nil, false
	}
	if !c.fresh(env) {
		return nil, false
	}

	c.mu.Lock()
	c.mem[key] = env
	c.mu.Unlock()

	return env.Advisories, true
}

func (c *DiskCache) fresh(env cacheEnvelope) bool {
	ttl := time.Duration(env.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = c.ttl
	}
	return time.Since(env.StoredAt) < ttl
}

// Put stores advisories under key. The write is atomic (temp file + rename)
// so a killed scan cannot leave a half-written cache entry behind.
func (c *DiskCache) Put(key string, advisories []Advisory) error {
	env := cacheEnvelope{
		Key:        key,
		StoredAt:   time.Now(),
		TTLSeconds: int64(c.ttl / time.Second),
		Advisories: advisories,
	}

	c.mu.Lock()
	c.mem[key] = env
	c.mu.Unlock()

	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding cache entry: %w", err)
	}

	final := c.path(key)
	tmp, err := os.CreateTemp(c.dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp cache file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("writing cache entry: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("closing cache entry: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("chmod cache entry: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("committing cache entry: %w", err)
	}

	return nil
}

// Purge deletes every cache entry.
func (c *DiskCache) Purge() error {
	c.mu.Lock()
	c.mem = make(map[string]cacheEnvelope)
	c.mu.Unlock()

	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		_ = os.Remove(filepath.Join(c.dir, e.Name()))
	}
	return nil
}

// MemoryCache is an in-process Cache, useful in tests and for one-shot runs
// where touching the filesystem is undesirable.
type MemoryCache struct {
	mu  sync.RWMutex
	ttl time.Duration
	m   map[string]cacheEnvelope
}

// NewMemoryCache creates an in-memory cache.
func NewMemoryCache(ttl time.Duration) *MemoryCache {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &MemoryCache{ttl: ttl, m: make(map[string]cacheEnvelope)}
}

// Get implements Cache.
func (c *MemoryCache) Get(key string) ([]Advisory, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	env, ok := c.m[key]
	if !ok || time.Since(env.StoredAt) >= c.ttl {
		return nil, false
	}
	return env.Advisories, true
}

// Put implements Cache.
func (c *MemoryCache) Put(key string, advisories []Advisory) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = cacheEnvelope{Key: key, StoredAt: time.Now(), Advisories: advisories}
	return nil
}
