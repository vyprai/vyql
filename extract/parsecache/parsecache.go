// Package parsecache is a content-addressed, BadgerDB-backed cache of per-file NIR parse
// results. Tree-sitter parsing dominates scan time on large repos; a re-scan of an unchanged
// checkout (the CI / iterative-dev case) can skip it entirely. The cache is OPT-IN via the
// $VYQL_CACHE environment variable (a directory) — like a build cache — so a normal one-shot
// scan writes nothing to disk.
//
// Keys are sha256(salt ∥ langTag ∥ root ∥ abs ∥ content): the salt is derived from the running
// executable (so any rebuild — i.e. any frontend change — auto-invalidates the whole cache),
// and root+abs+content make a hit guarantee an identical parse result, including the module's
// path-derived Key/File fields. Values are gob-encoded nir.Modules. Built on the same Badger
// engine the graph store uses (ADR 0002).
package parsecache

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"os"
	"strconv"
	"sync"

	badger "github.com/dgraph-io/badger/v4"

	"github.com/vyprai/vyql/extract/nir"
)

// Cache is a Badger-backed parse-result cache. A nil *Cache is a valid no-op (all methods
// are safe), so callers can treat "caching disabled" uniformly.
type Cache struct {
	db   *badger.DB
	salt []byte
}

var (
	shared   *Cache
	openOnce sync.Once
)

// Shared returns the process-wide cache opened from $VYQL_CACHE, or nil if the variable is
// unset or the database cannot be opened (caching is best-effort and never fatal). Opened
// once; Badger holds a directory lock, so a single instance is shared across frontends.
func Shared() *Cache {
	openOnce.Do(func() {
		dir := os.Getenv("VYQL_CACHE")
		if dir == "" {
			return
		}
		opts := badger.DefaultOptions(dir).WithLogger(nil)
		db, err := badger.Open(opts)
		if err != nil {
			return // another process holds the lock, or the path is bad — silently disable
		}
		shared = &Cache{db: db, salt: execSalt()}
	})
	return shared
}

// execSalt derives a cache-busting salt from the running binary (path + size + mtime), so a
// rebuilt scanner — any change to a frontend or to NIR — never reads stale parse results.
func execSalt() []byte {
	exe, err := os.Executable()
	if err != nil {
		return []byte("novsalt")
	}
	h := sha256.New()
	h.Write([]byte(exe))
	if fi, err := os.Stat(exe); err == nil {
		h.Write([]byte(strconv.FormatInt(fi.Size(), 10)))
		h.Write([]byte(strconv.FormatInt(fi.ModTime().UnixNano(), 10)))
	}
	return h.Sum(nil)
}

// Key derives the cache key for a file's parse result. The absolute path selects the
// extractor (ext→language), and root+abs reproduce the module's path-derived Key/File, so a
// hit on (root, abs, content) yields an identical module; content makes edits miss.
func (c *Cache) Key(root, abs string, content []byte) string {
	if c == nil {
		return ""
	}
	h := sha256.New()
	h.Write(c.salt)
	h.Write([]byte(root))
	h.Write([]byte{0})
	h.Write([]byte(abs))
	h.Write([]byte{0})
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// Get returns the cached module for key, if present and decodable.
func (c *Cache) Get(key string) (nir.Module, bool) {
	if c == nil {
		return nir.Module{}, false
	}
	var raw []byte
	err := c.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		raw, err = item.ValueCopy(nil)
		return err
	})
	if err != nil {
		return nir.Module{}, false
	}
	var m nir.Module
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&m); err != nil {
		return nir.Module{}, false
	}
	return m, true
}

// Put stores a module's parse result under key (best-effort; errors are ignored).
func (c *Cache) Put(key string, m nir.Module) {
	if c == nil {
		return
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(m); err != nil {
		return
	}
	val := buf.Bytes()
	_ = c.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), val)
	})
}

// Salt returns the executable-derived cache-busting salt (nil if disabled). Callers building
// higher-level keys (e.g. a whole-scan result key) fold it in so a rebuilt binary invalidates.
func (c *Cache) Salt() []byte {
	if c == nil {
		return nil
	}
	return c.salt
}

// GetRaw returns the raw bytes stored under key. For caches above the per-file layer
// (e.g. a whole-scan result) the caller owns the encoding.
func (c *Cache) GetRaw(key string) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	var raw []byte
	err := c.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		raw, err = item.ValueCopy(nil)
		return err
	})
	if err != nil {
		return nil, false
	}
	return raw, true
}

// PutRaw stores raw bytes under key (best-effort).
func (c *Cache) PutRaw(key string, val []byte) {
	if c == nil {
		return
	}
	_ = c.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), val)
	})
}

// Clear empties the cache (drops all keys) while keeping the database open. Safe on nil.
func (c *Cache) Clear() error {
	if c == nil {
		return nil
	}
	return c.db.DropAll()
}

// Close flushes and closes the cache. Safe on nil.
func (c *Cache) Close() error {
	if c == nil {
		return nil
	}
	return c.db.Close()
}
