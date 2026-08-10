// Package parsecache is a content-addressed, BadgerDB-backed cache of per-file NIR parse
// results. Tree-sitter parsing dominates scan time on large repos; a re-scan of an unchanged
// checkout can skip it entirely when a caller explicitly provides a cache.
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

	"github.com/vyprai/vyql/internal/extract/nir"
)

// Cache is a Badger-backed parse-result cache. A nil *Cache is a valid no-op (all methods
// are safe), so callers can treat "caching disabled" uniformly.
type Cache struct {
	db   *badger.DB
	salt []byte
}

var shared struct {
	mu sync.RWMutex
	c  *Cache
}

// options sizes badger for a CLI cache, not a server. Badger's defaults hold a
// 64MiB memtable arena — eagerly allocated the moment the DB opens, on every
// scan — with up to five more queued behind it, plus a 256MiB block cache of
// decompressed copies. This cache's workload is point reads that are each hit
// at most once per scan, and its keys are content-addressed, so conflict
// detection tracks writes that cannot conflict.
func options(dir string) badger.Options {
	return badger.DefaultOptions(dir).
		WithLogger(nil).
		WithMemTableSize(16 << 20).
		WithNumMemtables(2).
		WithBlockCacheSize(64 << 20).
		WithDetectConflicts(false)
}

// Open creates a Badger-backed cache in dir. CLI callers should prefer explicit command
// flags over environment-variable configuration.
func Open(dir string) (*Cache, error) {
	db, err := badger.Open(options(dir))
	if err != nil {
		return nil, err
	}
	return &Cache{db: db, salt: execSalt()}, nil
}

// Shared returns the process-wide cache. Command owners wire this explicitly so
// library/test callers do not pick up ambient filesystem state.
func Shared() *Cache {
	shared.mu.RLock()
	defer shared.mu.RUnlock()
	return shared.c
}

// SetShared installs the process-wide cache and returns a restore function.
func SetShared(c *Cache) func() {
	shared.mu.Lock()
	prev := shared.c
	shared.c = c
	shared.mu.Unlock()
	return func() {
		shared.mu.Lock()
		shared.c = prev
		shared.mu.Unlock()
	}
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

// statKey keys a file by identity-WITHOUT-content: salt ∥ root ∥ abs ∥ size ∥ mtime. It maps
// to the file's content key, so an unchanged file (same size+mtime) resolves to its parsed
// module without being read or hashed — the dominant cost on a warm re-scan of a large tree.
// The salt folds in the binary identity, so a rebuilt scanner invalidates stat entries too.
func (c *Cache) statKey(root, abs string, size, mtimeNs int64) string {
	h := sha256.New()
	h.Write(c.salt)
	h.Write([]byte("stat\x00"))
	h.Write([]byte(root))
	h.Write([]byte{0})
	h.Write([]byte(abs))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(size, 10)))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(mtimeNs, 10)))
	return hex.EncodeToString(h.Sum(nil))
}

// statHeader is the stat entry value: enough to build a STUB module (the lowerer's identity
// fields) without decoding the body, plus the content key to fetch the full NIR on demand.
type statHeader struct {
	ContentKey string
	Key        string
	File       string
	Hash       string
}

func encodeHeader(h statHeader) []byte {
	var buf bytes.Buffer
	_ = gob.NewEncoder(&buf).Encode(h)
	return buf.Bytes()
}

func decodeHeader(raw []byte) (statHeader, bool) {
	var h statHeader
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&h); err != nil {
		return statHeader{}, false
	}
	return h, true
}

// PrefetchStubs resolves, for each unchanged file (same size+mtime), a STUB module — its Key,
// File, Hash, and CacheKey (the content key) WITHOUT reading or decoding the file's NIR. The
// lowerer decodes the full body on demand only if it actually needs it (a signature change
// elsewhere invalidating the cached body sub-graph). One batched read transaction. Files that
// changed or were never cached are absent. Like most build caches this trusts size+mtime; a
// content change preserving both (rare; editors bump mtime) is missed — `vyql cache clear`
// forces a rebuild.
func (c *Cache) PrefetchStubs(root string, files []string) map[string]nir.Module {
	if c == nil || len(files) == 0 {
		return nil
	}
	statKeys := make([]string, 0, len(files))
	statKeyFile := make(map[string]string, len(files))
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			continue
		}
		sk := c.statKey(root, f, fi.Size(), fi.ModTime().UnixNano())
		statKeys = append(statKeys, sk)
		statKeyFile[sk] = f
	}
	headers := c.GetManyRaw(statKeys)
	out := make(map[string]nir.Module, len(headers))
	for sk, raw := range headers {
		if h, ok := decodeHeader(raw); ok {
			out[statKeyFile[sk]] = nir.Module{Key: h.Key, File: h.File, Hash: h.Hash, CacheKey: h.ContentKey}
		}
	}
	return out
}

// AuxStatKeys returns, for each stattable file, a stat-derived cache key in namespace ns. It
// lets an auxiliary per-file analysis whose result depends only on file content (e.g. secret
// scanning) reuse the stat fast-path: an unchanged file's cached result is replayed instead of
// re-reading the file. Combine with GetManyRaw/PutManyRaw for batched I/O. Returns nil if
// caching is off.
func (c *Cache) AuxStatKeys(root string, files []string, ns string) map[string]string {
	if c == nil {
		return nil
	}
	out := make(map[string]string, len(files))
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			continue
		}
		out[f] = "aux\x00" + ns + "\x00" + c.statKey(root, f, fi.Size(), fi.ModTime().UnixNano())
	}
	return out
}

// PutStat records the stat→header mapping after a (re)parse so the next scan can build a stub
// without reading the file. Called whenever a content key is known valid for the file's current
// stat (fresh parse, or a content hit where only the mtime moved).
func (c *Cache) PutStat(root, abs, contentKey string, m nir.Module) {
	if c == nil || contentKey == "" {
		return
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return
	}
	c.PutRaw(c.statKey(root, abs, fi.Size(), fi.ModTime().UnixNano()),
		encodeHeader(statHeader{ContentKey: contentKey, Key: m.Key, File: m.File, Hash: m.Hash}))
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

// GetManyRaw reads many keys in a SINGLE read transaction and returns the present ones. The
// per-module binding-label cache looks up thousands of keys per scan; one transaction instead
// of one-per-key turns an I/O-bound loop (the dominant cost of a large incremental scan) into a
// single pass. Missing keys are simply absent from the result.
func (c *Cache) GetManyRaw(keys []string) map[string][]byte {
	if c == nil || len(keys) == 0 {
		return nil
	}
	out := make(map[string][]byte, len(keys))
	_ = c.db.View(func(txn *badger.Txn) error {
		for _, k := range keys {
			item, err := txn.Get([]byte(k))
			if err != nil {
				continue
			}
			if v, err := item.ValueCopy(nil); err == nil {
				out[k] = v
			}
		}
		return nil
	})
	return out
}

// PutManyRaw writes many key/value pairs, batching into as few transactions as Badger's size
// limits allow. Used for the cold-scan path where every module's labels are stored at once.
func (c *Cache) PutManyRaw(kv map[string][]byte) {
	if c == nil || len(kv) == 0 {
		return
	}
	wb := c.db.NewWriteBatch()
	defer wb.Cancel()
	for k, v := range kv {
		if err := wb.Set([]byte(k), v); err != nil {
			return
		}
	}
	_ = wb.Flush()
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
