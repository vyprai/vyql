package solvers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
)

// SummaryCache provides thread-safe, content-addressed in-memory caching for
// FunctionSummary records.
type SummaryCache struct {
	mu      sync.RWMutex
	entries map[string]*FunctionSummary
}

// NewSummaryCache creates an empty SummaryCache.
func NewSummaryCache() *SummaryCache {
	return &SummaryCache{
		entries: make(map[string]*FunctionSummary),
	}
}

// SummaryKey computes a cryptographic content-addressed hash key for a function's
// identity and body content.
func SummaryKey(funcID string, bodyContent []byte) string {
	h := sha256.New()
	h.Write([]byte(funcID))
	h.Write([]byte{0})
	h.Write(bodyContent)
	return hex.EncodeToString(h.Sum(nil))
}

// Get retrieves a cached FunctionSummary by key if present.
func (c *SummaryCache) Get(key string) (*FunctionSummary, bool) {
	if c == nil || key == "" {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.entries[key]
	return s, ok
}

// Put stores a FunctionSummary under the given content-addressed key.
func (c *SummaryCache) Put(key string, summary *FunctionSummary) {
	if c == nil || key == "" || summary == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = summary
}

// Serialize serializes a FunctionSummary into JSON bytes.
func (c *SummaryCache) Serialize(s *FunctionSummary) ([]byte, error) {
	return json.Marshal(s)
}

// Deserialize parses a FunctionSummary from JSON bytes.
func (c *SummaryCache) Deserialize(data []byte) (*FunctionSummary, error) {
	var s FunctionSummary
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
