package solvers

import (
	"testing"
)

func TestSummaryCachePutGet(t *testing.T) {
	cache := NewSummaryCache()
	key := SummaryKey("pkg.handler", []byte("def handler(x): return x"))

	summary := NewFunctionSummary("pkg.handler")
	summary.ParamToReturn[0] = true

	cache.Put(key, summary)

	got, ok := cache.Get(key)
	if !ok {
		t.Fatal("expected summary cache hit")
	}
	if !got.ParamToReturn[0] {
		t.Errorf("expected ParamToReturn[0]=true from cache")
	}

	// Non-existent key must return false
	_, ok = cache.Get("nonexistent_key")
	if ok {
		t.Errorf("expected cache miss for non-existent key")
	}
}

func TestSummaryCacheSerializationRoundTrip(t *testing.T) {
	cache := NewSummaryCache()
	summary := NewFunctionSummary("service.query")
	summary.ParamToReturn[1] = true
	summary.KilledThreats[0] = map[string]bool{"core.SqlParameterization": true}

	bytes, err := cache.Serialize(summary)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	deserialized, err := cache.Deserialize(bytes)
	if err != nil {
		t.Fatalf("Deserialize failed: %v", err)
	}

	if deserialized.FuncID != "service.query" {
		t.Errorf("expected funcID 'service.query', got %q", deserialized.FuncID)
	}
	if !deserialized.ParamToReturn[1] {
		t.Errorf("expected ParamToReturn[1]=true")
	}
	if !deserialized.KilledThreats[0]["core.SqlParameterization"] {
		t.Errorf("expected killed threat 'core.SqlParameterization'")
	}
}

func BenchmarkSummaryCacheGet(b *testing.B) {
	cache := NewSummaryCache()
	key := SummaryKey("bench.fn", []byte("function bench() {}"))
	summary := NewFunctionSummary("bench.fn")
	summary.ParamToReturn[0] = true
	cache.Put(key, summary)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.Get(key)
	}
}
