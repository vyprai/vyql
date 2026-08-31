## What changed, and why

## What you measured

Detection changes move benchmark numbers. If you touched bindings, rules or the
engine, give before/after on at least one suite:

```
BenchmarkJava    before: +X.XX   after: +X.XX
BenchmarkPython  before: +X.XX   after: +X.XX
```

Recall and precision separately, if the change trades between them.

## Checklist

- [ ] `make ci` passes locally
- [ ] `go test -count=1` — never a bare `go test` (the cache does not track `.vyql` data)
- [ ] Protected benchmarks did not regress
