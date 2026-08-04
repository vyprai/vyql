# ADR 0001 — USG Storage Engine

Status: **Accepted, at-rest engine SUPERSEDED by [ADR 0002](0002-go-badgerdb.md)**
— the hybrid, partition-scoped *architecture* and benchmark methodology below
stand; the at-rest engine candidate changes from SQLite-class columnar to
**BadgerDB**, and the implementation language is **Go** (ADR 0002).
Original status: Accepted (Phase 0 exit-gate decision; docs/04 AC3)
Date: 2026-06 (relative; see git history)
Supersedes the open question in [docs/04](../04-universal-security-graph.md)
§"Open questions / Storage engine".

## Context

docs/04 left the USG storage engine as an open question between a property-
graph DB and a hybrid (relational/columnar facts + Datalog evaluation + solver
indexes), leaning hybrid. Phase 0 requires the decision recorded **with
benchmark evidence** against the scale model (50M code nodes / 200M edges
dominant volume).

## Benchmark

Harness: a synthetic graph generator plus per-store drivers, validated for
result-equivalence across candidates. Code-heavy synthetic
graphs; two candidates exercising the hottest engine/solver operations —
concept-label lookup (rule/adapter binding), edge traversal (solvers), and
6-hop BFS (reach/taint shape).

| store | nodes | build | concept×2000 | edges×2000 | bfs×100 | size |
|---|---|---|---|---|---|---|
| in-memory (dict adj + concept index) | 100k | 115ms | 2ms | 1ms | 108ms | 17.7MB |
| sqlite (relational + indexes) | 100k | 394ms | 189ms | 9ms | 507ms | 21.3MB |
| in-memory | 250k | 358ms | 4ms | 3ms | 178ms | 40.5MB |
| sqlite | 250k | 1019ms | 468ms | 10ms | 576ms | 55.8MB |

**Reading the numbers.** In-memory is **30–100× faster** on the hot paths
(concept lookup, BFS) and uses ~70–75% of SQLite's footprint. SQLite's indexed
single-edge lookup is competitive (~10ms/2000), but per-query overhead makes it
**too slow for the tight, repeated lookups inside solver fixpoints** (BFS 507ms
vs 108ms). Extrapolating linearly: the in-memory store holds ~17.7MB/100k nodes
→ ~9GB for the 50M-node scale model — **feasible per partition (repo/account),
not for an entire org at once**; SQLite persists and scales past RAM but cannot
serve the hot path at the needed latency.

## Decision

**Hybrid, partition-scoped:**

1. **Materialized Class A facts** (nodes/edges/labels/provenance) live in a
   **persisted relational/columnar fact store** (SQLite-class in the prototype;
   a real columnar engine — e.g. DuckDB/Parquet-class — in production). This is
   the source of truth, scales past RAM, and is queried in bulk by scope.
2. **Evaluation runs over in-memory working sets**: the engine loads the
   relevant **partition** (repo / cloud account) into the in-memory adjacency +
   concept-index representation (the prototype's `Graph`) plus
   **solver-specific indexes** for hot paths. Most rule evaluation is
   partition-local (docs/04 §scale), so the active working set fits in RAM.
3. **Class B virtual relations** (taint/reach/assume) are never stored —
   computed by solvers over the working set, cached with dependency
   fingerprints (docs/04, and the shared solver contract).
4. **Cross-partition** traversal (attack paths) happens only through the few
   declared cross-domain edges, fetched on demand from the fact store.

This matches docs/04's lean and the benchmark: in-memory is the correct
**hot-path** representation; a persisted columnar store is the correct
**at-rest / scale** representation; the partition boundary makes both true at
once.

## Consequences

- The prototype's in-memory `Graph` is the **working-set representation**, not
  the storage layer — it is validated for the hot path; production adds the
  columnar fact store + partition loader beneath it.
- Need a **partition loader** (scope → working set) and **eviction** policy
  (Phase 1/2 task — feeds docs/04 §incremental updates).
- Solver caches key on subgraph dependency fingerprints so a delta invalidates
  only affected working-set results (already in the solver contract).
- **Re-benchmark at the full scale model** with the production columnar engine
  before GA; the prototype benchmark establishes the *trend and architecture*,
  not the absolute production numbers (recorded honestly as an extrapolation).

## Alternatives rejected

- **Pure property-graph DB** (Neo4j-class): general traversal is convenient but
  the hot-path latency and operational weight don't beat partition-scoped
  in-memory + a columnar fact store for our specific workload (bounded,
  concept-bound solver queries, not ad-hoc deep traversal).
- **Pure in-memory**: cannot hold a full org; no persistence/incrementality.
- **Pure SQLite/columnar with no working set**: hot-path latency unacceptable
  for solver fixpoints (BFS 5× slower).
