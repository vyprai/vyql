# ADR 0002 — Implementation Language (Go) + Storage Engine (BadgerDB)

Status: **Accepted** (user direction). **Supersedes the storage-backend choice
in [ADR 0001](0001-storage-engine.md)** (the hybrid *architecture* from 0001
stands; the at-rest engine changes from SQLite-class columnar to BadgerDB).
Date: 2026-06 (relative; see git history).

## Context

Direction from the product owner: **the final product is implemented in Go**,
and **the graph database is BadgerDB**. The Python `poc/` (133 tests across 23
cases) has validated the VyQL semantics end-to-end; it now serves as the
**reference oracle / executable spec** for the Go port, not as the shipping
artifact.

## Decision

1. **Implementation language: Go** (1.26). The production engine, USG, solvers,
   frontends, adapters, and CLI are built in `go/` (module
   `github.com/vyprai/vyql`).
2. **Persistent fact store: BadgerDB** (embedded, pure-Go LSM key-value store).
   The graph is modeled as prefix-scannable KV (`go/usg/badger.go`):
   - `n\0<id>` → Node
   - `eo\0<src>\0<seq>` / `ei\0<dst>\0<seq>` → Edge (out/in adjacency)
   - `lc\0<concept>\0<nodeID>` → Label (concept index)
   - `ln\0<nodeID>\0<concept>` → Label (node's labels)

   Ordered keys make concept lookups and edge traversal **ordered prefix
   scans**; the 0x00 separator never appears in textual ids.
3. **The hybrid from ADR 0001 stands.** BadgerDB is the at-rest, scale,
   partition-scoped fact store; an **in-memory working set** (`go/usg/inmem.go`,
   `InMemStore`) serves the hot evaluation path. Both implement the same `Store`
   interface and are verified to return **identical results**
   (`go/usg/usg_test.go` `TestStoreEquivalence`) — so the engine is
   storage-agnostic and the partition loader can choose the backend per use.
4. **Python `poc/` is the reference oracle.** Go behavior is ported against it;
   the Python cases (`poc/cases/case_*`) are mirrored as Go tests so the Go
   build is checked against the validated spec.

## Why BadgerDB

- **Pure Go, embedded** — no CGO, no external database process; ships as a
  single binary. Operationally simple for the CI/CLI deployment shapes
  (docs/03).
- **LSM-tree** — write-optimized, which suits ingestion-heavy extraction (a repo
  scan writes millions of nodes/edges).
- **Ordered keys + prefix iteration** — gives us concept and adjacency indexes
  for free, exactly the hot-path operations the storage benchmark measured.
- **Proven for graphs** — it is the storage layer under Dgraph (a distributed
  graph database), so the graph workload is well-trodden.
- **In-memory mode** (`WithInMemory(true)`) — used for tests and ephemeral CI
  scans where persistence isn't needed.

## Consequences

- **Port plan.** The engine, solvers (taint/reach/assume), frontends
  (tree-sitter has Go bindings; acorn/Ripper can stay as shell-outs initially or
  become Go-native), adapters, and rule compiler are ported to Go incrementally,
  each checked against the Python oracle's tests.
- **Re-benchmark.** The storage benchmark (ADR 0001 / `poc/bench/`) is re-run in
  Go against BadgerDB before GA; the prototype numbers established the
  *architecture*, not Badger's absolute figures.
- **Edge-sequence persistence.** The Badger store's edge `seq` counter is
  per-process; persisting/recovering it across reopen (max-seq scan or a stored
  counter) is a follow-on (tracked in PROGRESS.md).
- **Schema-evolution & GC.** BadgerDB value-log GC and versioned-key handling
  are operational tasks for the persistent deployment (Phase 1+).

## Status of ADR 0001

The **hybrid, partition-scoped architecture** in ADR 0001 remains accepted. Only
its *at-rest engine candidate* (SQLite-class columnar) is superseded here by
BadgerDB. The benchmark methodology and the in-memory-working-set rationale carry
over unchanged.
