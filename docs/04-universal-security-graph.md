# 04 — Universal Security Graph (USG)

Status: `DRAFT` — schema core stable; scale and incrementality sections have
open questions listed at the end. The `code.*` node/edge schema and the
materialized-facts-vs-virtual-relations split were validated by real AST
extractors (Python, JavaScript, Ruby) that parse actual repositories into this
schema and feed the engine unchanged. Interprocedural `CALLS`/dataflow edges are
built with import + type resolution, not bare names — see
[10](10-domain-sast.md) §"Call resolution" (`../poc/extract/`, `poc/FINDINGS.md`
§§"Real-repo extraction" / "Call resolution").

## Principles

1. **Everything observable becomes nodes and edges; everything *derived*
   stays virtual.** Inventory facts (a bucket exists, a function calls
   another, a role has a policy) are materialized. Analysis results
   (taint flows, privilege closure, internet reachability) are virtual
   relations computed by solvers and cached with invalidation metadata.
2. **Every node and edge carries provenance.** Which extractor, which
   adapter, which source artifact, when, and at what confidence. No anonymous
   facts: a graph used for security decisions must be auditable.
3. **Namespaced schema.** Node and edge types live in domain namespaces
   (`code.*`, `cloud.*`, `identity.*`, `sbom.*`, `runtime.*`, `business.*`)
   with a small shared core. Cross-domain edges are explicit and few.

## Node schema

Common envelope on every node:

```
id          stable content-derived id (see "Identity" below)
type        namespaced type, e.g. cloud.Bucket
labels      concept annotations attached by adapters, e.g. [PUBLIC_STORAGE]
props       typed properties per node type
provenance  { extractor, adapter?, source_ref, observed_at, confidence }
scope       tenant / account / repo / cluster partition key
```

### Core node types by namespace

**code.** `File`, `Module`, `Package`, `Class`, `Function`, `Method`,
`Parameter`, `Variable`, `CallSite`, `Literal`, `Route` (HTTP endpoint),
`ConfigKey`.

**cloud.** `Account`, `Project`, `Subscription`, `Region`, `Network`,
`Subnet`, `SecurityGroup`, `LoadBalancer`, `Gateway`, `VM`, `Container`,
`ServerlessFunction`, `Bucket`, `Database`, `Queue`, `Secret`, `KMSKey`,
`DNSRecord`.

**identity.** `User`, `Group`, `Role`, `ServiceAccount`, `Policy`,
`PolicyStatement`, `Permission`, `Session`, `Federation`, `TrustRelation`.

**sbom.** `Repository`, `Dependency`, `Package`, `PackageVersion`,
`ContainerImage`, `Layer`, `Artifact`, `License`, `Advisory` (CVE/GHSA),
`Maintainer`.

**runtime.** `Process`, `Connection`, `Request`, `Session`, `EventWindow`
(aggregated; raw events are not graph nodes — see
[11](11-domain-supply-chain-runtime.md)).

**business.** `Actor`, `Action`, `Resource`, `Workflow`, `State`,
`Transition`, `Approval`, `Constraint`. (Research track,
[12](12-domain-business-logic.md).)

**threat.** `ThreatActor`, `Campaign`, `TTP` (ATT&CK technique ref),
`Indicator` — projected from STIX.

### Concept labels

Adapters attach **concept labels** to nodes (and in some cases edges). Labels
are the bridge between the graph and the ontology: a `cloud.Bucket` node with
label `PUBLIC_STORAGE` is what `from PUBLIC_STORAGE` binds to. Labels carry
the provenance of the adapter that applied them, so a finding can show *why*
the engine believed a node was public.

## Edge schema

Edges share the envelope (id, type, props, provenance, scope). Edge types are
split into three classes — this classification is load-bearing:

### Class A — Materialized structural edges (facts)

| Edge | Domain | Meaning |
|---|---|---|
| `CONTAINS`, `IMPORTS`, `DECLARES` | code | structure |
| `CALLS` | code | call graph (with `resolution: static\|heuristic\|dynamic`) |
| `DEPENDS_ON` | sbom | dependency (with version constraint, direct/transitive) |
| `IN_NETWORK`, `MEMBER_OF`, `ATTACHED_TO` | cloud/identity | containment/attachment |
| `HAS_POLICY`, `GRANTS`, `TRUSTS` | identity | policy facts |
| `EXPOSES` | cloud | listener/port exposure facts |
| `OWNS`, `APPROVES`, `VALIDATES` | business | declared business facts |
| `OBSERVED` family: `SPAWNED`, `CONNECTED_TO`, `SERVED` | runtime | telemetry-derived facts |

### Class B — Virtual relations (computed by solvers, never stored as truth)

| Relation | Solver | Notes |
|---|---|---|
| `TAINTS(a, b, kind)` | taint (IFDS-style) | witness = dataflow path |
| `FLOWS_TO(a, b)` | dataflow | non-taint value flow |
| `REACHES(a, b, protocol?)` | reachability | network path through SGs, routes, LBs, peering |
| `CAN_ASSUME(p, q)` | privilege | closure over trust/grant facts |
| `CAN_ACCESS(p, r, action)` | privilege | effective permission after policy evaluation |

**Why virtual:** materializing these is either combinatorially explosive
(all-pairs taint), instantly stale (reachability after any SG change), or
imprecise (taint as edge transitive-closure loses context/field sensitivity —
the core lesson from CPG systems, see [02](02-prior-art-and-positioning.md)).
Solvers may cache results keyed by a dependency fingerprint of the input
subgraph; the cache is an optimization, never the source of truth.

### Class C — Annotation edges

`SANITIZES`, `PROTECTS`, `AUTHORIZES`, `CHECKS` — attached by adapters to
record where a control applies (e.g., this middleware PROTECTS these routes).
Consumed by solvers when evaluating `unless` clauses
([08](08-dataflow-and-taint.md)).

## Identity and merging

Node ids are deterministic functions of stable natural keys per type
(e.g. cloud ARN / resource id; code: repo + path + qualified name + signature
hash; sbom: purl). Two extractors observing the same entity converge on the
same id. Cross-domain *entity resolution* (this `cloud.ServerlessFunction`
runs that `code.Package`; this `runtime.Process` is that container) is
performed by dedicated linkers that emit `SAME_DEPLOYMENT` / `RUNS` edges
with confidence — these links are what make attack paths cross domains, and
they are the hardest data-quality problem in the system. They get their own
test suites and confidence thresholds.

## Scale model

Working assumptions for a mid-size enterprise tenant (sizing target, not
limit):

| Domain | Nodes | Edges |
|---|---|---|
| code (500 repos) | 50M | 200M |
| cloud (50 accounts) | 500K | 2M |
| identity | 100K | 1M |
| sbom | 5M | 20M |
| runtime (aggregated windows) | 1M/day rolling | 5M/day rolling |

Consequences:

- The USG is **partitioned by scope** (tenant → account/repo). Most rule
  evaluation is partition-local; cross-partition traversal happens only
  through declared cross-domain edges, which are few.
- Code sub-graphs dominate volume. CI mode keeps them ephemeral; Nexus stores
  **summaries** (call-graph at function granularity, concept-labeled
  endpoints, dataflow summaries per function — the same per-function summary
  artifacts the taint solver uses, [08](08-dataflow-and-taint.md)) rather
  than full ASTs.
- Runtime data enters as **aggregated windows** with retention tiers, never
  as raw event nodes.

## Incremental updates

Every ingestion produces a **delta** (added/removed/changed nodes and edges
with scope). The engine maintains:

1. **Rule→concept dependency index** — which rules can be affected by which
   concept labels.
2. **Solver dependency fingerprints** — each cached solver result records the
   subgraph fingerprint it depended on (e.g., the set of SG/route nodes a
   reachability answer traversed). A delta intersecting the fingerprint
   invalidates the cache entry.
3. **Finding lifecycle** — findings are keyed by (rule id, witness identity);
   re-evaluation marks findings new/persisting/resolved rather than
   recreating them ([14](14-findings-explainability-output.md)).

## Open questions

- **Storage engine.** Property graph DB vs. relational+Datalog vs. hybrid
  (relational facts + specialized solver indexes). Leaning hybrid: Class A
  facts in a columnar store with Datalog evaluation, solver-specific indexes
  (e.g., policy automata for `CAN_ACCESS`) built on the side. Needs a
  prototype benchmark against the scale model above.
- **Temporal model.** Do we keep history (graph-at-time-T) in v1? Attack-path
  forensics and "when did this become exposed" want it; cost is significant.
  Current position: snapshots + finding lifecycle in v1, full bitemporal
  later.
- **Schema evolution.** Adapter-driven label vocabularies change with
  ontology versions; nodes labeled under ontology vN must be re-labelable
  under vN+1 without full re-extraction. Proposal: store raw pattern-match
  facts alongside labels so re-labeling is an adapter re-run, not an
  extractor re-run.
