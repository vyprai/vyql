# 08 — Data Flow and Taint Semantics

Status: `DRAFT` — semantics proposed; precision levels to be validated
against benchmark suites (OWASP Benchmark, real-world juliet-style corpora)
during Tier 2 implementation.

This document defines what `taint A -> B` and `flow A -> B` *mean*. It exists
because "graph native" is the part of the VyQL pitch most likely to mislead:
interprocedural dataflow is **not** reachability over materialized edges, and
the difference is the difference between a SAST engine and a false-positive
generator. Two conforming engines must agree on these semantics at a declared
precision level.

## Why taint is not a graph edge

Materializing `FLOWS_TO` edges and computing taint as transitive closure
fails three ways:

1. **Explosion.** All-pairs flow facts for a 1M-LOC service are combinatorial.
2. **Context insensitivity.** Closure through a shared helper
   (`function id(x) { return x }`) merges every caller's data into every
   other caller — taint "teleports" between unrelated call sites.
3. **Field insensitivity.** `obj.a = tainted; sink(obj.b)` becomes a finding
   if flow is tracked at object granularity.

CodeQL computes dataflow on demand for exactly these reasons; CPG systems
that naively closure over flow edges rediscover them painfully. Therefore:
**`TAINTS`/`FLOWS_TO` are virtual relations** (Class B,
[04](04-universal-security-graph.md)) served by a dedicated solver.

## Solver model: summary-based on-demand dataflow

The taint solver follows the IFDS/summary paradigm:

- **Intra-procedural:** per-function flow facts computed over the extractor's
  SSA/def-use form at full flow sensitivity.
- **Inter-procedural:** per-function **summaries** — "param 0 flows to return
  value", "param 1 flows into field f of param 0" — computed once, reused at
  every call site. Call-site matching gives context sensitivity (k-CFA-style
  bounded; level set by the precision profile).
- **On demand:** evaluation starts from the rule's bound endpoints
  (concept-labeled sources and sinks) and explores only relevant paths.
- Summaries are the unit of caching and incrementality: a changed function
  invalidates its summary and dependents' query results, not the world. They
  are also what Nexus persists for code ([04](04-universal-security-graph.md)
  §scale).

### Precision profile

A named, versioned declaration of sensitivity — part of engine conformance:

```
profile vypr.default.v1 {
  flow_sensitive:    true
  field_sensitive:   true   (access-path depth ≤ 3, then smashing)
  context_sensitive: call-site, k = 2
  path_sensitive:    false  (branch conditions not correlated in v1)
  containers:        keyed where index is literal, else whole-container
  implicit_flows:    off    (control-dependence taint off by default)
  reflection/eval:   modeled as taint-preserving unknown
}
```

Rules may request stricter/looser profiles in `meta`; findings record the
profile used. Changing the default profile is a major engine version event.

### Taint propagation, kinds, and labels

Taint facts are typed: `taint(Src, Snk, Kind, Witness)` where `Kind` comes
from the source concept's `taint:` declaration ([06](06-ontology.md)).
Propagation is defined by:

- **Default propagators:** assignments, parameter passing, returns, field
  writes/reads per the precision profile, string concatenation/interpolation.
- **Adapter-declared propagators:** library functions that preserve taint
  (`map call(lodash.merge) propagates arg1 -> return`) or transform kinds.
- **Adapter-declared sanitizer transfer functions:** see below.

## The `unless sanitized_by` semantics (normative)

Given a witness path `W = n₀ → n₁ → … → nₖ` (source to sink) and control
concept `C` with `applies: path`:

> The flow is suppressed iff some node `s` labeled `C` lies **on W** such
> that the tainted value at `s` is the value that continues along W, and
> `C.neutralizes` includes the threat kind of the rule's sink.

Precisely: sanitization is a **transfer function on the dataflow fact**, not
a structural check. The solver kills the taint fact at `s`; if no fact
survives to the sink, no finding.

**Operationally, "dominates the path" reduces to "no surviving fact reaches the
sink."** A finding exists iff some path carries a live (un-killed) fact to the
sink; if every path passes through a neutralizing control, all facts die and
there is no finding. This is cleaner than computing graph dominators and yields
the table below directly — confirmed by the prototype, which implements exactly
this (`poc/solvers/taint.py`, `poc/FINDINGS.md` #1).

Consequences (these are the cases that distinguish a real engine):

| Case | Result | Why |
|---|---|---|
| Sanitizer exists elsewhere in program, not on path | **finding** | never touched the flow |
| Sanitizer on one branch, tainted value flows around it on the other | **finding** | the surviving fact reaches the sink via the unsanitized branch |
| Value sanitized, then *re-tainted* (concatenated with fresh taint) | **finding** | the fresh taint is a *distinct source*; its fact never met the sanitizer (no special "re-taint" node needed — per-source propagation handles it; `poc/FINDINGS.md` #2) |
| Sanitizer applied to a different field of the same object | **finding** (within access-path depth) | field-sensitive facts |
| Sanitizer wraps the sink call itself (parameterized API) | **no finding** | adapter maps the API to a control with `applies: path` at the sink boundary, or simply doesn't map it as a sink |
| Wrong-type sanitizer (`HTML_ESCAPE` on SQLi rule) | **compile error** | ontology typing ([06](06-ontology.md)) |

`unless guarded_by C` (endpoint-scoped) is structural by design: suppressed
iff a `PROTECTS`/`CHECKS` Class C edge from a node labeled `C` covers the
sink's scope (e.g., authz middleware covering the route that contains the
sink). Used where "on the dataflow path" is not the right question.

## `flow` vs `taint`

`flow A -> B` uses the same solver without taint-kind gating or sanitizer
transfer functions — "does this value reach there at all". Used for
secret-leakage rules (`flow SECRET_VALUE -> LOG_WRITE`), where *sanitization*
is usually not a meaningful concept but redaction controls can still be
modeled as kind transformers.

## Cross-domain flow composition

Taint does not stop at process boundaries. Composition points, in order of
shipping:

1. **HTTP boundaries (v1):** a `code.Route` labeled as serving
   `EXTERNAL_API_RESPONSE`/`HTTP_INPUT` in one service, linked by deployment
   linkers ([04](04-universal-security-graph.md) §identity) to callers in
   another — composed in the Datalog core, with the cross-service hop carried
   at `confidence: medium` unless API schemas confirm it.
2. **Queue/stream boundaries:** producer `MESSAGE_OUTPUT` to consumer
   `MESSAGE_INPUT` via broker topology from the cloud graph.
3. **Storage boundaries (second-order injection):** `DATABASE_WRITE` of
   tainted data + `DATABASE_READ` as second-order source — off by default
   (noisy), enabled per-rule.

This composition — solver results joined through the Datalog core across
domain boundaries — is what no single-domain tool can do, and it is the
technical heart of attack paths ([13](13-attack-path-analysis.md)).

## What the reach and assume solvers share with this design

`reach` and `assume` are also virtual-relation solvers with witnesses and
caches, but their fixpoints are genuinely graph-shaped (network topology,
privilege closure) and far cheaper; their semantics live in
[09](09-domain-cloud-identity.md). The shared contract for **all** solvers:

1. Inputs: bound endpoint sets + rule context (taint kinds, profile).
2. Outputs: tuples with **witnesses** sufficient to reconstruct a proof tree.
3. Declared semantics versioned with the engine.
4. Cache entries carry dependency fingerprints for incremental invalidation.

## Open questions

- **Implicit flows** (control-dependence taint): off by default; needed for
  some sandbox-escape rules. Revisit with demand.
- **Path sensitivity:** v1 is path-insensitive; the known FP class
  (sanitize-or-throw validation idioms) may force lightweight path
  correlation. Measure on benchmarks first.
- **Framework lifecycle modeling** (DI containers, route dispatch,
  serialization hooks): the classic SAST call-graph gap. Plan: adapters can
  declare synthetic call edges (`map route_definition to dispatches handler`)
  — needs prototyping on Spring and Express to validate the shape.
- **Solver conformance suite:** the table of sanitizer cases above must
  become an executable conformance test set before a second engine
  implementation exists.
