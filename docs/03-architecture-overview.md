# 03 — Architecture Overview

Status: `STABLE`

## System pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│ INGESTION                                                       │
│  Source code · IaC · Cloud APIs · K8s · IAM · SBOM ·            │
│  Runtime telemetry (OCSF) · Threat intel (STIX) · Business defs │
└───────────────┬─────────────────────────────────────────────────┘
                │  extractors + pattern matchers
                ▼
┌─────────────────────────────────────────────────────────────────┐
│ ADAPTERS  (pattern → concept binding, with provenance)          │
└───────────────┬─────────────────────────────────────────────────┘
                ▼
┌─────────────────────────────────────────────────────────────────┐
│ UNIVERSAL SECURITY GRAPH (USG)                                  │
│  materialized nodes/edges + concept annotations                 │
│  virtual relations served by solvers                            │
└───────────────┬─────────────────────────────────────────────────┘
                ▼
┌─────────────────────────────────────────────────────────────────┐
│ VyQL ENGINE                                                     │
│  rule compiler → logical plan → evaluation                      │
│  ├─ Datalog core (semi-naive, stratified negation)              │
│  └─ Flow solvers (pluggable):                                   │
│      reach  → graph reachability w/ edge filters                │
│      assume → privilege closure                                 │
│      taint  → on-demand IFDS-style dataflow                     │
│      flow   → direct dataflow                                   │
└───────────────┬─────────────────────────────────────────────────┘
                ▼
┌─────────────────────────────────────────────────────────────────┐
│ OUTPUT                                                          │
│  Findings (+ proof trees) · Attack paths · Risk inputs          │
│  SARIF · Nexus API · explanations                               │
└─────────────────────────────────────────────────────────────────┘
```

## The four language layers

VyQL separates *what a structure looks like* from *what it means* from *what
is forbidden*. Each layer has a hard boundary enforced by the compiler.

### Layer 1 — Pattern Layer (technology-specific)

Patterns match raw structures in a specific technology: AST shapes, Terraform
blocks, Kubernetes YAML, IAM policy JSON, OCSF events. Each technology family
has a matcher dialect (see [07](07-adapters-and-patterns.md) — we embed
existing matchers like tree-sitter queries and JSONPath/CEL where possible
rather than inventing grammars).

```vyql
pattern javascript.member_call {
  match ast {
    node CallExpression as call
    where call.callee is MemberExpression as member
    bind receiver = member.object
    bind method   = member.property
  }
}
```

Patterns know nothing about security. They are reusable building blocks.

### Layer 2 — Concept Layer (technology-independent)

Concepts define security meaning and form the controlled vocabulary
([06](06-ontology.md)). Concepts carry `kind`, taint typing, control–threat
bindings, and standards mappings.

```vyql
package code;

concept HttpInput : source {
  taint: [taint.UntrustedData]
  cwe: [CWE_20]
}

concept SqlExecution : sink {
  vulnerable_to: [injection.SqlInjection]
  cwe: [CWE_89]
}

package core;

concept SqlParameterization : control {
  neutralizes: [injection.SqlInjection]
}
```

### Layer 3 — Adapter Layer (binding)

Adapters map patterns to concepts for one technology, with provenance and
confidence ([07](07-adapters-and-patterns.md)):

```vyql
adapter javascript.express {
  requires pattern javascript.member_call
  map property_access(req, "body")  to HTTP_INPUT
  map property_access(req, "query") to HTTP_INPUT
  provenance { author: vypr.research, reviewed: true, confidence: high }
}
```

One concept may have hundreds of adapters across technologies. Conflicts are
resolved by the precedence model in [07](07-adapters-and-patterns.md).

### Layer 4 — Rule Layer (intent)

Rules reference **only concepts** — never patterns, adapters, or raw node
types. This boundary is what makes rules durable:

```vyql
rule vypr.injection.sql {
  meta {
    id: "VYQL-INJ-001"
    severity: high
    cwe: [CWE-89]
    owasp: ["A03:2021"]
  }
  taint HTTP_INPUT -> SQL_EXECUTION
  unless sanitized_by SQL_PARAMETERIZATION
}
```

The compiler rejects any rule that names a pattern or technology-specific
node type. (Escape hatch: a rule may be marked `domain_specific` and scoped
to a graph namespace, for genuinely non-portable checks; these are
quarantined in their own rule packs.)

## Engine architecture

### Compilation

1. **Parse** rule → AST.
2. **Resolve** concepts against the loaded ontology version; reject unknown
   concepts (no stringly-typed vocabulary).
3. **Plan**: lower to a logical plan over the Datalog core. Flow verbs
   (`taint`, `reach`, `assume`, `flow`) lower to *solver calls* — opaque
   predicates served by the matching solver, not to edge traversals.
4. **Stratify**: `unless` clauses compile to negation; the planner checks
   stratification and rejects cyclic negative dependencies at compile time.

### Evaluation

- The Datalog core evaluates with semi-naive iteration; solvers are invoked
  with the bound source/sink concept sets and return flow tuples *with
  witness paths* (required for proof trees,
  [14](14-findings-explainability-output.md)).
- Solvers are domain experts: the `reach` solver understands security groups,
  route tables, and load balancers; the `taint` solver runs IFDS-style
  on-demand dataflow over code ([08](08-dataflow-and-taint.md)); the `assume`
  solver computes privilege closure ([09](09-domain-cloud-identity.md)).
- Solver choice is keyed by the namespaces of the concepts involved; a rule
  spanning domains (attack path) composes solver results through the Datalog
  core ([13](13-attack-path-analysis.md)).

### Incrementality

The USG is updated incrementally (a commit, a config change, a runtime event
batch). The engine maintains per-rule dependency summaries so that a delta
re-evaluates only affected rules over affected subgraphs. Full design in
[04](04-universal-security-graph.md) §"Incremental updates". This is a v1
requirement, not an optimization: cloud and runtime domains are meaningless
with batch-only evaluation.

## Component boundaries and ownership

| Component | Owns | Must not know about |
|---|---|---|
| Extractors | producing raw nodes/edges per technology | concepts, rules |
| Pattern matchers | structural matching dialects | concepts, rules |
| Adapters | pattern→concept binding | rules, other adapters' internals |
| Ontology | concept definitions, taint kinds, mappings | technologies, adapters |
| Rule packs | intent, metadata, tests | patterns, technologies |
| Solvers | flow semantics per domain | rule syntax |
| Engine core | planning, stratification, evaluation, proofs | technologies |

The two boundaries that must never erode, in order of importance:

1. **Rules ↔ concepts only.** The day a rule references `aws_s3_bucket`
   directly, rule durability is lost and VyQL becomes another per-tech DSL.
2. **Solvers own flow semantics.** The day `taint` is implemented as
   transitive closure over materialized edges "temporarily", SAST precision
   is lost and never recovered.

## Deployment shapes

- **Nexus-embedded** (primary): engine runs against the central Nexus USG;
  continuous evaluation on graph deltas.
- **CI mode**: per-repo subset — code extractor + relevant adapters + Tier 2
  rule packs; emits SARIF; graph is ephemeral and scoped to the repo plus an
  imported summary of org context (e.g., which services are internet-facing).
- **CLI/dev mode**: same as CI with local caching; used by rule authors with
  the test harness ([15](15-rule-lifecycle-governance.md)).
