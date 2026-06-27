# 05 — Language Specification

Status: `SUPERSEDED` — this file records the historical v1 prototype syntax.
The production language contract is VyQL v2 in
[21-vyql-v2-definition.md](21-vyql-v2-definition.md). Production parsers and
shipped definitions must reject the v1 forms shown below, including `adapter`,
`match`, `sanitized_by`, and `guarded_by`.

## Design constraints

1. **Small formal core.** The rule layer is stratified Datalog with typed
   flow predicates. Not Turing-complete. Anything that needs general
   computation belongs in a solver or an adapter, not a rule.
2. **One consistent surface.** Earlier drafts mixed `unless protected_by X`,
   `unless checked Y`, and `require reachability` — three shapes for two
   ideas. This spec unifies them: **flow kind is the rule's verb; guards are
   `where`; exceptions are `unless`.**
3. **Compile-time safety.** Unknown concepts, unstratifiable negation, and
   solver/concept domain mismatches are compile errors, not runtime
   surprises.

## Surface syntax

### Top-level declarations

```
declaration := concept_decl | pattern_decl | adapter_decl
             | rule_decl | query_decl | statemachine_decl
             | import_decl
```

Concepts, patterns, and adapters are specified in
[06](06-ontology.md)/[07](07-adapters-and-patterns.md). This document covers
rules and queries.

### Rule grammar (EBNF, abridged)

```ebnf
rule        = "rule" qualified_name "{" meta_block? body "}" ;
meta_block  = "meta" "{" (meta_key ":" meta_value)* "}" ;

body        = flow_stmt clause* | match_stmt clause* ;

flow_stmt   = flow_verb endpoint "->" endpoint ;
flow_verb   = "taint" | "flow" | "reach" | "assume" ;
endpoint    = concept_ref binding? | "(" endpoint_expr ")" ;
binding     = "as" identifier ;

match_stmt  = "match" concept_ref binding clause* ;   (* non-flow rules *)

clause      = where_clause | unless_clause | along_clause ;
where_clause  = "where" predicate_expr ;
unless_clause = "unless" exception ;
along_clause  = "along" path_constraint ;             (* see 13-attack-paths *)

exception   = "sanitized_by" concept_ref
            | "guarded_by"   concept_ref
            | "present"      concept_ref "on" scope_expr
            | predicate_expr ;
```

### The four flow verbs

| Verb | Question it answers | Solver | Witness |
|---|---|---|---|
| `taint A -> B` | can attacker-controlled data from A reach B? | on-demand dataflow ([08](08-dataflow-and-taint.md)) | dataflow path |
| `flow A -> B` | does a value from A reach B (taint-agnostic)? | dataflow | dataflow path |
| `reach A -> B` | is there a network path from A to B? | reachability | network hop path |
| `grant A -> B` | can principal A obtain the privileges of B? | privilege closure | grant/trust chain |

The verb selects the solver. `require reachability`-style clauses from the
v0.1 draft are **removed**: the flow kind is never a bolt-on.

### The two exception forms

`unless sanitized_by C` — flow-scoped. The flow is suppressed only if a node
labeled with control concept `C` **dominates the witness path** and `C`
`neutralizes` the taint kind of the flow (typing checked at compile time).
Full semantics in [08](08-dataflow-and-taint.md).

`unless guarded_by C` — endpoint-scoped. The finding is suppressed if control
`C` applies to the sink/target endpoint (via a Class C `PROTECTS`/`CHECKS`
edge), regardless of path. Used for authorization-style controls where
"on the path" is not meaningful (e.g., an authz middleware guards a route).
**`guarded_by` is threat-typed exactly like `sanitized_by` when the target is a
typed sink:** the guard must neutralize a threat the sink is vulnerable to, so
an authz check cannot "guard" (silently suppress) a SQL-injection finding — that
is a compile error. Typing is skipped only when the match target is an untyped
business action (where `guarded_by` is a pure authorization gate). This was a
gap found during prototyping; see `poc/FINDINGS.md` #3.

A bare predicate `unless <expr>` covers residual cases (e.g. state-machine
guards). All three compile to stratified negation.

### Examples across domains (canonical forms)

```vyql
// SAST — identical for every language with adapters
rule vypr.injection.sql {
  meta { id: "VYQL-INJ-001", severity: high, cwe: [CWE-89], owasp: ["A03:2021"] }
  taint HTTP_INPUT -> SQL_EXECUTION
  unless sanitized_by SQL_PARAMETERIZATION
}

// Cloud — identical for AWS/Azure/GCP
rule vypr.cloud.public_database {
  meta { id: "VYQL-CLD-003", severity: critical }
  reach INTERNET -> DATABASE
  where DATABASE holds_asset_kind [CUSTOMER_DATA, PII]
}

// Identity
rule vypr.identity.external_to_admin {
  meta { id: "VYQL-IDN-002", severity: critical, attack: ["TA0004"] }
  grant EXTERNAL_PRINCIPAL -> ADMIN_PRIVILEGE
}

// Runtime
rule vypr.runtime.webshell {
  meta { id: "VYQL-RTM-001", severity: critical, attack: ["T1505.003"] }
  flow HTTP_REQUEST -> SHELL_EXECUTION
  where same_process_lineage
}

// Non-flow (match form) — misconfiguration
rule vypr.cloud.unencrypted_storage {
  meta { id: "VYQL-CLD-007", severity: medium }
  match STORAGE as s
  where not s has ENCRYPTION_AT_REST
  unless guarded_by COMPENSATING_ENCRYPTION   // e.g. client-side encryption
}

// Business logic (research track; declared model). `business.Refund` is an
// action concept (kind: action in the ontology) — no redundant `action`
// keyword; the kind comes from the ontology.
module vypr.bizlogic;
rule UnauthorizedRefund {
  meta { id: "VYQL-BIZ-001", severity: high }
  match business.Refund as a
  where a.actor is identity.User and a.resource is business.Order
  unless guarded_by core.OwnershipCheck
}
```

### State machines (business/workflow domain)

```vyql
state_machine Order {
  states  [CREATED, PAID, SHIPPED, REFUNDED]
  initial CREATED
  transition CREATED -> PAID
  transition PAID    -> SHIPPED
  transition PAID    -> REFUNDED
}

rule vypr.bizlogic.invalid_refund_transition {
  meta { id: "VYQL-BIZ-002", severity: high }
  match transition * -> REFUNDED on Order as t
  unless t.from == PAID
}
```

A `state_machine` declares the *spec*; observed transitions come from
adapters (code, logs, or runtime). The rule checks observations against the
spec. Who authors the spec is the central honesty question of the business
domain — see [12](12-domain-business-logic.md).

## Formal semantics

### Core model

A VyQL program denotes a stratified Datalog program over:

- **EDB (extensional database):** the materialized USG — `node(Id, Type)`,
  `edge(Id, Type, From, To)`, `prop(Id, Key, Val)`, `label(Id, Concept,
  Provenance)`.
- **Solver predicates:** `taint(A, B, Kind, Witness)`, `flow(A, B, Witness)`,
  `reach(A, B, Proto, Witness)`, `assume(A, B, Witness)`. Semantically these
  are ordinary (possibly infinite-feeling but finite) relations; operationally
  they are computed on demand by solvers with the bound arguments pushed
  down. The semantics of each solver predicate is specified in its solver
  document and is part of the language definition — two conforming engines
  must agree on what `taint` means at a declared sensitivity level
  ([08](08-dataflow-and-taint.md)).
- **IDB:** relations derived by rules.

### Rule translation (illustrative)

```vyql
taint HTTP_INPUT -> SQL_EXECUTION
unless sanitized_by SQL_PARAMETERIZATION
```

translates to:

```prolog
finding(rule_id, Src, Snk, W) :-
    label(Src, 'HTTP_INPUT', _),
    label(Snk, 'SQL_EXECUTION', _),
    taint(Src, Snk, Kind, W),
    sink_vulnerable('SQL_EXECUTION', Kind),          % ontology typing
    not suppressed(Src, Snk, W).

suppressed(Src, Snk, W) :-
    label(C, 'SQL_PARAMETERIZATION', _),
    neutralizes('SQL_PARAMETERIZATION', Kind),       % ontology typing
    dominates(C, W).                                  % path dominance, solver-checked
```

### Negation and stratification

`unless` is the only negation surface. The compiler builds the predicate
dependency graph; any cycle through negation is a **compile error** with the
cycle printed. Programs therefore have a unique perfect model (standard
stratified-Datalog semantics). Rationale: monotonic core + controlled
negation keeps evaluation predictable, incremental evaluation sound, and
proof trees well-defined.

### Three-valued provenance, two-valued findings

Facts carry confidence (adapter provenance, heuristic call-graph edges).
Evaluation is two-valued, but every derived tuple carries the **minimum
confidence along its derivation**, and rules can set
`meta { min_confidence: high }` to drop derivations through low-confidence
facts. This is bookkeeping on the proof tree, not a third truth value — it
keeps the semantics classical while letting consumers filter.

### Safety conditions

- Every variable in a rule head/finding must be bound in a positive body atom
  (range restriction).
- Solver predicates require their endpoint arguments bound by concept labels
  (no "compute all taint in the universe").
- Recursion is allowed in the Datalog core (e.g., user-defined transitive
  relations) but **not through solver predicates** — solvers handle their own
  fixpoints internally.
- **Endpoint kind checking.** Each flow verb constrains the *kind* of its
  endpoints, checked at compile time: `taint`/`flow` require `source → sink`;
  `reach` requires `exposure|asset → asset|exposure`; `assume` requires
  `principal → privilege|principal`. This rejects nonsense like a sink concept
  used as a taint source (`taint SQL_EXECUTION -> HTTP_INPUT`) or `assume`
  between non-identity concepts. Found missing during prototyping; see
  `poc/FINDINGS.md` #4.

## Queries vs. rules

`rule` produces findings with lifecycle. `query` is the same body grammar but
returns tuples for exploration/reporting (no finding lifecycle, no severity).
Attack-path declarations (`attack_path`) are a specialization of `query`
documented in [13](13-attack-path-analysis.md).

## Naming conventions & namespacing

VyQL uses a Go-style namespace model. **Identifiers are `[A-Za-z_][A-Za-z0-9_]*`,
namespaced with `.`; no dashes.**

- **`module <namespace>`** declares the namespace for the declarations that
  follow. Definitions (concepts, threat kinds, rules) are written with **short
  PascalCase names** inside their module; the canonical id is
  `<module>.<Name>`.

  ```vyql
  module code;
  concept HttpInput : source    { taint: [taint.UntrustedData]; cwe: [CWE_20] }
  concept SqlExecution : sink   { vulnerable_to: [injection.SqlInjection]; cwe: [CWE_89] }

  module vypr.injection;
  rule Sql {
    meta { cwe: CWE_89 }
    taint code.HttpInput -> code.SqlExecution      // cross-module refs: qualified
    unless sanitized_by core.SqlParameterization
  }
  ```

  A `module <namespace>;` declaration (terminated by `;`) applies to all
  declarations until the next `module`. Rule/concept names are the short
  PascalCase token (`Sql`, `HttpInput`); their canonical id is
  `<module>.<Name>` (`vypr.injection.Sql`, `code.HttpInput`).

- **PascalCase**, not ALL_CAPS, for all named entities: concepts
  (`code.HttpInput`), threat kinds (`injection.SqlInjection`), taint kinds
  (`taint.UntrustedData`), rules (`vypr.injection.Sql`). The `kind` enum stays
  lowercase (`source`, `sink`, `control`, …).
- **Namespaces** are lowercase: domains for concepts (`code`, `core`, `cloud`,
  `identity`, `sbom`, …), families for threat kinds (`injection`, `crypto`,
  `memory`, …), `taint` for taint kinds, `data` for asset kinds, vendor.category
  for rules.
- **CWE/CAPEC refs use the underscore form** — `CWE_89`, `CAPEC_66` — so they are
  bare identifiers (no dashes, no quotes). They normalize to the catalog
  ([16](16-standards-alignment.md), `go/taxonomy`).
- **Cross-module references are qualified** (`code.HttpInput`); same-module
  references may be short. This is exactly Go's `pkg.Name` model.

## Module system

```vyql
import vypr.ontology.core as core        // pins ontology by semver range in pack manifest
import vypr.rules.injection.*
```

- Rule packs are versioned bundles: rules + tests + a manifest pinning
  ontology and minimum engine versions ([15](15-rule-lifecycle-governance.md)).
- Name resolution is explicit; there is no global namespace — names resolve
  within the current `module`, then via qualified `namespace.Name`.

## Open questions

- Aggregation (`count`, `exists` over groups) — needed for rules like "role
  with more than N wildcard grants". Proposal: stratified aggregation
  (aggregate only over fully-derived strata), same restriction as negation.
- Inline pattern literals in rules for one-off `domain_specific` rules —
  convenience vs. boundary erosion. Current position: not allowed; revisit
  with field evidence.
- Surface syntax bikeshed (keyword choices, `holds_asset_kind` operator set)
  — to be settled in the v0.1 implementation review.
