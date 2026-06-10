# 12 — Domain: Business Logic Analysis

Status: `RESEARCH` — do not build against this document without a separate
design review. This is the most ambitious and least proven part of the VyQL
vision, and this document is deliberately honest about which parts are
engineering and which parts are open research.

## The model

Traditional vulnerability analysis is `source → sink`. Business logic
analysis is:

```
Actor → Action → Resource    under    Constraints
```

plus workflow structure (states, transitions, approvals, invariants).

`business.*` vocabulary: `Actor`, `Action`, `Resource`, `Workflow`, `State`,
`Transition`, `Approval`, `Constraint`, `Invariant`; concepts like
`OWNERSHIP_CHECK`, `APPROVAL_REQUIREMENT`, `SEGREGATION_OF_DUTIES`.

```vyql
rule vypr.bizlogic.unauthorized_refund {
  meta { id: "VYQL-BIZ-001", severity: high }
  match action REFUND as a
  where a.actor is USER and a.resource is ORDER
  unless guarded_by OWNERSHIP_CHECK
}

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

rule vypr.bizlogic.self_approval {
  meta { id: "VYQL-BIZ-004", severity: high }
  match approval as ap on action as a
  where ap.approver == a.actor
}
```

The language layer is the easy part: these rules compile to the same Datalog
core as everything else. **The entire difficulty is where the
`business.*` facts come from.**

## The extraction problem, stated honestly

For `unauthorized_refund` to fire, something must have established that:

1. A code path constitutes the action `REFUND` (action identification),
2. on a resource of class `ORDER` (resource binding),
3. invoked by an actor of class `USER` (actor binding),
4. and whether an `OWNERSHIP_CHECK` guards it (control recognition).

Steps 1–3 require recovering *business semantics* from artifacts that don't
declare them. This is not an adapter-sized problem; in the general case it is
unsolved. Any roadmap that promises "automatic business logic analysis of
arbitrary code" is writing checks the field cannot cash. We therefore define
three sourcing modes, in increasing order of ambition:

### Mode 1 — Declared models (v1 of this domain; engineering, not research)

The customer (or Vypr services) declares the business model in VyQL:
state machines, action definitions bound to code/API anchors, asset
classifications.

```vyql
business_model acme.orders {
  action REFUND   anchors [ route("POST /orders/{id}/refund"),
                            code.Method("RefundService.execute") ]
  resource ORDER  anchors [ code.Class("Order"), db.table("orders") ]
  actor USER      anchors [ principal(AUTHENTICATED_USER) ]
}
```

Anchors bind business concepts to graph nodes the extractors already
produce. From there, everything is ordinary VyQL: `guarded_by
OWNERSHIP_CHECK` resolves through Class C edges that *code adapters* can
attach (an ownership-check adapter recognizing `order.userId == ctx.user.id`
comparison patterns is hard but adapter-shaped). Observed transitions come
from runtime/log adapters (Mode 3 events) or from state-field write analysis.

This mode is honest, valuable, and shippable: it is spec checking, and it is
what financial-services customers already do manually in design reviews.
Positioning: "encode your workflow invariants once; Vypr continuously checks
code, config, and runtime against them."

### Mode 2 — Assisted extraction (AI-drafted models; near-term research)

LLMs draft Mode 1 declarations from evidence the graph already holds: route
names, handler names, OpenAPI specs, ORM models, state-enum definitions,
audit-log schemas. A human confirms the draft (same trust pipeline as AI
adapters, [18](18-ai-integration.md)). The bet: business models are *small*
(dozens of actions, not thousands), so human confirmation scales where it
wouldn't for code adapters. This is a product-defining application of the AI
layer and is plausible within the program's horizon — but it ships behind
review gates, with extraction quality measured against Mode-1
ground truth from design partners.

### Mode 3 — Behavioral inference (long-term research)

Infer state machines and constraints from observed behavior (runtime events,
audit logs): process mining for workflows, invariant mining for constraints
("approver ≠ requester held in 100% of 50k observed approvals — flag the
deviation"). Promising literature exists (process discovery, specification
mining), but false-invariant rates and concept drift make this a research
track with no committed delivery. Anomaly-shaped output (deviations from
mined invariants) may ship earlier as *signals* (low confidence, review
queue) rather than findings.

## Fraud and abuse scenarios

With Mode 1 models plus runtime events, fraud rules become expressible:

```vyql
rule vypr.bizlogic.refund_velocity {
  meta { id: "VYQL-BIZ-010", severity: medium, confidence_floor: low }
  match window(24h) actions REFUND by same actor as a
  where count(a) > tenant_threshold(refund_velocity)
}
```

Aggregation-over-windows pushes on the language's aggregation design
([05](05-language-specification.md) open questions) and the streaming
evaluator ([11](11-domain-supply-chain-runtime.md)). Fraud scoring beyond
rule-shaped detection (ML models) is out of VyQL scope; VyQL rules can
*consume* model outputs as labeled facts.

## Why keep this domain in the architecture at all

Because the graph and ontology make the *declared* version cheap, and the
declared version alone is differentiating: no SAST/CSPM competitor can check
"refund requires ownership" across code, API gateway config, and runtime
behavior simultaneously. The research modes then have a well-defined target
representation to extract *into* — which is precisely how the AI strategy
de-risks: generation is always into a reviewable, testable, declarative
artifact.

## Commitments and non-commitments

| Commitment | Status |
|---|---|
| `business.*` schema + state machines + Mode 1 declared models | committed (post-Tier-2) |
| Ownership/authz-check recognition adapters for top frameworks | committed, scoped to recognizable idioms |
| Mode 2 AI-drafted models with human review | research with design partners; no GA date |
| Mode 3 behavioral inference | research; signals-only if it ships |
| "Automatic business logic vulnerability discovery in arbitrary code" | **explicit non-claim** — not in any roadmap or marketing material |
