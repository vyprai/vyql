# 13 — Attack Path Analysis

Status: `DRAFT` (ships with Tier 1; deepens with each domain added)

> **Not implemented.** This document is design, not a description of the shipped
> scanner. The `attackpath` package has no callers outside itself and is not reachable from the CLI. Read it as intent; do not read it as a feature list.


Attack path analysis is the payoff for the unified graph: traversals that
cross domain boundaries — internet exposure (cloud) → vulnerable code (SAST)
→ over-privileged identity (IAM) → sensitive data (assets). Each hop is
individually known to some siloed tool; the *path* is visible only to a
system that holds all domains in one representation.

## Declaration

`attack_path` is a specialized query form ([05](05-language-specification.md)):

```vyql
attack_path vypr.path.internet_to_customer_data {
  meta { id: "VYQL-ATP-001", attack: ["TA0001", "TA0008", "TA0010"] }
  start  INTERNET
  target asset holds_asset_kind [CUSTOMER_DATA]
  along  [reach, exploits, assume, can_access]
  max_hops 8
}
```

- `start` / `target` are concept-bound node sets.
- `along` declares which **step relations** the traversal may compose, in
  any order (a path may alternate reach → exploit → assume → reach …).
- Output is paths (witness chains), not booleans.

## Step relations

Attack paths compose a closed set of step relations, each backed by a solver
or by exported findings:

| Step | Backed by | Meaning |
|---|---|---|
| `reach(a, b)` | reachability solver ([09](09-domain-cloud-identity.md)) | network access |
| `assume(p, q)` | privilege solver | identity escalation |
| `can_access(p, r, act)` | privilege solver | effective permission |
| `exploits(a, b)` | **finding-derived edges** | a confirmed vulnerability finding on b reachable/triggerable from a (e.g. a taint finding on an exposed route) |
| `lateral(a, b)` | composite | reach + credential/asset presence enabling movement (e.g. instance holds key for b) |
| `runs(w, c)` / `same_deployment` | linkers ([04](04-universal-security-graph.md)) | domain-bridging identity |

`exploits` is the crucial design move: **rule findings feed back into the
graph as edges.** A SQLi finding on route R exports
`exploits(INTERNET-facing entry, R.database, via: VYQL-INJ-001)` with the
finding's confidence. Attack paths therefore strengthen automatically as
each domain's rule packs improve — the path engine itself stays small.
Finding-derived edges are Class B-like: regenerated from finding lifecycle,
never hand-persisted, and they carry the originating finding id so path
proofs nest the finding's own proof tree.

## Evaluation

Path queries run on a **scoped product graph**: nodes reachable from `start`
under the `along` relations, bounded by `max_hops` and per-step budgets.
Practical constraints:

- Step relations are queried through their solvers with direction-aware
  pruning (bidirectional search from start and target).
- Paths are deduplicated by *security-equivalence* (same hop types through
  same choke points), not raw node sequence — otherwise large flat networks
  produce thousands of trivially-distinct paths.
- Cycles are cut by monotonic state: a hop must add privilege, location, or
  data access not already held (attack progress, not random walk).

## Scoring and choke points

Raw path lists are unusable at enterprise scale; the deliverables are:

1. **Path score** — composed from hop confidences, exploit difficulty
   priors (per step type and finding class), and target asset sensitivity.
   Scoring weights live in the risk model ([17](17-risk-model.md)), not in
   path declarations.
2. **Choke-point analysis** — min-cut over the scored path set: "these 3
   security-group rules / this 1 role trust policy sever 80% of paths to
   CUSTOMER_DATA." This is the remediation product: fix lists ranked by
   paths severed per change. Witnesses make each proposed cut concrete (the
   exact SG rule id, the exact trust statement).
3. **Blast radius** (inverse query): from a given compromised node, what is
   reachable/assumable — same machinery, `start` bound to the incident
   node. Feeds incident response.

## Worked example

```
Internet
  ── reach ──▶ ALB (sg-0a1.. allows 0.0.0.0/0:443)
  ── reach ──▶ orders-svc (target group)
  ── exploits ──▶ orders-db          [VYQL-INJ-001 on POST /orders/{id}/refund,
                                      taint witness: req.body.note → knex.raw]
  ── can_access ──▶ s3://acme-exports [db instance role allows s3:GetObject*,
                                      via assumed role data-export]
  target: CUSTOMER_DATA (s3://acme-exports labeled PII by classification)

score: 8.7  | choke points: sg-0a1 ingress rule (severs 12 paths),
              parameterize refund handler (severs 3),
              scope data-export role (severs 9)
```

Every hop cites its witness; the `exploits` hop nests the full taint proof
tree ([14](14-findings-explainability-output.md)).

## ATT&CK alignment

Step types and finding classes carry ATT&CK technique mappings
([16](16-standards-alignment.md)); a rendered path can be projected onto the
ATT&CK matrix (initial access → execution → privilege escalation →
exfiltration) for analyst familiarity and for threat-intel join: "which
current paths use techniques attributed to actor groups targeting our
sector" — a `query` joining `threat.*` projections with path results.

## Open questions

- Path result lifecycle: paths are derived objects over volatile inputs;
  proposal is finding-style identity keyed on (start, target,
  choke-point-set) so dashboards don't churn on every re-evaluation.
- Simulation mode ("if we made this change, which paths close?") — requires
  counterfactual graph overlays; valuable for the remediation product,
  needs an overlay design in the USG.
- Probabilistic path scoring (priors per hop type) — keep simple and
  monotonic in v1; FAIR-style refinement belongs to [17](17-risk-model.md).
