# 17 — Risk Model

Status: `DRAFT` — v1 scope is deliberately modest. The earlier draft's
`risk { likelihood 0.8, impact HIGH }` block is removed: unexplained point
probabilities are exactly the kind of unauditable assertion VyQL exists to
eliminate. Every risk number must be **derived, decomposable, and
witness-backed**, or it doesn't ship.

## Position

Risk in VyQL is a **derived layer over findings and graph context**, not a
rule-authoring feature. Rule authors declare *severity* (the intrinsic
badness of the weakness class) and *confidence floors*; the risk layer
computes context-adjusted priority from graph facts. Rule files contain no
probabilities.

## v1: factor-based prioritization (shipping)

Each finding gets a priority score composed from named factors, every factor
traceable to graph facts or external data:

```
priority(f) = severity(f)            // rule metadata, or from_advisory (CVSS)
            ⊕ exposure(f)            // reach(INTERNET, subject)? confirmed by runtime?
            ⊕ asset_proximity(f)     // path length / can_access to sensitive assets
            ⊕ exploit_likelihood(f)  // EPSS, KEV membership, exploit maturity (SCA)
            ⊕ privilege_context(f)   // subject's blast radius via assume-closure
            ⊕ control_pressure(f)    // compensating controls present (guarded_by near-misses)
            ⊖ confidence_discount(f) // derivation confidence
```

`⊕` is a documented, monotonic combination (v1: weighted band arithmetic,
not multiplied probabilities — bands are honest about precision; fake
decimals are not). The output is a band (P0–P4) plus the factor breakdown:

```
P0  VYQL-INJ-001 @ orders-svc/refund.js:67
    severity: high (CWE-89)
    exposure: internet-reachable (reach witness: ALB sg-0a1…) — confirmed
              by runtime traffic (last 24h)
    asset:    sink database holds PII (tenant classification)
    exploit:  injection class, no public exploit required
    privilege: db role can read 3 PII stores (assume closure)
    confidence: high
```

Every factor line carries its witness. The factor weights are tenant-tunable
within guardrails; defaults are Vypr-maintained and benchmark-calibrated
(ordering quality measured against expert triage on benchmark orgs — the
metric is rank correlation with expert judgment, not absolute scores).

Attack-path scoring ([13](13-attack-path-analysis.md)) uses the same factor
vocabulary per hop; choke-point ranking inherits it.

## v2: quantitative scenarios (designed-for, not shipped)

The graph holds the inputs a FAIR-style analysis needs: threat-event
frequency proxies (exposure + threat-intel actor interest via `threat.*`
joins), vulnerability (findings with confidence), loss magnitude proxies
(asset kinds + tenant-declared business impact). v2 scope, gated on design
partners who actually run FAIR programs:

- **Scenario objects:** a named (threat, path-set, asset) triple with
  distributions over frequency and magnitude — Monte Carlo over path scores
  rather than point estimates.
- **Calibration discipline:** distributions require declared sources
  (industry priors, tenant history, expert elicitation records). No
  unsourced numbers — same provenance bar as everything else.
- Mappings: FAIR taxonomy for factor names; ISO 31000 vocabulary for
  process documentation; attack-tree export for paths feeding external
  analysis. (B-CAVe and similar frameworks: evaluate with design partners
  rather than pre-committing.)

## What we refuse to do

- Emit probabilities without decomposable derivations.
- Let rule authors hardcode likelihood (severity yes; likelihood never —
  likelihood is context, and context lives in the graph).
- Conflate confidence (is the finding real?) with likelihood (will it be
  exploited?). They are separate fields everywhere in the system.

## Open questions

- Factor weight learning from tenant triage behavior (accept/dismiss as
  signal) — promising, but feedback loops can entrench bias; needs careful
  design.
- Cross-finding aggregation ("risk of this service/team/BU") — roll-up
  semantics (max? path-aware composition?) deferred to Nexus reporting
  design.
- Temporal decay: runtime-confirmed exposure ages ([11](11-domain-supply-chain-runtime.md)
  open questions) — factor recomputation cadence must match graph delta
  cadence.
