# 14 — Findings, Explainability, and Output

Status: `STABLE` (core model); SARIF mapping details `DRAFT`

## Principle: explainability is an engine property

Every finding carries a machine-readable derivation produced automatically by
the evaluator. There is **no rule-level `explain` block** — rule authors
cannot opt in or out, so evidence is uniform across the entire rule corpus.
(Earlier drafts had `explain { show source; show path; ... }`; removed —
presentation choices belong to renderers, not rules.)

## One finding per sink

Findings are deduplicated to **one per (rule, sink)**: a vulnerable sink reachable
from N sources is a single issue, not N. The flow evaluator keeps the
highest-confidence source as the representative witness (ties resolve to the first,
deterministically). This is presentation only — recall is unchanged, and the
suppressed sources remain available as alternate witnesses. Without it, real-world
scans inflate badly (a single logged/echoed value reachable from 25 request reads
became 25 findings).

## The proof tree

Stratified Datalog gives every derived tuple a well-defined derivation. The
engine records, per finding:

```
finding
├─ rule: vypr.injection.sql @ 1.2.0   (pack vypr.rules.injection 2024.06)
├─ ontology: 1.4.0   engine: 0.9.2   profile: vypr.default.v1
├─ bindings
│   ├─ source: code.CallSite#a91f  (orders-svc/src/refund.js:42  req.body.note)
│   │    └─ label HTTP_INPUT  ← adapter javascript.express@1.4.0
│   │         (fidelity: resolved; won over javascript.http_generic by specificity)
│   └─ sink: code.CallSite#b22e   (orders-svc/src/refund.js:67  knex.raw(...))
│        └─ label SQL_EXECUTION ← adapter javascript.knex@1.1.0
├─ solver witness: taint, kind UNTRUSTED_DATA
│   └─ path: refund.js:42 → buildNote (refund.js:51 summary p0→ret)
│            → notes.js:18 → refund.js:67 arg0
├─ negation evidence: unless sanitized_by SQL_PARAMETERIZATION
│   └─ no SQL_PARAMETERIZATION label dominates witness path
│      (nearest: knex parameter binding at refund.js:71 — different statement)
├─ confidence: high  (min over derivation)
└─ fingerprint: sha256(rule id + witness identity)   → finding lifecycle key
```

Two elements deserve emphasis:

- **Negation evidence.** For every `unless`, the proof records *what was
  checked and not found*, including near-misses. "We looked for a
  parameterization control on this path; the closest one is on a different
  statement" is the difference between a trustworthy finding and noise — and
  it's what makes triage fast.
- **Label provenance.** The proof shows which adapter believed what, at what
  fidelity, and how conflicts resolved ([07](07-adapters-and-patterns.md)).
  A false positive is therefore *diagnosable*: bad adapter mapping, bad
  pattern fidelity, or bad rule — three different fixes, distinguishable
  from the proof alone.

Witness formats per solver: dataflow paths (taint/flow), hop chains with
permitting-rule ids (reach), grant/trust chains (assume), event evidence
refs (runtime). Attack-path findings nest the per-hop proofs
([13](13-attack-path-analysis.md)).

## Finding lifecycle

Findings are stateful objects keyed by fingerprint (rule id + witness
identity, tolerant to line drift via content anchoring):

```
new → open ⇄ persisting → resolved (fact gone)
                        → suppressed (human or VEX, with reason + expiry)
                        → invalidated (ontology/adapter change removed basis)
```

- Re-evaluation transitions states; it never duplicates findings.
- `invalidated` is distinct from `resolved` and triggers re-audit listings
  when an ontology/adapter *major* change retracts findings en masse
  ([15](15-rule-lifecycle-governance.md) impact reports).
- Suppressions are first-class facts with provenance, scope (this finding /
  this rule on this resource / this rule in this repo), justification, and
  expiry. Expired suppressions reopen findings; unbounded suppressions
  require elevated permission. VEX statements enter as suppressions with
  `origin: vex` ([16](16-standards-alignment.md)).

## Confidence and routing

`confidence = min(derivation)` over label fidelity, solver edge confidences
(heuristic call edges, unevaluatable IAM conditions), and linker confidence.
Consumers route on it:

| Confidence | Default routing |
|---|---|
| high | CI gate / alert |
| medium | dashboard, PR annotation (non-blocking) |
| low | review queue only |

Rules can set `confidence_floor` to drop derivations below a threshold
entirely ([05](05-language-specification.md)). Tenants can re-map routing;
the floor is the rule author's honesty mechanism.

## Output formats

### SARIF (normative for code-shaped findings)

- `run.tool` = engine + pack versions; `rule` objects carry full metadata
  (CWE/OWASP taxa via SARIF taxonomies).
- Witness path → `codeFlows[].threadFlows[]`; source/sink →
  `relatedLocations`; fingerprint → `partialFingerprints` (stable across
  line drift, the key CI integration property).
- Proof-tree extras (label provenance, negation evidence) ride in
  `properties` bags under a stable `vypr.*` key schema.

### Nexus API (normative for everything)

Full-fidelity JSON: finding + proof tree + graph node refs (so UIs can pivot
from finding to graph neighborhood). Attack paths and choke-point reports
are Nexus-API-only in v1 (SARIF has no path-set shape; revisit with OASIS if
needed).

### Human renderings

Renderers consume the proof tree — never bespoke per-rule text:

```
Untrusted data reaches a SQL query without parameterization.

  req.body.note            refund.js:42   ← attacker-controlled (Express)
   → buildNote(...)        refund.js:51
   → knex.raw(query)       refund.js:67   ← SQL execution (Knex)

  No parameterization on this path. Note: refund.js:71 uses parameter
  binding — apply the same approach to the statement at line 67.

  Why this matters here: orders-svc is internet-reachable (ALB sg-0a1…)
  and orders-db holds PII.                       [from graph context]
```

The "why this matters here" line is generated from graph-context joins
(exposure, asset labels) — the cross-domain payoff surfaced at the
individual-finding level. Externally polished explanations are allowed as a
presentation layer but must be generated *from the proof tree* and carry no
claims absent from it ([18](18-ai-integration.md)).

## Open questions

- Witness identity under refactors (function rename moves the whole path):
  content-anchored fingerprints handle line drift; rename-tolerance needs
  evaluation against real repo histories.
- Proof-tree size budgets for pathological witnesses (500-hop reach chains);
  proposal: full witness stored, rendered views elide with expansion.
- OCSF finding emission (OCSF has a finding class) alongside SARIF — likely
  cheap, decide with the runtime tier.
