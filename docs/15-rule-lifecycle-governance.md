# 15 — Rule Lifecycle and Governance

Status: `STABLE` (process); harness tooling `DRAFT`

VyQL's durability claim rests on governance: rules outlive technologies only
if the ontology, adapters, and rule packs evolve under explicit compatibility
contracts. This document defines the artifact model, versioning rules,
testing harness, and review gates.

## Artifact model

| Artifact | Unit of release | Contains |
|---|---|---|
| **Ontology** | `vypr.ontology.core` (semver) | concept definitions, typing, hierarchies, standards mappings |
| **Adapter packs** | per technology family (semver) | adapters + patterns + fixtures, pinned to ontology range |
| **Rule packs** | per domain (calver + semver) | rules + tests + docs, pinned to ontology range + min engine |
| **Engine** | semver | evaluator, solvers, precision profiles |
| **Tenant config** | per tenant | overrides, suppressions, custom concepts/rules under tenant namespace |

Every pack has a manifest:

```toml
[pack]
name = "vypr.rules.injection"
version = "2026.06.1"
ontology = ">=1.4 <2.0"
engine   = ">=0.9"

[depends]
concepts = ["HTTP_INPUT", "SQL_EXECUTION", "SQL_PARAMETERIZATION", ...]
```

The compiler verifies every referenced concept against the pinned ontology
at pack build time — a rule pack cannot ship referencing a concept that
doesn't exist, and an ontology release CI job compiles every shipped pack
against the candidate version.

## Versioning and compatibility contracts

### Ontology

- **Minor (additive):** new concepts, new refinements, added standards
  mappings. Existing rules unaffected by construction.
- **Major (semantic):** changed typing (`neutralizes`, `vulnerable_to`),
  changed hierarchy, removed/renamed concepts. These can flip findings.
  Gate: an **impact report** — the full Vypr rule corpus re-run against
  benchmark graphs, diffing findings (new / retracted / confidence-changed),
  reviewed before release. Retractions in the field surface as
  `invalidated` lifecycle transitions, never silent disappearance
  ([14](14-findings-explainability-output.md)).
- Renames go through aliases with a two-minor-release deprecation window;
  the compiler warns on alias use.

### Adapters

- Patch: fixture-verified mapping fixes. Minor: new mappings, new version
  targets. Major: removed mappings or fidelity downgrades (require impact
  report scoped to affected rules).
- Adapter releases re-run their fixtures plus the rule packs that depend on
  their concepts against integration corpora.

### Rules

- Rule **ids are immutable**; rule logic changes bump rule version; severity
  or `confidence_floor` changes are minor but appear in release notes
  (they re-route findings).
- Deleted rules leave tombstones (id + reason) so historical findings remain
  interpretable.

## The rule testing harness

The Semgrep lesson: golden tests adjacent to rules are the single highest-ROI
quality mechanism in this kind of system. Mandatory at three layers:

### 1. Adapter fixtures (label tests)

Annotated minimal inputs per adapter ([07](07-adapters-and-patterns.md)):
`expect-label: HTTP_INPUT`. Run on every adapter change. An adapter without
fixtures does not merge.

### 2. Rule tests (finding tests)

Each rule ships annotated positive/negative cases per supported technology:

```javascript
// test: vypr.injection.sql / javascript.express+knex
app.post("/r", (req, res) => {
  knex.raw(`select * from t where id = ${req.body.id}`);  // vyql-finding: VYQL-INJ-001
  knex("t").where("id", req.body.id);                     // vyql-ok: parameterized
  const clean = validator.toInt(req.body.id);
  knex.raw(`select * from t where id = ${clean}`);        // vyql-ok: sanitized (ALLOWLIST_VALIDATION? -> no: INT coercion adapter-mapped)
});
```

The harness runs extract → adapt → evaluate and diffs against annotations.
Rule tests double as **executable documentation** and as the conformance
corpus for the sanitizer-semantics cases in
[08](08-dataflow-and-taint.md).

For non-code domains, fixtures are graph snapshots: a Terraform corpus, a
synthesized IAM environment (including PMapper/BloodHound public datasets,
[09](09-domain-cloud-identity.md)), recorded OCSF event windows.

### 3. Benchmark regression (quality gates)

Nightly: full corpus against benchmark suites (OWASP Benchmark, curated
real-world corpora, the cloud benchmark org). Tracked per rule: recall,
precision, finding churn. A release that drops a rule's benchmark precision
below its declared floor blocks.

## Review gates

| Change | Required review |
|---|---|
| New concept | ontology owners + one domain owner; standards-mapping check ([16](16-standards-alignment.md)) |
| Concept typing change | ontology owners + impact report |
| New adapter (human) | domain owner + fixtures green |
| New adapter (AI-generated) | human promotion review (18); until promoted, runs at subordinate precedence |
| New rule | domain owner + tests in ≥2 technologies (or justified single-tech `domain_specific`) |
| Severity/confidence change | domain owner; release-notes entry |
| Tenant custom rule/concept | tenant-side approval only; quarantined namespace; cannot affect Vypr-shipped findings |

## Suppression and FP workflow

- Suppressions: scoped, justified, expiring facts
  ([14](14-findings-explainability-output.md)).
- Every field FP gets a disposition: **adapter bug** (fix mapping + add
  fixture), **rule bug** (fix + add rule test), **precision limitation**
  (documented, linked to profile roadmap), or **correct-but-accepted-risk**
  (suppression). The disposition taxonomy is the content program's quality
  flywheel — FP reports without dispositions are the failure mode where
  trust erodes silently.
- Tenant overrides ([07](07-adapters-and-patterns.md) precedence tier 1) are
  the standing mechanism for "our wrapper is a sanitizer" knowledge; the
  content program mines anonymized overrides for adapter-gap signal.

## Distribution

Packs distribute through a signed registry (Vypr-published + tenant-private
channels). Engines verify signatures and manifest pins at load. CI mode pins
exact pack versions in-repo for reproducible results; Nexus mode tracks a
tenant-configured channel (stable / latest) with staged rollout and
automatic impact-report generation on channel upgrades.

## Open questions

- Cross-pack rule dependencies (composite rules consuming finding-derived
  edges, [13](13-attack-path-analysis.md)) — pack dependency semantics
  needed: probably explicit `depends.findings = ["VYQL-INJ-*"]`.
- Tenant rule sharing/marketplace — out of scope for v1; the namespace and
  signing design should not preclude it.
- Fixture licensing for real-world corpora — legal review before importing
  third-party test suites.
