# 06 — Security Ontology

Status: `DRAFT` — structure stable; the vocabulary itself is a living,
versioned artifact governed per [15](15-rule-lifecycle-governance.md).

The ontology is the most important component of VyQL. Rules are durable only
because the vocabulary they reference is stable, typed, and governed. The
ontology is a product artifact with its own release cycle, review process,
and compatibility guarantees — not a header file.

## Concept anatomy

```vyql
module code;

concept SqlExecution : sink {
  vulnerable_to: [injection.SqlInjection]
  enabled_by: [taint.UntrustedData]
  description: "Execution of a SQL statement by a database driver or ORM raw-query interface."
  cwe: [CWE_89]
  examples: ["JDBC Statement.execute", "psycopg2 cursor.execute", "knex.raw"]
  since: ontology 1.0
}
```

The **kind is a type annotation in the header** (`concept SqlExecution : sink`),
not a redundant body field — the same "say it once" rule that drops the `action`
keyword from `match`. The name is short and PascalCase inside its `module`
namespace; the qualified id is `code.SqlExecution`. Cross-module references
(`vulnerable_to`, `neutralizes`, `refines`, …) and CWE ids (`CWE_89`) are
written qualified, never bare. A dotted header (`concept code.SqlExecution : sink`)
is also accepted when no `module` is in scope.

Required: the header kind, `domain` (implied by the `module`), `description`,
`since`. Typing fields (`taint`, `vulnerable_to`, `neutralizes`, `grants`,
`holds`) depend on kind.
Standards mappings (`cwe`, `capec`, `attack`, `d3fend`, `owasp`) are required
where a sensible mapping exists ([16](16-standards-alignment.md)); absence
must be justified in review.

## Concept kinds

| Kind | Role | Typing obligations |
|---|---|---|
| `source` | origin of data/control | `taint: [TaintKind]` |
| `sink` | dangerous consumption point | `vulnerable_to: [ThreatKind]` |
| `control` | a defense | `neutralizes: [ThreatKind]`, `applies: path \| endpoint \| scope` |
| `asset` | something valuable | `holds: [AssetKind]`, sensitivity |
| `privilege` | a capability level | partial order position (see below) |
| `principal` | an acting identity class | trust level |
| `exposure` | a boundary condition | (e.g. `INTERNET`, `PUBLIC_STORAGE`) |
| `action` | business operation class | actor/resource signature |
| `state` | workflow state class | bound to `state_machine` decls |

## Taint kinds and threat kinds — the typing system

The single most consequential design decision in the ontology: **controls are
bound to the threats they neutralize.** `HTML_ESCAPE` neutralizes `XSS`; it
does not neutralize `SQL_INJECTION`. Without this binding,
`unless sanitized_by` silently accepts the wrong sanitizer — a false-negative
machine.

```
TaintKind   := UNTRUSTED_DATA | USER_IDENTITY | SECRET_VALUE | ...
ThreatKind  := SQL_INJECTION | XSS | COMMAND_INJECTION | PATH_TRAVERSAL
             | DESERIALIZATION_ABUSE | SSRF | LDAP_INJECTION | ...
```

Type checking at rule compile time:

```
taint S -> K unless sanitized_by C   is well-typed iff
  ∃ t ∈ K.vulnerable_to : t ∈ C.neutralizes
  ∧ S.taint ∩ relevant_taints(t) ≠ ∅
```

A rule pairing `HTTP_INPUT -> SQL_EXECUTION` with
`unless sanitized_by HTML_ESCAPE` is a **compile error**, with a message
naming the mismatch. This is the ontology paying rent.

The same typing check applies to `unless guarded_by C` whenever the target is a
typed sink — an `AUTHORIZATION_CHECK` (neutralizes `BROKEN_ACCESS`) cannot guard
a SQL-injection sink, because suppressing an injection finding on the basis of an
unrelated control is a false negative. Endpoint-scoped controls therefore still
carry `neutralizes`, and the legitimate `guarded_by` pairings are threat-matched
(e.g. `CSRF_PROTECTION` guarding a CSRF-vulnerable state-changing operation). The
prototype confirmed this gap and the fix (`poc/FINDINGS.md` #3).

## Core vocabulary (v1 seed)

The seed list below is the starting point, not the registry. The registry is
the versioned ontology repo; every addition goes through governance.

### Sources

`HTTP_INPUT`, `API_INPUT`, `FILE_UPLOAD`, `COOKIE`, `HTTP_HEADER`,
`MESSAGE_INPUT` (queue/stream), `CLI_ARGUMENT`, `ENV_VARIABLE`,
`DATABASE_READ` (second-order), `EXTERNAL_API_RESPONSE`,
`USER_CONTROLLED_DATA` (abstract parent).

Sources form a hierarchy: `HTTP_INPUT refines USER_CONTROLLED_DATA`. Rules
written against the parent match all refinements; rules against the child are
narrower. Refinement is single-parent in v1 (keeps reasoning and review
simple).

### Sinks

`SQL_EXECUTION`, `NOSQL_QUERY`, `COMMAND_EXECUTION`, `CODE_EVAL`,
`HTML_RENDER`, `FILE_PATH_ACCESS`, `DESERIALIZATION`, `LDAP_QUERY`,
`XPATH_QUERY`, `URL_FETCH` (SSRF), `LOG_WRITE`, `REDIRECT_TARGET`,
`TEMPLATE_RENDER`.

### Controls

`SQL_PARAMETERIZATION`, `HTML_ESCAPE`, `SHELL_ESCAPE`, `SCHEMA_VALIDATION`,
`ALLOWLIST_VALIDATION`, `AUTHENTICATION_CHECK`, `AUTHORIZATION_CHECK`,
`OWNERSHIP_CHECK`, `CSRF_PROTECTION`, `RATE_LIMIT`, `ENCRYPTION_AT_REST`,
`ENCRYPTION_IN_TRANSIT`, `NETWORK_ISOLATION`, `MFA_REQUIREMENT`,
`APPROVAL_REQUIREMENT`.

Each control declares `applies`:

- `path` — must dominate a flow witness (`sanitized_by` semantics).
- `endpoint` — guards a node (`guarded_by` semantics; attached via
  `PROTECTS`/`CHECKS` edges).
- `scope` — property of a resource/scope (encryption, MFA).

### Assets and asset kinds

Asset concepts: `DATABASE`, `OBJECT_STORE`, `SECRET_STORE`, `SOURCE_REPO`,
`PAYMENT_SYSTEM`.
Asset kinds (what they hold): `CUSTOMER_DATA`, `PII`, `PHI`, `PAYMENT_DATA`,
`CREDENTIALS`, `SOURCE_CODE`, `BUSINESS_CRITICAL`.

Asset-kind labeling comes from three places, in precedence order: explicit
customer classification (Nexus), adapter inference (e.g., column-name
heuristics, with `confidence: low`), and defaults. Rules like
`where DATABASE holds_asset_kind [PII]` are only as good as this labeling —
surfaced honestly in finding provenance.

### Privileges and principals

Privileges form a declared partial order:

```
READ < WRITE < ADMIN < SUPER_ADMIN        (per resource family)
```

Principals: `EXTERNAL_PRINCIPAL`, `AUTHENTICATED_USER`, `INTERNAL_SERVICE`,
`CI_PRINCIPAL`, `HUMAN_ADMIN`, `WORKLOAD_IDENTITY`, `ANONYMOUS`.

The privilege-closure solver consumes this order: `grant X -> ADMIN_PRIVILEGE`
matches reaching any privilege ≥ ADMIN in the relevant family
([09](09-domain-cloud-identity.md)).

### Exposures

`INTERNET`, `PUBLIC_STORAGE`, `PUBLIC_SERVICE`, `INTERNET_REACHABLE`,
`VPN_REACHABLE`, `PARTNER_REACHABLE`.

`INTERNET` is a singleton pseudo-node per tenant graph; `reach INTERNET -> X`
is the canonical exposure question.

## Hierarchies and rule matching

- `refines` (single-parent specialization) — matching is downward-closed:
  a rule over `USER_CONTROLLED_DATA` matches `HTTP_INPUT` nodes.
- `relates` (informational cross-links) — no matching semantics; used by
  explanation and AI retrieval.
- Concept aliases are supported for renames with deprecation windows
  ([15](15-rule-lifecycle-governance.md)); the compiler warns on alias use.

## Two layers: curated concepts + the full CWE/CAPEC catalog

"Encompass all CWE/CAPEC" and "keep the analysis vocabulary small" are both true,
because they live in **two layers** (implemented in `go/taxonomy/` + `go/ontology/`):

1. **The taxonomy catalog** — the *complete* MITRE CWE (969) and CAPEC (615)
   catalogs are embedded as reference data (`go/taxonomy/`, generated from the
   official CSVs by `poc/tools/gen_taxonomy.py`). Every weakness/attack-pattern
   is queryable by id with hierarchy (ChildOf) and cross-references
   (CWE↔CAPEC). This is the full taxonomy.
2. **The analysis vocabulary** — concepts (sources/sinks/controls) and a curated
   **threat-kind registry** (`ThreatKinds()`, ~60 kinds across injection, path,
   request-forgery, deserialization, access-control, authn, crypto, secrets,
   memory, concurrency, validation, DoS, supply-chain, business-logic). Each
   threat kind maps to a small set of **primary CWE ids**; its CAPEC patterns are
   **derived** from the catalog cross-references (never hand-keyed). Each concept
   carries CWE/CAPEC mappings.

`ontology.Validate(onto, catalog)` enforces the link: **every CWE/CAPEC id cited
by a concept or threat kind must resolve in the catalog, and every `vulnerable_to`
/ `neutralizes` must name a registered threat kind** (docs/16 — bad ids fail
CI). This already caught a real error (a CWE *category* id used where a
*weakness* was needed). So the analysis vocabulary stays curated and
hold-in-your-head, while the full taxonomy is always one lookup away and every
finding can roll up to its CWE/CAPEC.

## Governance summary

(Full process in [15](15-rule-lifecycle-governance.md).)

- The ontology is semver'd. **Additive** changes (new concepts, new adapters'
  labels) are minor. **Typing changes** (neutralizes/vulnerable_to edits) are
  major — they can flip findings — and require an impact report generated by
  re-running the rule corpus against benchmark graphs.
- Every concept addition requires: description, kind typing, standards
  mapping or justified absence, at least two adapter bindings *or* a
  statement of why it's adapter-pending, and an owning team.
- A concept used by zero rules and zero adapters for two minor releases is
  flagged for deprecation. Vocabulary bloat is a real failure mode; the
  ontology must stay small enough that rule authors can hold it in their
  heads (target: low hundreds of concepts, not thousands).

## Open questions

- Multi-parent refinement (a concept that is both a source and an asset
  reference) — deferred; current cases are handled by separate concepts plus
  `relates`.
- Tenant-local concept extensions: customers will want private concepts
  (e.g. `ACME_INTERNAL_SERVICE`). Proposal: allowed under a tenant namespace,
  cannot be referenced by Vypr-shipped rules, surfaced in governance reports.
- Quantitative sensitivity on assets (beyond kind labels) — belongs to the
  risk model ([17](17-risk-model.md)), not the ontology.
