# 07 — Adapters and Patterns

Status: `DRAFT`

The adapter layer is where VyQL's universality claim is paid for. This
document specifies the two technology-facing layers (patterns, adapters),
their conflict/precedence model, and the content program that keeps them
honest. Read [01](01-vision-and-scope.md) §"What VyQL actually claims" first:
adapters are the relocated per-technology cost, and they are sized as a
first-class product.

## Pattern layer

### Principle: embed matchers, don't invent them

Each technology family needs a structural matching dialect. We do not invent
N grammars; we embed proven matchers behind a uniform declaration shell:

| Family | Matcher dialect | Backing |
|---|---|---|
| Source code AST | `ast` blocks | tree-sitter queries (+ language-server-grade name/type resolution where the extractor provides it) |
| JSON/YAML config (IaC, K8s, IAM) | `doc` blocks | JSONPath + CEL predicates |
| HCL (Terraform) | `doc` blocks over HCL-to-JSON projection | same |
| Structured events (runtime) | `event` blocks | OCSF field predicates |
| Graph-shape (identity, sbom) | `graph` blocks | small fixed pattern language over Class A edges |

```vyql
pattern javascript.member_call {
  match ast(javascript) {
    query: (call_expression
             function: (member_expression
               object:   @receiver
               property: @method))
  }
  export property_access(receiver, method)
}

pattern terraform.s3_public_acl {
  match doc(terraform) {
    path: resource.aws_s3_bucket[*]
    where: acl in ["public-read", "public-read-write"]
    bind bucket = @
  }
}
```

Patterns export named, typed match shapes (`property_access(receiver,
method)`) that adapters consume. Patterns contain **zero security
vocabulary** — the compiler rejects concept references inside pattern blocks.

### Pattern fidelity levels

A pattern declares what the matcher can actually see, because adapters
inherit this as a confidence ceiling:

- `syntactic` — shape only (tree-sitter without resolution).
- `resolved` — names/types resolved (extractor-dependent).
- `semantic` — backed by extractor semantic info (e.g., this call resolves to
  `pg.Client.query` through two re-exports).

`map req.body to HTTP_INPUT` at `syntactic` fidelity will also label a local
variable named `req` that isn't a request. Fidelity is recorded in label
provenance and consumable by `min_confidence` rule metadata.

## Adapter layer

### Anatomy

```vyql
adapter javascript.express {
  meta {
    version: "1.4.0"
    targets: { package: "express", versions: ">=4 <6" }
    fidelity: resolved
    provenance {
      author: "vypr.research"
      origin: human          // human | ai_generated | ai_assisted | community
      reviewed_by: ["..."]
      evidence: ["docs:expressjs.com/api", "test:express_fixtures"]
    }
  }

  requires pattern javascript.member_call
  requires pattern javascript.route_definition

  map property_access(req, "body")   to HTTP_INPUT
  map property_access(req, "query")  to HTTP_INPUT
  map property_access(req, "params") to HTTP_INPUT

  // Control binding: endpoint-scoped control attaches PROTECTS edges
  map middleware_use("helmet")       to SECURITY_HEADERS  on routes_below
  map middleware_use(authz_fn)       to AUTHORIZATION_CHECK on routes_below
}
```

Key properties:

- **Version-targeted.** Adapters declare which versions of the technology
  they describe. Framework API changes ship as adapter updates, never rule
  updates.
- **Evidence-linked.** Every mapping cites why it's believed (docs, fixture
  tests). Required for AI-generated adapters; required-by-review for human
  ones.
- **Control attachment.** Adapters are also how Class C edges
  (`PROTECTS`, `SANITIZES`, `CHECKS`) enter the graph — mapping a framework's
  defense mechanisms onto control concepts with their `applies` scope.

- **Advisory adapters** are a distinct, high-leverage adapter class: they consume
  enriched vulnerability advisories (a `VulnerableEntrypoint` — package, affected
  versions, vulnerable symbol, vuln-class, tainted argument, precondition;
  [11](11-domain-supply-chain-runtime.md)) and, where the SBOM confirms the
  affected version is present, label the resolved library call site's tainted
  argument with the sink concept implied by the vuln-class. They turn a CVE into
  a typed sink so the standard taint rules decide exploitability. They depend on
  import/type resolution to map an advisory's symbol to real call sites, and they
  are the prime target for AI generation from advisory text
  ([18](18-ai-integration.md)). Like all adapters they carry provenance and
  precedence, and AI-drafted ones run subordinate until reviewed.

- **Sink-argument precision.** A sink mapping must identify *which argument
  position* carries the dangerous value, not just "this call is a sink". Marking
  the **query position** of `cursor.execute(query, params)` (the first argument)
  — and deliberately *not* the `params` tuple — means placeholder-parameterized
  queries produce no taint path to the sink and raise zero findings, with no
  sanitizer label required. Parameterization-by-placeholder is thus handled by
  sink precision; `unless sanitized_by` remains for *explicit* escaping/
  validation on the path. The two mechanisms compose. (Validated on real Flask/
  aiohttp code; see `poc/FINDINGS.md` §"Real-repo extraction" #1.)

### Adapter tests are mandatory

An adapter ships with fixtures: minimal real inputs (code snippets, Terraform
files, IAM policies) annotated with expected labels:

```javascript
// fixture: express_body.js
app.post("/x", (req, res) => {
  const v = req.body.name;   // expect-label: HTTP_INPUT
  const w = req.headers.foo; // expect-label: HTTP_HEADER
});
```

The harness ([15](15-rule-lifecycle-governance.md)) runs extract → match →
adapt and diffs labels. An adapter without fixtures does not merge. This is
the Semgrep golden-test lesson applied one layer down.

## Conflict and precedence model

With hundreds of adapters per concept, overlap is guaranteed: two adapters
label the same node differently, or one labels what another exempts.

Resolution order (first match wins):

1. **Tenant overrides** — explicit allow/deny/relabel entries a customer
   maintains (e.g., "our wrapper `db.safeQuery` is SQL_PARAMETERIZATION").
2. **Specificity** — adapter targeting a narrower version range / more
   specific package beats a generic one (`javascript.express@>=5` beats
   `javascript.express`, which beats `javascript.http_generic`).
3. **Fidelity** — `semantic` beats `resolved` beats `syntactic`.
4. **Origin trust** — `human-reviewed` beats `ai_generated` unreviewed.
5. **Tie** — both labels applied, conflict logged to the adapter quality
   dashboard. Conflicting *control* labels (one says sanitizer, other says
   not) never tie-break silently: flagged for review, lower-confidence label
   suppressed in the interim.

All resolution decisions are recorded in label provenance — a finding's proof
tree can show "labeled HTTP_INPUT by javascript.express@1.4.0 (won over
javascript.http_generic by specificity)".

## The adapter content program

This is a product commitment, not an appendix:

- **Coverage matrix** as a tracked artifact: concepts × technologies, with
  measured coverage (which of the top-N frameworks per language have
  adapters, per concept). Gaps drive the content roadmap.
- **Telemetry-driven prioritization:** extraction can detect frameworks in
  customer code (package manifests) that have no adapter — an "unknown
  framework" report ranks the backlog by real exposure.
- **AI generation pipeline** ([18](18-ai-integration.md)): models draft
  adapters from documentation and code corpora; drafts arrive with
  `origin: ai_generated`, evidence links, and fixtures; human review promotes
  them. Confidence and precedence rules above make unreviewed AI adapters
  *usable but subordinate* — they can only add lower-trust labels, never
  override reviewed ones.
- **Community/customer contribution** path with the same gates.

## Sizing honesty

Order-of-magnitude estimate for Tier 2 code coverage: ~10 languages × ~15
frameworks-worth-covering each × (sources, sinks, controls) ≈ **300–500
adapter units**, each small (dozens of mappings) but each requiring fixtures
and review. At a sustainable pace this is a multi-quarter content program
even with AI drafting — which is why Tier 1 (cloud/identity, ~a dozen
adapters total for three providers + K8s) ships first and proves the
architecture ([19](19-roadmap.md)).

## Open questions

- **Pattern dialect for binaries/bytecode** (JVM, .NET, compiled Go) — needed
  for SCA reachability; likely a `semantic`-fidelity extractor problem more
  than a pattern problem. Deferred to SCA design.
- **Adapter composition** — can an adapter extend another (Express adapter
  reused by NestJS)? Proposal: `extends` with explicit mapping inheritance;
  needs prototyping before committing.
- **Negative mappings** — "this looks like a sink but isn't" (e.g., an ORM's
  identifier-quoting API). Currently expressible as tenant overrides only;
  probably needs first-class `exempt` mappings in adapters.
