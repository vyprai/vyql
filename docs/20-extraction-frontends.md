# 20 — Extraction Frontends, Resolution, and Dependencies

Status: `DRAFT` — architecture proposed in the prototype and now implemented in
the Go CLI for 22 source languages; higher-precision resolution-tier choices per
language remain open and are listed at the end.

This document answers a recurring question — "tree-sitter or a different parser
per language?" — and specifies how source becomes the `code.*` subgraph
([04](04-universal-security-graph.md)) with import/type resolution and how that
connects to dependency/SBOM data ([11](11-domain-supply-chain-runtime.md)).

## The reframe: parsing ≠ resolution ≠ coherence

"Parser choice" conflates three independent concerns. Decide each separately:

1. **Parsing** — syntax → a tree.
2. **Resolution** — names, types, imports → a semantic model.
3. **Coherence** — one representation the rule/adapter layers can target.

The PoC settled the central confusion empirically: four structurally unrelated
parsers — CPython `ast` (Python objects), acorn (ESTree JSON), Ripper (Lisp
S-expressions), and tree-sitter (CST) — all fed the **same** rule, because
coherence is engineered in a **normalized IR**, not inherited from any parser.
The current Go implementation extends this to Go plus 21 tree-sitter source
frontends. Import/type/dataflow resolution is built once *on top* of NIR — no
parser provides it. Conclusion: choose the parser for parsing qualities;
build/skin resolution separately; create coherence in your own IR.

## The layered architecture

```
 source files
     │
     ▼
┌──────────────────────────────────────────────────────────────┐
│ FRONTEND (per language, thin)                                │
│   parse with tree-sitter (default) → translate CST to NIR     │
└───────────────┬──────────────────────────────────────────────┘
                ▼
┌──────────────────────────────────────────────────────────────┐
│ NORMALIZED IR (NIR)  ← coherence lives HERE                   │
│   small, semantic-shaped node set; identical across languages │
└───────────────┬──────────────────────────────────────────────┘
                ▼
┌──────────────────────────────────────────────────────────────┐
│ LOWERING (shared, language-agnostic)                         │
│   dataflow construction + import/type call resolution         │
│   → code.* nodes + FLOWS/CALLS edges in the USG               │
└───────────────┬──────────────────────────────────────────────┘
                ▼   (concept labels via adapters, then rules)
        Universal Security Graph
```

Adding a language = one **frontend** (parse + translate to NIR) plus adapter
content. Resolution, dataflow, and rules are untouched. Swapping a parser
(tree-sitter → native → LSP) = swapping a frontend; everything downstream is
unchanged. The PoC proved this on three languages and parser-swap parity
(`poc/cases/case_17`); the Go implementation now applies the same architecture
across the current 22-language source set.

### Tier 1 — Parsing: tree-sitter by default

| Property | Why it wins here |
|---|---|
| Uniform node API across 100+ languages | one integration; fast language onboarding |
| Error recovery | scans real/un-buildable/partial repos at scale (build-free default, [10](10-domain-sast.md)) |
| Incremental | re-parse on edit — serves PR-time and the incrementality goal ([04](04-universal-security-graph.md)) |
| One C library + grammars | avoids a polyglot scanner (node + JVM + .NET + ruby runtimes) |

Tree-sitter is a *parser*, not a semantic analyzer: it gives a CST, **not**
resolved names, types, or import-to-file edges. Its node *types* still differ
per grammar (`call` vs `call_expression` vs `method_add_arg`) — so it provides
*mechanical* coherence (one API), never *semantic* coherence. Semantic coherence
is the NIR's job.

Native frontends (TypeScript compiler, Roslyn, JDT, go/types, Ripper) are the
opposite: rich semantics, but each a silo with its own AST and runtime. Use them
as a **resolution-tier upgrade** (below), not as the default parser.

### Tier 2 — Normalized IR (NIR): where coherence is engineered

NIR is **semantic-shaped, not syntax-shaped**: it carries exactly what dataflow
and resolution need (modules, imports, func/class defs, assignments, calls with
receiver/args, taint-propagating string builds) and nothing language-specific.
Each frontend translates its parse tree into NIR; the rest of the system only
ever sees NIR. This is the single most important layer for the "AST node
coherence" requirement — and it is small (the PoC's NIR is ~25 node kinds).

### Tier 3 — Resolution: a distinct, pluggable tier

Resolution (imports, scopes, types, call targets) is **not** bundled with the
parser. Three escalating options, chosen per language/precision need:

1. **Build-free resolvers on the IR (default).** Import tables, scope maps, and
   light type resolution computed over NIR — what the PoC implements for all
   languages, and what docs/10 §"Call resolution" specifies (import → type →
   guarded unique-name fallback). Or **tree-sitter-stack-graphs** (GitHub's
   name-binding framework on tree-sitter) for a more reusable mechanism. This is
   the right ceiling for dynamic languages (Python/Ruby/JS), where no static
   type system exists anyway.
2. **Build-aware via native frontends / SCIP (high precision).** Consume **SCIP**
   indexes (Sourcegraph's successor to LSIF) produced by per-language indexers
   (`scip-java`, `scip-typescript`, `scip-python`, `scip-ruby`). These wrap the
   native compiler (real types, real module resolution) but emit a **uniform
   symbol schema** — so you get correct resolution for statically-typed
   languages **without integrating N native ASTs**. Reserve for languages where
   type-driven dispatch is essential (Java interfaces, C# overloads, TS
   structural types).
3. **LSP servers** for live go-to-def / find-refs when a standing index isn't
   wanted.

The resolution *contract* is the same regardless of tier: produce
import-resolved, type-resolved interprocedural `CALLS` edges; resolution quality
sets edge confidence ([14](14-findings-explainability-output.md)). Unresolved
targets are left **unconnected** (a bounded false negative) rather than
over-connected (an unbounded false-positive source) — see docs/10 and the
measured FP removal in `poc/cases/case_16`.

### The precision ceiling is language-dependent

State it plainly: statically-typed languages (Java, C#, Go, TS) get
high-precision resolution cheaply from their frontends → use SCIP/native.
Dynamic languages (Python, Ruby, plain JS) have a low ceiling regardless → the
build-free IR resolvers are close to the practical best without running the
code, and that is an accepted SAST reality.

## Dependencies are a separate axis — decouple them

Dependency resolution is **not** an AST problem and must not live in the code
extractor:

- **Package dependencies** come from manifests/lockfiles (`package-lock.json`,
  `poetry.lock`, `go.mod`, `pom.xml`, `Gemfile.lock`) parsed by dedicated readers
  or off-the-shelf SBOM tooling (Syft, cdxgen), producing the `sbom.*` subgraph
  ([11](11-domain-supply-chain-runtime.md)).
- **The link** between code and dependencies is made by the import resolver:
  an import (`import requests`, `require('lodash')`) resolves to a package node,
  emitting a `code.Import → sbom.PackageVersion` edge.
- **Reachability-gated SCA** (the headline SCA value, VYQL-SCA-002) is then a
  cross-domain join: a vulnerable `sbom.PackageVersion` **whose symbols are
  actually called** in resolved code. This needs the same call graph the SAST
  taint solver uses — which is exactly why resolution must be import/type-aware,
  not name-based. The PoC demonstrates this end to end (`poc/extract/sbom.py`,
  `poc/cases/case_18`): a vulnerable-and-called dependency is a finding; a
  vulnerable-but-unused one is not.

So the dependency story reuses two things the frontend/resolution tiers already
produce — the import table and the call graph — and adds a manifest parser.
Nothing about it belongs in the parser choice.

## Recommendation (summary)

- **Parse** with tree-sitter by default (uniform, build-free, robust, broad).
- **Normalize** into NIR — this is where coherence lives; keep it small and
  semantic-shaped.
- **Resolve** in a separate tier: build-free IR resolvers / stack-graphs by
  default; SCIP/native for precision-critical (statically-typed) languages;
  resolution quality drives confidence.
- **Depend**: a separate manifest/SBOM path, linked to code via the import
  resolver — never inside the AST extractor.

This matches the design's existing "build-free default, build-aware upgrade"
stance ([10](10-domain-sast.md)) and the layer boundaries ([03](03-architecture-overview.md)):
the parser is replaceable; the normalization and resolution layers are where the
durable, reusable engineering concentrates.

## Open questions

- **Which languages should graduate to SCIP/native?** Leading candidates: Java
  and TypeScript (type-driven dispatch, mature indexers). Python/Ruby/JS stay on
  build-free resolvers initially.
- **tree-sitter-stack-graphs vs hand-rolled resolvers** as the default
  build-free mechanism — stack-graphs is more reusable but a larger upfront
  investment; benchmark name-resolution recall before committing.
- **NIR stability/versioning** — NIR is now an internal contract between
  frontends and lowering; it needs the same governance as the ontology
  ([15](15-rule-lifecycle-governance.md)) once multiple frontends depend on it.
- **Binary/bytecode frontends** (JVM, .NET, compiled Go) for SCA reachability —
  not tree-sitter-shaped; likely native (ASM/Cecil) frontends emitting NIR.
