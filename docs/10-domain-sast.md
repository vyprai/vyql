# 10 — Domain: Code Analysis (SAST)

Status: `DRAFT` (Tier 2 — ships after the cloud/identity flagship)

SAST is where VyQL's universality claim is hardest to deliver and where the
incumbents (CodeQL, Semgrep) are strongest. This document scopes a credible
path: the concept layer genuinely de-duplicates rule logic across languages,
but only if the underlying extractors and the taint solver
([08](08-dataflow-and-taint.md)) meet a real precision bar. The rule
language is not the risk; extractor quality and adapter coverage are.

> **Validated on real code, in three languages.** Prototype extractors for
> Python (CPython `ast`), JavaScript (acorn/ESTree), and Ruby (Ripper
> S-expressions) — three structurally unrelated parser frontends — each walk
> source into the *same* USG schema, and the *single unchanged* SQLi rule runs
> over all three (Flask, Express, Rails). Each finds genuine interprocedural
> cross-file vulnerabilities (Python: a flow across three files; JS/Ruby:
> controller→model) and stays clean on parameterized variants. Adding a language
> or framework was an extractor + adapter set, never a rule change. All three
> extractors use import + type resolution ([below](#call-resolution-normative)),
> which removed real false positives that bare name matching produced. Every gap
> found was a per-language extractor quirk (method-chain receivers, class/
> singleton-method bodies, AST list-wrapper recursion, source-root-relative
> module naming), never in the rule/concept layers — confirming the "extractor
> quality is the risk, not the language" thesis. See `../poc/extract/` and
> `poc/FINDINGS.md` §§"Real-repo extraction" / "Cross-language" / "Call
> resolution".

## Pipeline

```
repo → language extractor → code.* nodes + Class A edges + SSA/def-use form
     → pattern matching (tree-sitter dialect, [07])
     → adapters label sources/sinks/controls
     → taint solver summaries (per function, cached)
     → rule evaluation → SARIF
```

## Language extractors

Per-language extractors produce a normalized code model: AST, resolved
names/types where feasible, call graph with resolution confidence, SSA-form
def-use chains for the taint solver. The frontend architecture — tree-sitter
parsing → a normalized IR → a shared resolution/dataflow engine, with the parser
swappable and dependencies decoupled — is specified in
[20](20-extraction-frontends.md). Each extractor below is a *frontend* (parse +
translate to the normalized IR); resolution and dataflow are shared, not
per-language.

**v1 languages (in order):** JavaScript/TypeScript, Python, Java, Go.
**Wave 2:** C#, PHP, Ruby, Kotlin.

Build-free extraction is the default (tree-sitter + heuristic resolution);
build-aware extraction (full type info) is an upgrade path per language.
Extraction fidelity feeds label confidence ([07](07-adapters-and-patterns.md)
§fidelity) — be honest in provenance about which mode produced a finding.

**Call-graph policy:** edges carry `resolution: static|heuristic|dynamic`.
Dynamic-dispatch heuristics (duck typing, DI containers, reflection) are the
dominant source of both FNs (missed edges) and FPs (over-approximated edges);
the precision profile bounds heuristic fan-out, and adapters can declare
framework dispatch explicitly (route → handler, DI wiring) which converts
heuristic edges to `resolved` ones. This adapter-declared-dispatch mechanism
is the single highest-leverage SAST investment — it is how CodeQL's
framework models earn their keep, relocated into our adapter layer.

## Call resolution (normative)

Interprocedural edges (argument → parameter, return → call-site) connect a call
to the function it actually invokes. Resolution **must** use import and type
information, never bare function names — name-based matching over-connects on
name collisions and silently manufactures false positives (a data flow into a
safe `Foo.create` also wires into an unrelated `Bar.create` that happens to be a
sink). Required resolution order:

1. **Import resolution.** Each file has an import table mapping local names to
   targets: `import m` / `from m import f` / `const x = require('./m')` /
   `import {f} from './m'`. A module-qualified call `m.f(...)` resolves through
   that table to the function defined in module `m`; a from-imported `f(...)`
   resolves to `m.f`. Module names are computed against the **source root** (the
   sys.path / package root), which is often a subdirectory of the repo — getting
   this wrong silently breaks all cross-module resolution.
2. **Type resolution.** A method call `obj.m(...)` resolves via a per-scope type
   map: `self`/`this` inside class `C`, constructor assignments
   (`x = C(...)` → `x : C`), and class/static calls (`C.m(...)`). The receiver's
   class plus the method name selects the target. Languages without per-file
   namespacing (Ruby) resolve the receiver constant to its class directly.
3. **Guarded fallback.** Only when 1–2 cannot resolve a call, connect by name
   **iff exactly one** user function bears that name. Never connect to a set of
   same-named candidates — that is the over-connection this section forbids.

Unresolved targets are left unconnected (a bounded false negative) in preference
to over-connecting (an unbounded false-positive source). Build-aware extraction
([above](#language-extractors)) supplies full type info and raises resolution
from heuristic to `resolved`; resolution quality flows into finding confidence
([14](14-findings-explainability-output.md)). The prototype implements all three
steps for Python, JavaScript, and Ruby; on a real app this removed multiple
false positives that name-based resolution produced (see `poc/FINDINGS.md`
§"Call resolution", `poc/cases/case_16`).

## Rule pack: the cross-language injection family

The entire injection family is one rule per threat kind, shared by every
language:

```vyql
rule vypr.injection.sql {
  meta { id: "VYQL-INJ-001", severity: high, cwe: [CWE-89] }
  taint USER_CONTROLLED_DATA -> SQL_EXECUTION
  unless sanitized_by SQL_PARAMETERIZATION
}

rule vypr.injection.command {
  meta { id: "VYQL-INJ-002", severity: critical, cwe: [CWE-78] }
  taint USER_CONTROLLED_DATA -> COMMAND_EXECUTION
  unless sanitized_by SHELL_ESCAPE
  unless sanitized_by ALLOWLIST_VALIDATION
}

rule vypr.injection.xss_reflected {
  meta { id: "VYQL-INJ-005", severity: high, cwe: [CWE-79] }
  taint HTTP_INPUT -> HTML_RENDER
  unless sanitized_by HTML_ESCAPE
}

rule vypr.injection.ssrf {
  meta { id: "VYQL-INJ-008", severity: high, cwe: [CWE-918] }
  taint USER_CONTROLLED_DATA -> URL_FETCH
  unless sanitized_by ALLOWLIST_VALIDATION
}
```

What varies per language is **only adapters**: which expressions are
`HTTP_INPUT` (Express `req.body`, Flask `request.args`, Spring
`@RequestParam`), which calls are `SQL_EXECUTION` (knex.raw, cursor.execute,
JdbcTemplate), which APIs count as `SQL_PARAMETERIZATION` (prepared
statements, ORM parameter binding). The de-duplication factor is real: ~6
languages × ~10 injection rules collapses to 10 rules + per-language
adapters that are each far smaller than 10 ported rules.

## Secrets and config

Secrets detection rides the same pipeline with `match`-form rules (entropy/
pattern-labeled `SECRET_VALUE` literals) plus one flow rule that beats
regex-only scanners:

```vyql
rule vypr.secrets.hardcoded_to_exposure {
  meta { id: "VYQL-SEC-002", severity: critical }
  flow SECRET_VALUE -> [LOG_WRITE, HTTP_RESPONSE, TELEMETRY_EMIT]
}
```

## Where code joins the wider graph

This is SAST's differentiation inside Vypr — context no standalone SAST has:

- **Exposure-aware severity.** A SQLi finding in a service that
  `reach(INTERNET, service)` confirms is internet-facing outranks the same
  finding in an internal batch job. Implemented as risk modifiers
  ([17](17-risk-model.md)), driven by deployment linker edges
  ([04](04-universal-security-graph.md)).
- **Asset-aware severity.** The database the tainted query hits is a graph
  node with asset-kind labels — `holds [PII]` upgrades the finding.
- **Attack-path membership.** A code vulnerability becomes a hop in an
  attack path ([13](13-attack-path-analysis.md)): code findings export
  `code.Route`-level "compromise edges" (`EXPLOITS`) that path queries
  traverse.

```vyql
rule vypr.composite.internet_sqli_to_pii {
  meta { id: "VYQL-CMP-001", severity: critical }
  match code.Route as r
  where reach(INTERNET, r.service)
    and taint(r.inputs, SQL_EXECUTION as q) unless sanitized_by SQL_PARAMETERIZATION
    and q.database holds_asset_kind [PII]
}
```

## Quality bar and benchmarking

Tier 2 does not ship on vibes. Gates:

- **Benchmark suites:** OWASP Benchmark (Java), plus a curated real-world
  corpus per language with labeled true/false positives (built from
  disclosed CVE fix commits, the Semgrep/CodeQL public test corpora where
  licenses permit, and internal fixtures).
- **Targets (v1 SAST):** on OWASP Benchmark, ≥ CodeQL-default recall on the
  injection categories with FP rate ≤ 1.5× CodeQL-default. Honest target:
  match the incumbent on the *shared* rule families; win on cross-domain
  context, not raw analysis depth, in year one.
- **Per-adapter recall tracking:** the fixture suites double as recall
  sensors — a framework release that breaks an adapter shows up as fixture
  failures, not field FNs.

## Non-goals for SAST v1

- Path-sensitive analysis, symbolic execution, full implicit-flow tracking
  ([08](08-dataflow-and-taint.md) open questions).
- Languages without SSA-capable extractors (C/C++ deferred — memory-safety
  analysis is a different engine class).
- Autofix generation (post-v1; the witness path + control vocabulary is
  designed to make fixes derivable later).
