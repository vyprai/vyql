# 10 — Domain: Code Analysis (SAST)

Status: `DRAFT` (Tier 2; the deterministic SAST slice is implemented in Go)

SAST is where VyQL's universality claim is hardest to deliver and where the
incumbents (CodeQL, Semgrep) are strongest. This document scopes a credible
path: the concept layer genuinely de-duplicates rule logic across languages,
but only if the underlying extractors and the taint solver
([08](08-dataflow-and-taint.md)) meet a real precision bar. The rule
language is not the risk; extractor quality and adapter coverage are.

> **Validated and implemented across 22 source languages.** The current Go CLI
> routes Go through `go/ast` and Python, JavaScript/TS, Ruby, Java, PHP, C#,
> C, C++, Rust, Bash, Scala, Lua, Kotlin, PowerShell, Swift, Perl, Solidity,
> Objective-C, Elixir, Dart, and Groovy through tree-sitter frontends. They all
> lower into the same NIR and shared USG/dataflow model; rules remain written
> against concepts. The original prototype proved the thesis on three unrelated
> parsers (Python `ast`, acorn/ESTree, Ruby/Ripper), where the same SQLi rule
> found real interprocedural vulnerabilities and stayed clean on parameterized
> variants. The current implementation extends that model with shared lowering,
> import/type resolution, named-value matching, SCA, config/IaC, and secrets.

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

**Current source languages:** Go, Python, JavaScript/TypeScript, Ruby, Java,
PHP, C#, C, C++, Rust, Bash, Scala, Lua, Kotlin, PowerShell, Swift, Perl,
Solidity, Objective-C, Elixir, Dart, and Groovy.

Build-free extraction is the default (tree-sitter plus shared IR resolution,
with Go using the native parser); build-aware extraction (full type info) is an
upgrade path per language.
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
([14](14-findings-explainability-output.md)). The Go lowering layer implements
this shared resolution model for the current frontends; the prototype first
proved the approach for Python, JavaScript, and Ruby and removed multiple false
positives that name-based resolution produced (see `poc/FINDINGS.md`
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
- Full symbolic memory/race proof. The current implementation includes
  exploitability-aware C/C++/ObjC memory/numeric/TOCTOU/lifecycle findings
  (tainted indexes, copy sizes, size arithmetic, potential UAF/double-free/null
  deref, file TOCTOU, and lock lifecycle), but precise alias/lifetime/range/
  interleaving proof remains a deeper engine class.
- Autofix generation (post-v1; the witness path + control vocabulary is
  designed to make fixes derivable later).
