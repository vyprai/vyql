# `vyql/` — VyQL content (definitions, not code)

Every hand-authored **definition is written in VyQL** (docs/05 top-level
declarations: `concept`, `threat`, `adapter`, `rule`, …) and loaded from disk at
runtime — no `go:embed`. The engine resolves this directory via `$VYQL_HOME`, or
by walking up from the working directory / the executable to find a `vyql/`
containing `ontology/concepts.vyql` (see `go/datadir`).

```
vyql/
  packs/        rule packs (rule …) — the default ruleset
    injection.vyql  request_forgery.vyql  path.vyql  deserialization.vyql
    secrets.vyql  cloud.vyql  identity.vyql  sca.vyql  business.vyql  runtime.vyql  smartcontract.vyql
  adapters/     framework→concept adapters (adapter …) — one per technology
    python.vyql  javascript.vyql  ruby.vyql  go.vyql  java.vyql  php.vyql  csharp.vyql
    c.vyql  cpp.vyql  rust.vyql  bash.vyql  scala.vyql  lua.vyql  kotlin.vyql
    powershell.vyql  swift.vyql  perl.vyql  solidity.vyql  objc.vyql
  ontology/     the curated analysis vocabulary
    concepts.vyql       concept X : kind { … }  (sources/sinks/controls/assets/…)
    threatkinds.vyql    threat X { cwe: […] }   (weakness classes)
    privileges.json     the privilege partial order (config, not a definition)
  taxonomy/     MITRE reference catalogs (machine-generated, not authored)
    cwe.json            every CWE (id → name/abstraction/parents/capec/desc)
    capec.json          every CAPEC (id → name/abstraction/severity/cwes/desc)
  risk.json     factor weights + P0–P4 priority bands (tunable config, docs/17)
```

### Definitions (VyQL) vs reference-data / config (JSON) vs engine (Go)

- **Definitions are VyQL.** Concepts, threat kinds, adapters, and rules are
  hand-authored declarations — they live here as `*.vyql`.
- **Reference data + config stay JSON.** The CWE/CAPEC catalogs are a MITRE
  *import* (1500+ machine-generated entries, regenerated from the official CSVs,
  not hand-written). The risk weights/bands and privilege order are *tunable
  config*, not declarations. None are "definitions," so they remain data files.
- **The engine is Go.** The graph store, stratified evaluator + solvers, the
  type-checker, the language parsers (tree-sitter / go-ast — CGO, cannot be data),
  and the output formatters. Mechanism that *defines how VyQL evaluates* (flow-verb
  endpoint type rules, the confidence scale, the SARIF level mapping) stays Go.

### Adapter syntax (`adapters/<tech>.vyql`, docs/07)

```vyql
adapter python {
  meta { fidelity: resolved }
  source "request.form" -> code.HttpInput      // an input call/attr path → source concept
  source "request.args" -> code.HttpInput
  sink method "execute"  -> code.SqlExecution   // a call method → sink (labels the tainted arg)
  sink path "os.system"  -> code.CommandExecution
}
```

`meta { match: contains }` switches input matching from prefix to substring (used
by Go, whose receiver names vary). Collection-literal args (e.g. Rails
`where(id: x)` hash conditions) are skipped as sinks.

## Editing

- **Rules** — add a `rule … { }` to a `*.vyql` under `packs/`; `vyql scan` picks
  it up (or point `-rules` at a file/dir).
- **Concepts / threat kinds** — edit `ontology/concepts.vyql`
  (`concept X : kind { … }`) and `ontology/threatkinds.vyql` (`threat X { … }`).
- **Adapters** — edit `adapters/<tech>.vyql` (`adapter … { source/sink … }`) to
  grow framework/sink coverage.
- After any edit, `go test ./...` validates that every concept, threat-kind, and
  CWE/CAPEC id resolves and that every rule type-checks.
- **Taxonomy** catalogs are generated from the official MITRE CSVs with
  `poc/tools/gen_taxonomy.py`; don't hand-edit.

## Running

```sh
# from the repo (auto-resolves this dir):
go run ./go/cmd/vyql scan <path>

# from anywhere (installed binary):
VYQL_HOME=/path/to/vyql vyql scan <path>
```
