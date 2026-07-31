# `vyql/` — VyQL content (definitions, not code)

Every hand-authored **definition is written in VyQL** (docs/05 top-level
declarations: `concept`, `threat`, `adapter`, `rule`, …) and loaded from disk at
runtime — no `go:embed`. The engine resolves this directory via `$VYQL_HOME`, or
by walking up from the working directory / the executable to find a `vyql/`
containing `ontology/concepts.vyql` (see `go/datadir`).

```
vyql/
  packs/        rule packs (rule ...) — 98 default rules across 22 packs
    auth.vyql  business.vyql  cloud.vyql  crypto.vyql  deserialization.vyql
    desktop.vyql  dos.vyql  identity.vyql  injection.vyql  lifecycle.vyql  memory.vyql
    misconfig.vyql  mobile.vyql  numeric.vyql  path.vyql  concurrency.vyql
    request_forgery.vyql  resource.vyql  runtime.vyql  sca.vyql  secrets.vyql
    smartcontract.vyql
  adapters/     framework->concept adapters (adapter ...) — 25 adapter files
    bash.vyql  c.vyql  config.vyql  cpp.vyql  csharp.vyql  dart.vyql
    elixir.vyql  go.vyql  groovy.vyql  java.vyql  javascript.vyql
    kotlin.vyql  lua.vyql  objc.vyql  perl.vyql  php.vyql  pii.vyql
    powershell.vyql  python.vyql  ruby.vyql  rust.vyql  scala.vyql
    textpattern.vyql  solidity.vyql  swift.vyql
  ontology/     the curated analysis vocabulary
    concepts.vyql       151 concepts: concept X : kind { ... }
    threatkinds.vyql    90 threat kinds: threat X { cwe: [...] }
    privileges.json     the privilege partial order (config, not a definition)
  profiles/     application threat-model profiles used by `vyql scan -profile`
  tests/        624 `.test.vyql` executable specs
  taxonomy/     MITRE reference catalogs (machine-generated, not authored)
    cwe.json            every CWE (id -> name/abstraction/parents/capec/desc)
    capec.json          every CAPEC (id -> name/abstraction/severity/cwes/desc)
  risk.json     factor weights + P0-P4 priority bands (tunable config, docs/17)
```

### Definitions (VyQL) vs reference-data / config (JSON) vs engine (Go)

- **Definitions are VyQL.** Concepts, threat kinds, adapters, and rules are
  hand-authored declarations — they live here as `*.vyql`.
- **Reference data + config stay JSON.** The CWE/CAPEC catalogs are a MITRE
  *import* (1500+ machine-generated entries, regenerated from the official CSVs,
  not hand-written). The risk weights/bands and privilege order are *tunable
  config*, not declarations. None are "definitions," so they remain data files.
- **The engine is Go.** The graph store, stratified evaluator + solvers, the
  type-checker, the language parsers (tree-sitter / go-ast; CGO cannot be data),
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
- After any edit, `cd go && go test -count=1 ./...` validates that every concept, threat-kind, and
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

## Third-party data

`taxonomy/cwe.json` and `taxonomy/capec.json` derive from the MITRE CWE and
CAPEC catalogs. See [taxonomy/ATTRIBUTION.md](taxonomy/ATTRIBUTION.md).
