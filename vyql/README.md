# `vyql/` — VyQL content (definitions, not code)

Every hand-authored **definition is written in VyQL v2** (top-level declarations
such as `module`, `concept`, `threat`, `pattern`, `binding`, `rule`, and
`policy`) and loaded from disk at runtime — no `go:embed`. Built-in language
mechanics such as rule verbs, coverage modes, and assume traversal are
implemented in Go; shipped VyQL content must not author them. The engine resolves
this directory via `$VYQL_HOME`, or by walking up from the working directory /
the executable to find a `vyql/` containing `ontology/concepts.vyql` (see
`go/datadir`).

```
vyql/
  packs/        rule packs (rule ...) — 98 default rules across 22 packs
    auth.vyql  business.vyql  cloud.vyql  crypto.vyql  deserialization.vyql
    desktop.vyql  dos.vyql  identity.vyql  injection.vyql  lifecycle.vyql  memory.vyql
    misconfig.vyql  mobile.vyql  numeric.vyql  path.vyql  concurrency.vyql
    request_forgery.vyql  resource.vyql  runtime.vyql  sca.vyql  secrets.vyql
    smartcontract.vyql
  bindings/     framework->concept binding modules (`binding ...`) split by technology
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
```

### Definitions (VyQL) vs reference-data / config (JSON) vs engine (Go)

- **Definitions are VyQL.** Concepts, threat kinds, bindings, and rules are
  hand-authored declarations — they live here as `*.vyql`.
- **Reference data stays JSON.** The CWE/CAPEC catalogs are a MITRE
  *import* (1500+ machine-generated entries, regenerated from the official CSVs,
  not hand-written). Tunable security behavior such as confidence aggregation
  and priority bands is authored as v2 `policy` declarations.
- **The engine is Go.** The graph store, stratified evaluator + solvers, the
  type-checker, built-in language mechanics, the language parsers (tree-sitter /
  go-ast; CGO cannot be data), and the output formatters. Go supplies primitive
  predicates and execution; v2 `policy`, `binding`, and `rule` declarations
  define the shipped security semantics.

### Binding Syntax (`bindings/<tech>/.../*.vyql`)

```vyql
module bindings.python.flask;

uses patterns.python.callExpr as callExpr;

binding requestArgs {
  requires { dependency("flask") }
  query pattern callExpr where callee.path ~= "flask.request.args"
  emit source code.HttpInput at call.result
}

binding dbExecute {
  query pattern callExpr where callee.method == "execute"
  emit sink code.SqlExecution at args[0]
  fidelity: resolved
}
```

Reusable `pattern` declarations describe the frontend graph shape; `binding`
declarations attach source, sink, check, issue, fact, or propagation semantics to
matching code.

## Editing

- **Rules** — add a `rule … { }` to a `*.vyql` under `packs/`; `vyql scan` picks
  it up (or point `-rules` at a file/dir).
- **Concepts / threat kinds** — edit `ontology/concepts.vyql`
  (`concept X : kind { … }`) and `ontology/threatkinds.vyql` (`threat X { … }`).
- **Bindings** — edit `bindings/<tech>/.../*.vyql` (`binding ...`) to grow
  framework/source/sink/check coverage.
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
