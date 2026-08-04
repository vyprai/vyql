# VyQL

A multi-language security scanner that follows tainted data through your code and
tells you why each finding is a finding.

VyQL is two things: a small Go engine, and a large body of security knowledge
written as data. The engine builds one language-agnostic graph of your program
and answers questions about it. Everything it knows about frameworks, sinks,
sanitizers and vulnerability classes lives in `vyql/` as text you can read, edit
and add to without touching Go.

```
pattern  →  concept  →  binding  →  rule
```

A **pattern** is a shape in the code. A **binding** attaches a **concept**
(`code.SqlExecution`, `core.HtmlEscape`) to it. A **rule** says which
combinations of concepts are a vulnerability. Adding coverage for a new framework
is usually a new binding, not new Go.

## Install

Requires Go 1.26+ and a C toolchain (the parsers are C).

```sh
go install github.com/vyprai/vyql/cmd/vyql@latest
```

Or from source:

```sh
git clone https://github.com/vyprai/vyql
cd vyql
make build          # -> bin/vyql
```

## Scan something

```sh
vyql scan ./my-project
```

```
analysis profile: HTTP API server (api)

1 finding(s):

[P3] [HIGH] VYQL-PATH-001  (conf=medium, fp=fd2b76a631e27d16)
    source: code.HttpInput @ app.js:5   <- code.HttpInput by javascript.input@resolved
    sink: code.FilePathAccess @ app.js:6
    taint path: app.jsAttr#85 -> app.jsArg#86
    unless path coveredBy core.PathCanonicalization: not satisfied
    unless endpoint coveredBy core.PathAccessCheck: not satisfied
```

Every finding shows the source, the sink, the path between them, and **the
neutralizing controls it looked for and did not find**. If a scanner tells you
something is vulnerable, it should be able to tell you what would have made it
safe.

```sh
vyql scan --format sarif ./my-project > results.sarif   # for CI
vyql scan --format json  ./my-project | jq '.[].rule'
```

## Understand a finding

The debugging commands are the point of the design — you can interrogate the
graph rather than guess at it.

```sh
vyql explain ./my-project                    # full proof tree per finding
vyql trace -from HttpInput -to SqlExecution ./my-project
vyql match ./my-project                      # what matched which concept
vyql resolve ./my-project                    # which calls did not resolve
vyql graph ./my-project                      # dump the graph itself
```

`vyql explain` is usually the fastest way to understand why something did or did
not fire.

## Languages

Java, Python, JavaScript/TypeScript, C#, PHP, Ruby, Go, Rust, Kotlin, Scala,
Swift, Dart, Groovy, Elixir, Lua, Perl, C, C++, Objective-C, Solidity, Bash,
PowerShell.

Depth is not uniform. Java, Python and JavaScript are the reference frontends and
carry the most complete modelling; the rest range from full taint tracking to
call-and-concat coverage. `vyql definitions -kind all` reports what is actually
loaded.

## Where the knowledge lives

```
vyql/
  ontology/   concepts and threat kinds -- the vocabulary
  bindings/   what in each language means which concept
  packs/      rules: which concept combinations are vulnerabilities
  taxonomy/   CWE and CAPEC
  tests/      executable specs, one per rule
```

None of this is compiled in. The binary loads it at startup from the directory
`VYQL_HOME` names, or by finding `vyql/` above the working directory. Point
`VYQL_HOME` at your own copy and your edits take effect on the next run.

## Adding coverage

A binding says "this shape in this language is this concept":

```
binding requestJson {
  requires { language("python") }
  query pattern callExpr where callee.path ~= "request.json"
  emit source code.HttpInput at call.result
}
```

Write it, add a spec in `vyql/tests/`, run `go test -count=1 ./...`. See
[docs/07-adapters-and-patterns.md](docs/07-adapters-and-patterns.md) for the
binding language.

## Documentation

[docs/README.md](docs/README.md) is the index. The design series (`docs/03`
through `docs/20`) is the reference for how the engine works; read it before
changing the engine or the language.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Two things worth knowing before your
first change:

- **`go test` must always be `go test -count=1`.** The Go test cache keys on
  source and does not track the `.vyql` data files, so a cached pass can hide a
  change to the security knowledge base entirely.
- **`CGO_ENABLED=1` is required.** The parsers are C; without cgo the build
  constraints exclude them silently rather than failing.

`make ci` runs exactly what the pipeline runs.

## Accuracy

Measured on the public OWASP Benchmark suites, scored by Youden index
(`J = TPR − FPR`, macro-averaged over categories):

| Suite | Cases | Score |
|---|---|---|
| BenchmarkJava | 2,740 | +1.00 |
| BenchmarkPython | 1,230 | +0.90 |

Reproduce them yourself — `benchmarks/fetch-corpora.sh` fetches the corpora (they
are GPL and are not vendored here), and
[benchmarks/RESULTS.md](benchmarks/RESULTS.md) records the method, the
per-category numbers, and the known corpus defects. Scores from our synthetic
language ports are recorded separately there and are **not** comparable to these.

## License

Apache-2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — the last covers the vendored
tree-sitter grammars, the MITRE CWE/CAPEC taxonomies, and the ecosyste.ms package
snapshot, which is CC-BY-SA 4.0.
