# Writing a binding

A binding is the join between a language and the security vocabulary: *this shape
in this language means this concept*. Most coverage gaps are a missing binding,
not a missing rule.

Bindings are part of the definitions, which are maintained separately and take no
outside changes. This page describes how they are written, because reading a scan
means reading them, and because a gap is easier to report when you can say which
binding is missing.

They live in `bindings/<language>/`, inside a fetched data directory.

## The four kinds

```
emit source  code.HttpInput          # attacker-controlled data enters here
emit sink    code.SqlExecution       # dangerous if tainted data reaches here
emit check   core.SqlParameterization  # neutralises a threat
emit issue   code.WeakCipher         # wrong on sight, no dataflow needed
```

Rules are written against concepts, so a binding immediately participates in
every rule that mentions the concept it emits. Adding one source can light up a
dozen rules.

## A source

```
module bindings.python.myframework;

binding requestJson {
  requires { language("python") }
  query pattern callExpr where callee.path ~= "request.json"
  emit source code.HttpInput at call.result
}
```

`at` is the part worth care: it says *which node* carries the taint. For a
source that is normally `call.result`; for a sink it is the argument that must
not be tainted.

## A sink

```
binding cursorExecute {
  query pattern callExpr where callee.method == "execute"
  emit sink code.SqlExecution at args[0]
}
```

`callee.method` matches the method name regardless of receiver, which is broad on
purpose — `execute` on an unknown receiver is usually a query. Narrow it with
`callee.receiver.type` when you can.

Path matching is **dotted-segment aware**: `callee.path ~= "Random"` also matches
`Random.secure`, because `Random.` is a segment prefix — but not `SecureRandom`.
This catches people out in both directions.

## A check

A check is what stops a rule firing, so it must say *what* it neutralises and
*where* it applies:

```
binding parameterizedQuery {
  query pattern callExpr where callee.method == "execute" and args.count >= 2
  emit check core.SqlParameterization at args[0] {
    covers path { from: args[0] to: call }
  }
}
```

`covers path` means the control neutralises the flow between two points.
`covers dominates` means it guards everything after it. Getting this wrong is the
usual cause of "my sanitizer is not recognised" — the binding exists, but its
coverage does not reach the sink.

## Gating on a dependency

```
binding expressBody {
  requires {
    dependency("express", range: ">=4 <6")
    soft(import("express"))
  }
  query pattern callExpr where callee.method == "body"
  emit source code.HttpInput at call.result
}
```

`requires` keeps a binding from firing on projects that do not use the framework
— the cheapest precision there is.

## Every binding needs a spec

A spec in `tests/` states what must fire and what must not:

```
test "flask request.json reaches a SQL sink"
  lang python
  code """
    @app.route("/u")
    def u():
        name = request.json["name"]
        db.execute("SELECT * FROM users WHERE name = '" + name + "'")
  """
  expect VYQL-INJ-001

test "parameterized query is safe"
  lang python
  code """
    @app.route("/u")
    def u():
        name = request.json["name"]
        db.execute("SELECT * FROM users WHERE name = ?", (name,))
  """
  reject VYQL-INJ-001
```

**Write the `reject` case.** A binding with only an `expect` is half-tested: it
proves you can detect, not that you can tell safe from unsafe, and precision is
where this class of tool actually fails. The suite enforces that every rule has
at least one spec.

## Check your work

```sh
vyql validate-binding -file bindings/python/myframework.vyql
go test -count=1 ./...
```

`-count=1` is not optional. The Go test cache keys on source and does not track
`.vyql` files, so a cached pass will report success on a data change it never
ran.

Then confirm it does what you meant on real code:

```sh
vyql match ./some-project | grep HttpInput
vyql definitions explain code.HttpInput
```

## If it fires too widely

Run the benchmarks. A broad binding trades precision for recall, and the
Youden score in [benchmarks/RESULTS.md](../../benchmarks/RESULTS.md) is
`TPR − FPR` precisely so that trade shows up as a number rather than a
judgement call.

```sh
./benchmarks/fetch-corpora.sh
VYQL_BENCH=1 BENCH_DIR=/tmp/bench/BenchmarkPython go test -count=1 -v ./cmd/vyql/ -run TestOWASPBenchmark
```

## Reference

- [07 Adapters and patterns](../07-adapters-and-patterns.md) — the binding language
- [06 Ontology](../06-ontology.md) — concepts, threat kinds, and how they are typed
- [08 Dataflow and taint](../08-dataflow-and-taint.md) — what `covers` means to the solver
