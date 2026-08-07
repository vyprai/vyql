# Contributing to VyQL

The most useful contributions are **security knowledge, not Go**. If a scan
misses something your framework does, or flags something that is actually safe,
the fix is usually a binding or a rule in `vyql/`. No engine change needed.

## Before your first change

Two things catch everyone out once.

**Always use `go test -count=1`.** The Go test cache keys on source files and
ignores the `.vyql` data files, so without it a cached pass hides your change
completely and the edit looks like a no-op. `make test` handles this.

**You need `CGO_ENABLED=1`.** The parsers are C. Without cgo the build
constraints quietly exclude them and you end up with a binary that cannot parse
anything.

```sh
make build     # -> bin/
make test      # full suite, never cached
make lint      # gofmt, go vet, golangci-lint
make ci        # exactly what the pipeline runs
```

If `make ci` passes locally, CI should agree.

## Reporting a missed or wrong finding

Open an issue with a **minimal reproducer**, the smallest file that shows the
problem. Then include what these say, because they answer most of the question
before anyone else has to guess:

```sh
vyql explain ./repro     # the proof tree, including which controls it looked for
vyql match ./repro       # which concept, if any, was attached to your code
vyql resolve ./repro     # whether the call resolved at all
```

A missed finding is usually one of three things: the source or sink was never
labelled (`match` shows nothing), the call did not resolve (`resolve` lists it),
or a rule's `unless` clause was satisfied by something that should not count
(`explain` names it).

## Adding coverage

The vocabulary is in `vyql/ontology/`, what each language *means* is in
`vyql/bindings/`, and what combinations are vulnerabilities is in `vyql/packs/`.

A binding attaches a concept to a shape in the code:

```
binding requestJson {
  requires { language("python") }
  query pattern callExpr where callee.path ~= "request.json"
  emit source code.HttpInput at call.result
}
```

Every binding and rule needs a spec in `vyql/tests/`. A spec is the executable
statement of what should and should not fire:

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
```

`reject` asserts the opposite: that a rule does *not* fire on safe code. A
change that adds detection without a `reject` case for the safe form is usually
incomplete, because precision is where this class of tool actually fails.

Path matching is dotted-segment aware: `callee.path ~= "Random"` matches
`Random.secure` but not `SecureRandom`.

See [docs/07-adapters-and-patterns.md](docs/07-adapters-and-patterns.md) for the
binding language and [docs/06-ontology.md](docs/06-ontology.md) for how concepts
are typed.

## Changing the engine

Read the design series first. [docs/README.md](docs/README.md) indexes it.
[docs/03](docs/03-architecture-overview.md) is the shape of the whole thing,
[docs/08](docs/08-dataflow-and-taint.md) is the taint semantics, and
[docs/20](docs/20-extraction-frontends.md) is how a language becomes a graph.

Engine changes move benchmark numbers, so say what happened to them. The
protected suites are gated in CI and must not regress:

```sh
./benchmarks/fetch-corpora.sh
VYQL_BENCH=1 BENCH_DIR=/tmp/bench/BenchmarkJava   go test -count=1 -v ./cmd/vyql/ -run TestOWASPBenchmark
VYQL_BENCH=1 BENCH_DIR=/tmp/bench/BenchmarkPython go test -count=1 -v ./cmd/vyql/ -run TestOWASPBenchmark
```

A change that improves recall by trading away precision is not obviously an
improvement. The numbers in [benchmarks/RESULTS.md](benchmarks/RESULTS.md) are
Youden (`TPR − FPR`) for that reason.

## Pull requests

Say what changed and why, and what you measured. If you touched detection, give
before and after numbers on a suite. If you fixed a false positive, say what the
guard was that the engine failed to see.

Commits are squashed on merge, so the PR description is what lands in history.

Adding a linter to `.golangci.yml` is welcome, but only together with the fixes
it forces. A blanket exclusion hides the backlog instead of clearing it. The
currently-excluded checks are named and reasoned in that file.

## Security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## License

Contributions are under Apache-2.0, matching the project. No CLA.
