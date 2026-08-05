# Working in this repository

Notes for coding agents. Humans should read [CONTRIBUTING.md](CONTRIBUTING.md) —
this covers the same ground plus the traps that cost real time here.

## What this is

A Go engine plus a large body of security knowledge stored as data.

- `cmd/` — the binaries; `internal/` — the engine (`engine`, `extract`, `parser`,
  `solvers`, `usg` and the rest). Everything outside `cmd/` is internal on
  purpose: the CLI is the supported interface, so the Go packages stay free to
  change.
- `vyql/` — the knowledge: `ontology/` (concepts), `bindings/` (what each
  language means), `packs/` (rules), `tests/` (specs), `taxonomy/` (CWE/CAPEC)
- `docs/` — the design series; `docs/README.md` indexes it
- `benchmarks/` — the measured record

`pattern → concept → binding → rule`. Most coverage work is a new binding, not
new Go. Reach for a Go change only after `vyql match` shows the concept is
genuinely unreachable from the data.

## Three rules that are not preferences

**`go test -count=1`, always.** The Go test cache keys on source files and does
not track `.vyql` data. Without `-count=1`, a cached pass hides a change to the
knowledge base entirely — your edit looks like a no-op and the suite agrees. A
bare `go test` in this repository is a bug.

**`CGO_ENABLED=1`.** The parsers are C. `CGO_ENABLED=0` fails outright, which is
the good case; do not "fix" it by disabling cgo.

**Never claim a detection change without a benchmark number.** Recall and
precision trade against each other, and a change that improves one while
silently destroying the other looks like progress in a unit test.

```sh
make build      # -> bin/
make test       # full suite, never cached
make lint       # gofmt, go vet, golangci-lint
make ci         # exactly what the pipeline runs
```

## Diagnose before you change anything

Four commands answer nearly every "why did it do that", and in this order:

```sh
vyql match ./repro      # was anything labelled? if not, no rule can fire
vyql resolve ./repro    # did the call resolve? taint stops at unresolved calls
vyql trace -from X -to Y ./repro   # where does the path actually stop?
vyql explain ./repro    # the proof tree, and which `unless` suppressed it
```

A missed finding is almost always one of: nothing was labelled (missing binding),
the call did not resolve, or an `unless` clause was satisfied. Reading rule files
to guess which is slower than running these.

See [docs/guides/debugging-findings.md](docs/guides/debugging-findings.md).

## Changing detection

Add a binding in `vyql/bindings/<lang>/`, then a spec in `vyql/tests/` with both
an `expect` **and** a `reject` for the safe form. A spec with only `expect`
proves you can detect, not that you can tell safe from unsafe — and precision is
where this class of tool actually fails.

Then measure:

```sh
./benchmarks/fetch-corpora.sh
VYQL_BENCH=1 BENCH_DIR=/tmp/bench/BenchmarkJava   go test -count=1 -v ./cmd/vyql/ -run TestOWASPBenchmark
VYQL_BENCH=1 BENCH_DIR=/tmp/bench/BenchmarkPython go test -count=1 -v ./cmd/vyql/ -run TestOWASPBenchmark
```

Both are gated in CI and must not regress. Current: **+1.00** and **+0.90**,
Youden (`TPR − FPR`) macro-averaged. `benchmarks/RESULTS.md` has the method.

## Traps

- **Path matching is dotted-segment aware.** `callee.path ~= "Random"` also
  matches `Random.secure`, but not `SecureRandom`.
- **A score is meaningless without its corpus.** Scores from the synthetic
  language ports are not comparable to the public OWASP suites. Conflating them
  has been the single largest source of confusion here.
- **Loading zero of something looks like success.** A glob that stops matching
  reports a clean run over nothing. `vyql definitions -kind all` should report
  concepts and rules in the hundreds and bindings in the tens of thousands. If a
  count is near zero the data directory is wrong, and every scan is silently
  under-reporting rather than failing.
- **Inline control calls inside a concatenation sometimes fail to neutralise.**
  If `sink("..." + esc(p))` still fires, try `clean = esc(p); sink("..." + clean)`.
  If that fixes it, the binding's `covers` is what needs changing.
- **`vyql/` is both a directory and the binary's name.** Binaries build to
  `bin/`; they cannot sit at the repository root.

## Before you say it works

Run the command and read the output. In this repository specifically:

- a rename that matches nothing looks exactly like a rename that worked — check
  the linter, not just the build
- `make ci` green locally is the bar; CI should then agree
- if you touched detection, quote the before and after numbers
