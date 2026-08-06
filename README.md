# VyQL

[![ci](https://github.com/vyprai/vyql/actions/workflows/ci.yml/badge.svg)](https://github.com/vyprai/vyql/actions/workflows/ci.yml)
[![detection](https://github.com/vyprai/vyql/actions/workflows/detection.yml/badge.svg)](https://github.com/vyprai/vyql/actions/workflows/detection.yml)
[![data](https://github.com/vyprai/vyql/actions/workflows/data.yml/badge.svg)](https://github.com/vyprai/vyql/actions/workflows/data.yml)
[![security](https://github.com/vyprai/vyql/actions/workflows/security.yml/badge.svg)](https://github.com/vyprai/vyql/actions/workflows/security.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/vyprai/vyql/cmd/vyql.svg)](https://pkg.go.dev/github.com/vyprai/vyql/cmd/vyql)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A security scanner for 22 languages. It follows untrusted input through your
code and tells you why it thinks each finding is real.

There are two parts. A small Go engine builds one graph of your program and
answers questions about it. Everything the engine knows about frameworks, sinks,
sanitizers and vulnerability classes lives in `vyql/` as plain text you can read
and edit.

```
pattern  →  concept  →  binding  →  rule
```

A **pattern** is a shape in the code. A **binding** attaches a **concept**
(`code.SqlExecution`, `core.HtmlEscape`) to it. A **rule** says which
combinations add up to a vulnerability. To cover a new framework you usually
write a binding, not Go.

## Install

```sh
curl -fsSL https://dl.vyprsec.ai/vyql/install.sh | sh
```

Picks the right build for your platform, verifies its published SHA-256, unpacks
it under `~/.local/share/vyql`, and puts `vyql` in `~/.local/bin`. Set
`VYQL_VERSION`, `VYQL_INSTALL_DIR` or `VYQL_BIN_DIR` to change any of that.

Release assets come from the GitHub release, which is where the checksums and
build provenance live. `VYQL_INSTALL_BASE_URL` points the download at a mirror
serving the same `<base>/<version>/<asset>` layout.

The checksum is served from the same host as the archive, so it catches a
corrupted download rather than a compromised release. Pin `VYQL_VERSION` and
check the sum against a second source if you need more than that.

Linux and macOS, amd64 and arm64. On Windows it says so rather than failing
obscurely. Use WSL, or the [GitHub
Action](https://github.com/marketplace/actions/vyql-security-scan).

### Download a release manually

The scanner loads its security knowledge from a `vyql/` directory at startup. The
release archive carries both halves, so it works on a machine that has never seen
VyQL:

```sh
# platforms: linux_amd64, linux_arm64, darwin_arm64, darwin_amd64
V=v0.2.3; P=darwin_arm64
curl -fsSLO https://github.com/vyprai/vyql/releases/download/$V/vyql_${V}_${P}.tar.gz
curl -fsSLO https://github.com/vyprai/vyql/releases/download/$V/vyql_${V}_${P}.tar.gz.sha256
shasum -a 256 -c vyql_${V}_${P}.tar.gz.sha256

tar -xzf vyql_${V}_${P}.tar.gz
cd vyql_${V}_${P}
./bin/vyql scan .
```

### go install

Requires Go 1.26+ and a C toolchain (the parsers are C).

```sh
go install github.com/vyprai/vyql/cmd/vyql@latest
```

The binary finds its data in the module cache, so no further setup is needed.

### Container

```sh
docker run --rm -v "$PWD:/work" ghcr.io/vyprai/vyql scan .
```

About 270 MB, most of it the security knowledge base. Runs as a non-root user,
so it will not leave root-owned files in a mounted tree. `debian:stable-slim`
rather than Alpine: the parsers are C linked against glibc.

### From source

```sh
git clone https://github.com/vyprai/vyql
cd vyql
make build          # -> bin/vyql
```

### As an agent skill

For Claude Code, VyQL ships as a plugin that teaches the agent to run a scan and
triage what comes back:

```
/plugin marketplace add vyprai/claude-plugins
/plugin install vyql@vypr
```

Then ask for a security scan in the ordinary way. The skill installs the `vyql`
binary if it is missing, but asks first. A security tool that downloads and
runs binaries unprompted has the wrong instincts.

It lives in [vyprai/claude-plugins](https://github.com/vyprai/claude-plugins)
rather than here, so installing it copies 32 KB instead of cloning a repository
whose knowledge base is several hundred megabytes.

`skills/vyql-security-scan/` there follows the [Agent
Skills](https://agentskills.io) format, which is not Claude-specific: any tool
that reads a `SKILL.md` can use it directly, without the plugin manifests.

### Check what you have

```sh
vyql version
```

```
vyql v0.2.3
commit: 46b81d245502c975c3b4056eaae449ff33808fec
built:  2026-08-06T14:47:54Z
go:     go1.26.4
platform: darwin/arm64
```

Worth quoting in a bug report: findings depend on the version of the security
knowledge as much as on the engine.

## How you use it

The same shape whether you drive the CLI yourself or ask an agent.

```
scope  →  scan  →  coverage  →  list  →  verify  →  reproduce  →  fix
```

**Scope.** Whole repo, or just what a change introduced. These are different
questions: on a codebase with a backlog, scanning everything at review time
buries the two findings your branch added under two hundred it did not. For a
diff, scan both sides and use `vyql diff`.

**Scan.** `vyql scan .` with no configuration. There is nothing to pick.

**Coverage.** Read the `scanned` line before the findings. A clean report over a
tree that was mostly skipped looks exactly like a clean report over a tree that
was fully read, and only that line tells them apart.

**List.** Everything it found, by severity, each with a location.

**Verify.** Pick one, or all the high ones. Findings are grouped by rule family
and verified an agent at a time, four families at most, because a systematic
false positive arrives as a whole family. This is static verification: it
establishes the path holds up, not that the bug is exploitable.

**Reproduce.** Optionally, boot the app from a clean worktree and exploit that.
If it will not boot cold, a failing test instead. Local only, never the instance
you are already running.

**Fix.** Optionally, and only if you ask. The default is to name the control and
leave the edit to you.

Stop wherever you have your answer. A list is a complete answer to "what is wrong
here", and most scans end there.

### Driving it with an agent

The same flow, without remembering the commands:

```
/plugin marketplace add vyprai/claude-plugins
/plugin install vyql@vypr
```

Then it is a conversation, and each turn builds on the last:

```
you  audit this repo for security problems

     scanned python:14 javascript:3, 2 files unread (.kt)
     7 findings. 2 critical, 3 high, 2 medium.
     1. VYQL-INJ-002  critical  api/users.py:88  request body reaches a shell
     2. VYQL-PATH-001 high      api/files.py:23  query param reaches open()
     ...

you  verify the high ones

     4 families: INJ (2), PATH (3), CRY (1), CFG (1). Verifying all four,
     one agent each. Nothing deferred.

     INJ   1 real, 1 false positive
     PATH  3 false positives, all through the same startswith() guard
     CRY   1 real
     CFG   1 unresolved, needs to know whether debug mode ships

     The three PATH findings share a cause. That guard is a containment
     check VyQL does not model, so it is a binding gap, not three bugs.

you  what about the INJ one

     Real. api/users.py:88 is a request handler and the path carries the
     value with no escaping. Fix is core.ShellEscape: subprocess with a
     list rather than shell=True.

you  prove it

     Booting from a clean worktree at the scanned commit.
     POST /users/import with a payload of "; id" returns uid=0(root).
     Torn down.

you  fix it then

     One file, api/users.py, introducing subprocess with an argument list.
     Shall I?
```

You never restate which finding you mean, because the list is still in the
conversation. A single question works too, but the flow is what it is built for.

A reproduction runs against your own machine and nothing else, and the skill asks
before executing one. Writing it is the deliverable; running it is your call.

The skill runs the right commands, reports coverage before findings, and holds
the line on what a verdict means. It asks before installing anything and before
writing a reproduction.

`skills/vyql-security-scan/` in that repository is a plain
[SKILL.md](https://agentskills.io), which is an open format. Any agent that reads
it can follow the same flow; Claude Code is just the one with an installer.

## Scan something

```sh
vyql scan ./my-project
vyql scan                  # no path: scans the working directory, and says so
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
controls that would have stopped it**. If you already have one of those controls
in place, `explain` will tell you why it didn't apply here.

```sh
vyql scan --format sarif ./my-project > results.sarif
vyql scan --format json  ./my-project | jq '.[].rule'
```

### Failing a build

**`scan` exits 1 when it finds anything HIGH or CRITICAL.** Dropping it into a
pipeline gates that pipeline, with no extra configuration.

```sh
vyql scan .                        # exit 1 on HIGH or CRITICAL  (the default)
vyql scan -fail-on critical .      # exit 1 only on CRITICAL
vyql scan -fail-on none .          # report everything, always exit 0
```

Severities, lowest to highest: `info low medium high critical`. `-fail-on`
takes any of them, or `none`.

A failed scan also exits 1, so if your pipeline needs to tell "found something"
apart from "could not run", give `-exit-code` a distinct value:

```sh
vyql scan -exit-code 3 .   # 3 = findings, 1 = VyQL failed, 2 = bad usage
```

### Adopting it on a codebase that already has findings

A baseline records what you have already triaged, keyed on the finding
fingerprint. The fingerprint is anchored to rule and location rather than line
number, so your verdict survives edits elsewhere in the file.

```sh
vyql scan -baseline-write .vyql-baseline.json .   # take the backlog as given
vyql scan -baseline .vyql-baseline.json .         # fail only on what is new
```

Entries are written as `accepted` with an empty reason; fill them in as you
triage, and change the verdict to `false-positive` where the finding is wrong:

```json
{ "fp": "cfb54bfb4024aa90", "verdict": "false-positive",
  "reason": "source is a build-time constant, not request data",
  "rule": "VYQL-INJ-002", "loc": "server.js:5" }
```

Baselined findings are kept out of both the report and the gate. Anything not in
the file is new and reported normally.

**Entries that stop matching are reported, not forgotten:**

```
warning: 4 baseline entries match nothing in this scan
         the code they excused may have changed; re-triage or remove them:
           27d5f6e6503511f5  VYQL-INJ-004  app.py:12
```

Otherwise a suppression outlives the code it excused: the code moves, the
excuse stays, and nobody looks again.

A malformed baseline, an unknown verdict or a missing file is an error, not an
empty baseline. Failing loudly beats silently suppressing everything or
nothing.

### What was actually read

"No findings" only means something if you know what was read. Anything left
unanalysed gets reported whether you ask or not:

```
scanned python:1 textpattern:1 — 9 finding(s)
warning: 15 file(s) matched no frontend and were not analysed (.zig 12, .cob 3)
         run with -coverage for the breakdown
```

`-coverage` gives the full account:

```sh
vyql scan -coverage .
```

```
coverage
  parsed    python 1 · textpattern 1
  excluded  5 file(s) dropped by -exclude
  unread    15 file(s) matched no frontend: .zig 12, .cob 3
  depth     java, python, javascript are the reference frontends;
            other languages range down to call-and-concat coverage
  note      a parse that partially fails still counts as parsed;
            this does not yet report that
```

A clean report over a tree that was mostly skipped reads exactly like a clean
report over a tree that was fully read. The warning is the difference, which is
why it is not optional. The `note` is there because the gap is real: tree-sitter
recovers from syntax errors, so a file that parsed badly still counts as parsed.

## Understand a finding

The diagnostic commands are the point of the design: you interrogate the analysis
instead of guessing at it. Every one takes paths just as `scan` does, so `.` scans
the current directory.

**`explain`** prints each finding's full proof tree, including the negation evidence:
every `unless` clause the rule carries and whether it was satisfied. Usually the
fastest answer to "why did this fire".

```sh
vyql explain .
vyql explain -rules vyql/packs/injection .   # narrow to one pack or file
```

**`match`** lists every node a binding attached a concept to. If your source or sink
is not listed, no rule can fire, because rules match concepts.

```sh
vyql match .
```

**`resolve`** shows which calls resolved to a body and which did not. Taint stops at
an unresolved call, so this is where a missing cross-function flow shows up.

```sh
vyql resolve .
```

**`trace`** follows taint from source to sink, or shows where it stops. Both
filters match on a substring of the concept name.

```sh
vyql trace .
vyql trace -from HttpInput -to SqlExecution .
vyql trace -to FilePathAccess .              # every path into file access
```

**`query`** searches the graph by predicate, for when you want to look rather than be
told.

```sh
vyql query -type code.Call .                 # by node type
vyql query -concept HttpInput .              # by concept label
vyql query -call db.Query .                  # by callee path or method
vyql query -loc handlers.go .                # by location substring
vyql query -concept SqlExecution -edges .    # include outgoing edges
vyql query -concept HttpInput -count .       # just how many
vyql query -from HttpInput -to SqlExecution .  # reachability between concepts
```

**`graph`** dumps the whole graph, or taint reachability per source. Verbose, and
definitive when the others all look right.

```sh
vyql graph .
vyql graph -taint .
```

Two more worth knowing:

```sh
vyql definitions -kind all                   # what concepts, rules and bindings loaded
vyql definitions explain code.SqlExecution   # which binding produced a label
vyql bindings -lang python                   # one language's source/sink/check vocabulary
```

A filter that matches no known concept is an error rather than an empty result,
because "0 sources reach a sink" and "you typed the name wrong" should not look
the same:

```
$ vyql trace -from HttpInpt .
vyql: -from "HttpInpt" matches no concept
  did you mean: code.HttpInput, code.HttpHeader, code.HttpPersistentAuthReuse?
  list them with: vyql definitions -kind concepts
```

### Comparing two scans

**`diff`** compares two `--format json` runs by finding fingerprint. Fingerprints
are anchored to rule and location rather than line number, so the comparison
survives edits elsewhere in the file:

```sh
vyql scan --format json . > before.json
# ... change something ...
vyql scan --format json . > after.json
vyql diff before.json after.json
```

```
before: 9 findings   after: 7 findings
- removed: 2   + added: 0   (= 7 unchanged)
  - [VYQL-INJ-004] app.py:18 → app.py:19
  - [VYQL-INJ-202]  → app.py:19
```

This is how to ask "did this branch introduce anything new" without failing on a
backlog that was already there.

A missed finding is nearly always one of three things, and `match`, `resolve` and
`explain` distinguish them in that order: nothing was labelled, the call did not
resolve, or an `unless` clause was satisfied.

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

Check a binding file parses, and what it emits, without running a scan. Bindings
live under `vyql/bindings/<language>/`, one module per file:

```sh
vyql validate-binding -file vyql/bindings/python/python/558.vyql
```

```json
{
  "ok": true,
  "bindings": [
    { "name": "python", "mapping_count": 1, "mappings": [ ... ] }
  ]
}
```

Then confirm it attaches what you expect on real code. `match` lists what was
labelled, and `definitions explain` names the binding responsible:

```sh
vyql match ./some-project
vyql definitions explain code.HttpInput
```

## Documentation

[docs/README.md](docs/README.md) is the index. The design series (`docs/03`
through `docs/20`) is the reference for how the engine works; read it before
changing the engine or the language.

## Stability

**The CLI is stable.** Commands, flags and output formats follow semantic
versioning: `scan`, its `--format` values, the JSON and SARIF shapes, and the
finding fingerprint will not change incompatibly within a major version. Build
tooling against them.

**The rule and binding language is not.** It is still moving, and a future
version changes parts of the syntax. Concepts get renamed and clauses get added,
so a rule pack written today may need edits to keep working. The specs in
`vyql/tests/` are what tell you when something breaks.

**The knowledge base evolves.** A newer release can report findings an older one
did not -- that is the point of it -- but it means pinning a version is the only
way to get identical output twice.

**Some documents describe design rather than behaviour.** The reference series in
[docs/](docs/README.md) includes work that is not implemented; those documents say
so at the top, and the index lists them separately. What a scan actually does is
whatever `vyql definitions -kind all` reports as loaded.

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

Run them yourself: `benchmarks/fetch-corpora.sh` pulls the corpora, which are
GPL and not vendored here. [benchmarks/RESULTS.md](benchmarks/RESULTS.md) has the
method, per-category numbers and known corpus defects. Scores from our own
language ports live there too, and are **not** comparable to these.

## License

Apache-2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The last one covers the vendored
tree-sitter grammars, the MITRE CWE/CAPEC taxonomies, and the ecosyste.ms package
snapshot, which is CC-BY-SA 4.0.
