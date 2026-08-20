# VyQL

[![ci](https://github.com/vyprai/vyql/actions/workflows/ci.yml/badge.svg)](https://github.com/vyprai/vyql/actions/workflows/ci.yml)
[![detection](https://github.com/vyprai/vyql/actions/workflows/detection.yml/badge.svg)](https://github.com/vyprai/vyql/actions/workflows/detection.yml)
[![data](https://github.com/vyprai/vyql/actions/workflows/data.yml/badge.svg)](https://github.com/vyprai/vyql/actions/workflows/data.yml)
[![security](https://github.com/vyprai/vyql/actions/workflows/security.yml/badge.svg)](https://github.com/vyprai/vyql/actions/workflows/security.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/vyprai/vyql/cmd/vyql.svg)](https://pkg.go.dev/github.com/vyprai/vyql/cmd/vyql)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A security scanner for 22 languages. It follows untrusted input through your
code, and for every finding it explains why it thinks the finding is real.

There are two parts. A small Go engine builds one graph of your program and
answers questions about it. Everything the engine knows about frameworks, sinks,
sanitizers and vulnerability classes lives in a `vyql/` data directory as plain
text you can read and edit — shipped with release installs, or fetched with
`vyql update` after `go install`.

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

The checksum comes from the same host as the archive. This catches a corrupted
download, but it does not catch a compromised release. If you need more than
that, pin `VYQL_VERSION` and compare the checksum with a second source.

Linux and macOS, amd64 and arm64. On Windows it tells you so, instead of failing
obscurely. Use WSL, or the [GitHub
Action](https://github.com/marketplace/actions/vyql-security-scan).

### Download a release manually

The scanner loads its security knowledge from a `vyql/` directory at startup. The
release archive carries both halves, so it works on a machine that has never seen
VyQL:

```sh
# platforms: linux_amd64, linux_arm64, darwin_arm64, darwin_amd64
V=v0.2.5; P=darwin_arm64
curl -fsSLO https://github.com/vyprai/vyql/releases/download/$V/vyql_${V}_${P}.tar.gz
curl -fsSLO https://github.com/vyprai/vyql/releases/download/$V/vyql_${V}_${P}.tar.gz.sha256
shasum -a 256 -c vyql_${V}_${P}.tar.gz.sha256

tar -xzf vyql_${V}_${P}.tar.gz
cd vyql_${V}_${P}
./bin/vyql scan .
```

### go install

Requires Go 1.26+ and a C toolchain (the parsers are C). This installs the
**engine only**. The knowledge base is not in the module.

```sh
go install github.com/vyprai/vyql/cmd/vyql@latest
vyql update -yes
```

`vyql update` downloads the free definitions from `dl.vyprsec.ai` into
`~/.local/share/vyql/vyql`. An interactive scan with no data directory nearby
asks before doing the same download. Without a terminal, a missing data
directory exits 1 and names `vyql update -yes`.

Use the install script instead if you want both halves in one step:

```sh
curl -fsSL https://dl.vyprsec.ai/vyql/install.sh | sh
```

Homebrew, Docker, and the GitHub release archive already include the free
definitions.

### Container

```sh
docker run --rm -v "$PWD:/work" ghcr.io/vyprai/vyql scan .
```

About 270 MB, and most of that is the security knowledge base. It runs as a
non-root user, so it does not leave root-owned files in a mounted tree. The base
is `debian:stable-slim` and not Alpine, because the parsers are C linked against
glibc.

### From source

```sh
git clone https://github.com/vyprai/vyql
cd vyql
./scripts/fetch-free-definitions.sh --with-tests ./vyql   # if ./vyql is absent
make build          # -> bin/vyql
```

CI uses the same fetch (with tests) before `go test`. The runtime free bundle
without tests is what release archives and `vyql update` install.

### As an agent skill

For Claude Code, VyQL ships as a plugin that teaches the agent to run a scan and
triage what comes back:

```
/plugin marketplace add vyprai/claude-plugins
/plugin install vyql@vypr
```

Then ask for a security scan in the normal way. If the `vyql` binary is missing,
the skill installs it, but it asks you first. A security tool should not download
and run binaries without asking.

It lives in [vyprai/claude-plugins](https://github.com/vyprai/claude-plugins)
and not here, so installing it copies 32 KB. Cloning this repository would copy
a knowledge base of several hundred megabytes.

`skills/vyql-security-scan/` there follows the [Agent
Skills](https://agentskills.io) format, which is not Claude-specific: any tool
that reads a `SKILL.md` can use it directly, without the plugin manifests.

### Check what you have

```sh
vyql version
```

```
vyql v0.2.4
commit: 6906231d71f36f0f7f93f6301870efff4ae333ad
built:  2026-08-07T01:43:38Z
go:     go1.26.4
platform: darwin/arm64
```

Quote this in a bug report, because findings depend on the version of the security
knowledge as much as on the engine.

## How you use it

The same shape whether you drive the CLI yourself or ask an agent.

```
scope  →  scan  →  coverage  →  list  →  verify  →  reproduce  →  fix
```

**Scope.** Whole repo, or just what a change introduced. These are different
questions. On a codebase that already has a backlog, scanning everything at
review time mixes the two findings your branch added into the two hundred that
were there before. For a diff, scan both sides and use `vyql diff`.

**Scan.** `vyql scan .` with no configuration. There is nothing to pick.

**Coverage.** Read the `scanned` line before the findings. A clean report over a
tree that was mostly skipped looks the same as a clean report over a tree that
was fully read. That line is the only way to tell them apart.

**List.** Everything it found, by severity, each with a location.

**Verify.** Pick one, or all the high ones. Findings are grouped by rule family
and verified one agent at a time, four families at most, because a systematic
false positive usually appears as a whole family. This is static verification: it
shows that the path holds up, not that the bug can be exploited.

**Reproduce.** Optionally, boot the app from a clean worktree and exploit that.
If it will not boot cold, a failing test instead. Local only, never the instance
you are already running.

**Fix.** Optionally, and only if you ask. The default is to name the control and
leave the edit to you.

You can stop at any point where you have your answer. A list is a complete answer to "what is wrong
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

     Scanning the whole tree. vendor/, node_modules/ and testdata/ are
     skipped already. On top of those I would skip:

       **/*_templ.go    generated templates, one huge function each
       examples/        sample code, not shipped

     Anything else to leave out, or shall I go?

you  go

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

You do not need to repeat which finding you mean, because the list is still in
the conversation. A single question also works, but the flow above is what the
skill is built for.

A reproduction runs only against your own machine, and the skill asks you before
it runs one. Writing the reproduction is the result. Whether to run it is your
decision.

The skill runs the right commands and reports coverage before findings. It also
keeps a strict meaning for a verdict. It asks you before it installs anything,
before it scans, and before it writes a reproduction.

It asks about scope because scope decides what the scan cannot find. A directory
skipped there is one that the report calls clean without having read it. It also
never shortens a list of findings without telling you. Past about 25 findings it
shows the critical and high ones, states how many of each severity it is holding
back, and offers you the rest.

`skills/vyql-security-scan/` in that repository is a plain
[SKILL.md](https://agentskills.io), which is an open format. Any agent that reads
it can follow the same flow. Claude Code is only the one that has an installer
for it.

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
in place, `explain` tells you why it did not apply here.

```sh
vyql scan -format sarif ./my-project > results.sarif
vyql scan -format json  ./my-project | jq '.[].rule'
```

### Failing a build

**`scan` exits 3 when it finds anything HIGH or CRITICAL.** If you put it in a
pipeline, it gates that pipeline, and you do not have to configure anything.

```sh
vyql scan .                        # exit 3 on HIGH or CRITICAL  (the default)
vyql scan -fail-on critical .      # exit 3 only on CRITICAL
vyql scan -fail-on none .          # report everything, always exit 0
```

Severities, lowest to highest: `info low medium high critical`. `-fail-on`
takes any of them, or `none`.

Every command reports the same four codes, so a pipeline can act on the status
alone without parsing output:

| code | meaning |
| --- | --- |
| `0` | the command run successfully |
| `1` | VyQL could not complete: bad path, unreadable file, rules that do not compile |
| `2` | usage error: unknown command or flag, missing path, a value outside its set |
| `3` | the check ran and did not pass: findings at or above `-fail-on`, a corpus that does not validate, a finding set that changed |

### Adopting it on a codebase that already has findings

A baseline records what you have already triaged, keyed on the finding
fingerprint. The fingerprint is anchored to rule and location rather than line
number, so your verdict survives edits elsewhere in the file.

```sh
vyql scan -baseline-write .vyql-baseline.json .   # take the backlog as given
vyql scan -baseline .vyql-baseline.json .         # fail only on what is new
```

**Applying a baseline lowers the gate to any new finding.** Without one, `scan`
asks "is anything in this code wrong". A severity floor is how a team decides not
to fix everything at once. With a baseline it asks "did this change add
anything", and then every addition counts: a new medium is something this branch
introduced, and not part of a backlog someone already accepted. With the normal
default, the build would pass on exactly those findings, while the report above
it listed them.

The run states this on stderr, so you do not have to work it out yourself, and it
names how to get the normal threshold back:

```
vyql: warning: baseline applied; gating on any new finding
         pass -fail-on high to keep the usual threshold, or -fail-on none to report only
```

A threshold you name always wins, so a pipeline that only wants new criticals
can ask for that:

```sh
vyql scan -baseline .vyql-baseline.json -fail-on critical .
```

Entries are written as `accepted` with an empty reason; fill them in as you
triage, and change the verdict to `false-positive` where the finding is wrong:

```json
{ "fp": "cfb54bfb4024aa90", "verdict": "false-positive",
  "reason": "source is a build-time constant, not request data",
  "rule": "VYQL-INJ-002", "loc": "server.js:5" }
```

A recording run still reports. `-baseline-write` writes the file and then prints
the findings it recorded, in whatever `-format` you asked for, so the run that
adopts the scanner can still publish its SARIF and you can see what was accepted
on your behalf:

```sh
vyql scan -baseline-write .vyql-baseline.json -format sarif . > results.sarif
```

That run does not fail the build. Everything it reported was accepted at the same
time, and failing on the backlog would make it impossible to adopt the scanner in
the pipeline that needs it. It does fail, before it prints anything, if the
baseline cannot be written.

**Rolling a baseline forward.** Give both flags, with different paths, and the
run applies the old baseline and records the next one:

```sh
vyql scan -baseline .vyql-baseline.json -baseline-write next.json .
```

This run reports and gates on what the old baseline does not cover, because that
is what is new. The file it writes carries three things: every finding the old
baseline covered, keeping its verdict and reason, so triage survives the roll;
every new finding below `-fail-on`, as `accepted`; and nothing else. A new
finding that meets `-fail-on` is left out on purpose. If it were recorded, the
next run would be green, the finding would be absorbed, and nobody would be told.
Entries in the old baseline that match no current finding are dropped, so a
rolled baseline does not keep suppressions for code that is gone.

Pointing both flags at the same file is refused. Recording writes every finding
as `accepted` with an empty reason, so it would overwrite the verdicts you
triaged. Record to a different path and diff it.

Baselined findings are kept out of both the report and the gate. Anything not in
the file is new and reported normally.

**Entries that stop matching are reported, not forgotten:**

```
warning: 4 baseline entries match nothing in this scan
         the code they excused may have changed; re-triage or remove them:
           27d5f6e6503511f5  VYQL-INJ-004  app.py:12
```

Without this, a suppression lives longer than the code it was written for: the
code moves, the
excuse stays, and nobody looks again.

A malformed baseline, an unknown verdict or a missing file is an error, and not
an empty baseline. It is better to fail with a message than to silently suppress
everything, or nothing.

### Skipping files

`-exclude` takes one pattern and may be repeated. One rule decides what a
pattern means:

```sh
vyql scan -exclude node_modules .              # that directory, at any depth
vyql scan -exclude '*_templ.go' .              # that file, at any depth
vyql scan -exclude 'src/gen/**' .              # rooted, because it has a slash
vyql scan -exclude '**/*.{test,spec}.ts' .     # brace alternation
vyql scan -exclude node_modules -exclude vendor .   # repeat for more
```

A value with no slash and no glob character names a directory. A value with no
slash but with a glob character names a file at any depth, because `*` does not
cross a slash: written literally, a bare suffix pattern would match only at the
scan root. A value that contains a slash is anchored at the scan root and matches
as written.

An excluded directory is never entered, so its files are not read and not even
listed. A malformed pattern is rejected before the scan starts, and `-coverage`
reports how much each pattern excluded.

One pattern per flag: a comma is rejected, because it would be ambiguous with a
valid glob pattern.

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
  excluded  5 file(s) and 1 director(ies) dropped by -exclude
              node_modules   1 dir(s)
              **/*_templ.go  5 file(s)
              *.min.js       0 file(s)  ← matched nothing
  oversized 2 file(s) skipped over the -max-file-size ceiling;
            raise it or pass 0 to scan them
  unread    15 file(s) matched no frontend: .zig 12, .cob 3
  depth     java, python, javascript are the reference frontends;
            other languages range down to call-and-concat coverage
  note      a parse that partially fails still counts as parsed;
            this does not yet report that
```

Source files above 2 MiB are skipped during tree walks by default. A file that
large is almost never written by hand, and parsing one costs more than the whole
rest of the tree. `-max-file-size 8MB` raises the ceiling and `0` turns it off.
Naming a file directly always scans it, whatever its size.

A clean report over a tree that was mostly skipped looks the same as a clean
report over a tree that was fully read. The warning is what separates them, and
that is why you cannot turn it off. The `note` is there because the gap is real:
tree-sitter recovers from syntax errors, so a file that parsed badly still counts
as parsed.

## Understand a finding

The diagnostic commands are why the design works this way: you ask the analysis
questions instead of guessing. Each one takes paths in the same way as `scan`, so `.` scans
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
```

**`graph`** dumps the whole graph, or taint reachability per source. Verbose, and
definitive when the others all look right.

```sh
vyql graph .
```

Two more that are useful to know:

```sh
vyql definitions -kind all                   # what concepts, rules and bindings loaded
vyql definitions explain code.SqlExecution   # which binding produced a label
vyql definitions -kind bindings -lang python  # one language's source/sink/check vocabulary
```

A filter that matches no known concept is an error, and not an empty result,
because "0 sources reach a sink" and "you typed the name wrong" must not look
the same:

```
$ vyql trace -from HttpInpt .
vyql: -from "HttpInpt" matches no concept
  did you mean: code.HttpInput, code.HttpHeader, code.HttpPersistentAuthReuse?
  list them with: vyql definitions -kind concepts
```

### Comparing two scans

**`diff`** compares two `-format json` runs by finding fingerprint. Fingerprints
are anchored to rule and location rather than line number, so the comparison
survives edits elsewhere in the file:

```sh
vyql scan -format json . > before.json
# ... change something ...
vyql scan -format json . > after.json
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

A missed finding is almost always one of three things, and `match`, `resolve` and
`explain` separate them in that order: nothing was labelled, the call did not
resolve, or an `unless` clause was satisfied.

## Every command and flag

`vyql help` lists the commands; `vyql help <command>` prints that command's
flags. This section is the same information with the reason for each one.

Four flags are shared. `-data` points at the `vyql/` data directory when it is
not where the binary would look, `-profile` picks the analysis profile, and
`-cpuprofile` / `-memprofile` write pprof files.

Every command that reads the data directory takes `-data`, including each
subcommand of `definitions`. `-profile` is on the commands that analyse source.
`diff` compares two reports and `cache` manages files on disk, so neither takes
any of the four:

```sh
vyql scan -data /opt/vyql .                  # data directory somewhere else
vyql definitions -data /opt/vyql -kind concepts
vyql scan -profile api .                     # skip auto-detection
vyql scan -cpuprofile cpu.prof -memprofile heap.prof .
```

`$VYQL_HOME`, `$VYQL_CPUPROFILE` and `$VYQL_MEMPROFILE` do the same and are the
fallback when the flag is not given.

### `scan`

| flag | default | what it does |
| --- | --- | --- |
| `-rules` | `vyql/packs` | load rules from a `.vyql` file or directory |
| `-bindings` | | a repo-local binding overlay directory |
| `-format` | `text` | `text`, `sarif`, `json` or `graph-json` |
| `-fail-on` | `high`, or any new finding with `-baseline` | exit `3` at or above this severity, or `none` |
| `-exclude` | | skip paths matching this pattern; repeatable |
| `-baseline` | | apply triaged findings, and report only what is new |
| `-baseline-write` | | record the current findings to this path |
| `-coverage` | off | what was parsed, excluded and left unread |
| `-stats` | off | graph counts, taint hubs, per-phase timing |
| `-flags` | `off` | review flags: `off`, `with` (findings and flags), `only` |
| `-flag-category` | `all` | filter review flags by category |
| `-flag-kind` | `all` | `all`, `attention`, `target` or `check` |
| `-flag-loc` | | filter review flags by location substring |
| `-cache` | `auto` | `auto`, `off`, or a directory |
| `-cache-incremental` | off | also cache per-file parses, for an edit loop |
| `-max-ram` | 80% of RAM | soft ceiling, e.g. `8GB` or `16GiB` |
| `-max-file-size` | `2MiB` | skip larger source files; `0` disables |

Combinations that are useful to know:

```sh
# CI: machine output, gated, with the coverage account on stderr
vyql scan -format sarif -fail-on high -coverage . > results.sarif

# CI on a codebase with a backlog: fail only on what this branch added
vyql scan -baseline .vyql-baseline.json -format sarif . > results.sarif

# roll the baseline forward while still gating on what it does not cover
vyql scan -baseline .vyql-baseline.json -baseline-write next.json .

# adopt: record everything, gate on nothing
vyql scan -fail-on none -baseline-write .vyql-baseline.json .

# review flags instead of findings, narrowed to one category and location
vyql scan -flags only -flag-kind attention -flag-loc handlers/ .

# findings and flags together, as one JSON document
vyql scan -flags with -format json .

# a big or slow tree: bound the memory, skip generated files, keep the cache warm
vyql scan -max-ram 8GB -exclude '**/*_templ.go' -exclude node_modules .
vyql scan -cache-incremental .               # second run after an edit is faster

# one pack, one profile, no cache: use this when a rule misbehaves
vyql scan -rules vyql/packs/injection -profile api -cache off -stats .
```

`-flags` selects the mode and the three `-flag-*` flags filter it. Setting a
filter while `-flags` is `off` is a usage error, because the filter could not
reach the output.

### `trace`

| flag | what it does |
| --- | --- |
| `-from` | only sources whose concept contains this substring |
| `-to` | only sinks whose concept contains this substring |
| `-brief` | one line per connected pair, with a hop count |
| `-count` | the number of connected pairs, and nothing else |

```sh
vyql trace .                                     # every source
vyql trace -from HttpInput -to SqlExecution .    # one question
vyql trace -to FilePathAccess .                  # every path into file access
vyql trace -from HttpInput -to SqlExecution -brief .
vyql trace -from HttpInput -count .
```

`-from` and `-to` are checked against the ontology before the scan runs, so a
typo is an error rather than a report of zero. Every mode reports how many
sources dead-ended, because a list of only the sources that reached a sink looks
the same as a clean result.

### `query`

| flag | what it does |
| --- | --- |
| `-type` | match node type substring |
| `-concept` | match concept label substring |
| `-call` | match callee path or method |
| `-loc` | match location substring |
| `-edges` | also print each match's outgoing edges |
| `-count` | print only how many matched |

```sh
vyql query -type code.Call .
vyql query -concept HttpInput .
vyql query -call db.Query .
vyql query -loc handlers.go .
vyql query -concept SqlExecution -edges .        # with outgoing edges
vyql query -concept HttpInput -count .           # just the number
vyql query -type code.Call -loc handlers/ -call exec .   # filters combine
```

Filters combine with AND. Reachability is `trace`, not `query`.

### `explain`, `match`, `resolve`, `graph`

```sh
vyql explain .
vyql explain -rules vyql/packs/injection .   # narrow to one pack or file
vyql match .
vyql resolve .
vyql graph .                                 # the whole USG, nodes and edges
```

### `definitions`

| flag | default | what it does |
| --- | --- | --- |
| `-kind` | `all` | `all`, `concepts`, `rules`, `bindings`, `reviews`, `packs` |
| `-lang` | | binding language filter |
| `-query` | | case-insensitive substring across names, patterns, packages, CWE |
| `-limit` | `80` | maximum rows per section |
| `-format` | `text` | `text` or `json` |

```sh
vyql definitions                                  # everything that loaded
vyql definitions -kind concepts                   # the concept vocabulary
vyql definitions -kind rules -query injection     # rules mentioning injection
vyql definitions -kind bindings -lang python      # one language's vocabulary
vyql definitions -kind bindings -lang go -format json
vyql definitions -kind concepts -limit 500        # raise the per-section cap
```

Subcommands:

```sh
vyql definitions search sql injection             # search every kind at once
vyql definitions explain code.SqlExecution        # which binding produced a label
vyql definitions refs core.SqlParameterization    # what references a definition
vyql definitions show-policy resultIdentity.default
vyql definitions show-mechanic ruleVerb.taint
vyql definitions validate                         # validate the loaded corpus
vyql definitions validate vyql/packs/injection    # or one path
vyql definitions validate -unstable               # report quarantined uses
vyql definitions validate-binding vyql/bindings/python/python/558.vyql
```

`validate` exits `3` when the corpus does not validate.

`refs` and `explain` take the path as `-in <path>` and not as a positional
argument, because their positional argument is the definition you are asking
about:

```sh
vyql definitions refs -in vyql/ontology/concepts core.SqlParameterization
vyql definitions explain -in vyql/bindings/python code.SqlExecution
```

### `diff`, `cache`, `update`, `version`, `help`

```sh
vyql diff before.json after.json     # two `scan -format json` outputs
vyql cache path                      # the directory this build would use
vyql cache clear                     # remove it, reporting the space freed
vyql cache clear -cache /tmp/mine    # a cache somewhere else
vyql update -check                   # compare local VERSION to dl.vyprsec.ai
vyql update -yes                     # download the free definitions bundle
vyql version
vyql help
vyql help scan
```

`diff` exits `3` when the finding set changed, so a pipeline can gate on "there
are new findings" without parsing the output.

`update -check` exits `3` when the CDN has a newer free bundle, or when none is
installed yet. `update -yes` installs without prompting into the current data
directory when one is found, otherwise into `~/.local/share/vyql/vyql`.

`cache clear` removes the directory instead of emptying it, and reports how much
space it freed. The next scan creates it again.

`scan -max-ram` puts the graph in a store under the system temporary directory,
removed when the scan ends, and also when you interrupt it. A `kill -9` cannot be
caught, so only that case leaves the directory behind. Remove it with
`rm -rf $TMPDIR/vyql-graph-*`.

## Languages

Java, Python, JavaScript/TypeScript, C#, PHP, Ruby, Go, Rust, Kotlin, Scala,
Swift, Dart, Groovy, Elixir, Lua, Perl, C, C++, Objective-C, Solidity, Bash,
PowerShell.

The depth is not the same everywhere. Java, Python and JavaScript are the
reference frontends and have the most complete modelling. The others range from
full taint tracking down to call-and-concat coverage. `vyql definitions -kind all`
reports what is actually
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

None of this is compiled into the binary. It is loaded at startup from the
directory that `$VYQL_HOME` or `-data` names, from a `vyql/` directory found
above the working directory, or beside the executable. `vyql update` installs
the free bundle under `~/.local/share/vyql/vyql`. Point `$VYQL_HOME` at your own
copy, and your edits apply on the next run.

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
vyql definitions validate-binding vyql/bindings/python/python/558.vyql
```

```json
{
  "ok": true,
  "bindings": [
    { "name": "python", "mapping_count": 1, "mappings": [ ... ] }
  ]
}
```

Then check that it attaches what you expect on real code. `match` lists what was
labelled, and `definitions explain` names the binding that did it:

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
versioning: `scan`, its `-format` values, the JSON and SARIF shapes, and the
finding fingerprint will not change incompatibly within a major version. Build
tooling against them.

**The rule and binding language is not.** It is still moving, and a future
version changes parts of the syntax. Concepts are renamed and clauses are added,
so a rule pack you write today may need edits later to keep working. The specs in
`vyql/tests/` are what tell you when something breaks.

**The knowledge base keeps changing.** A newer release can report findings that
an older one did not. That is the purpose of it, but it also means that pinning a
version is the only way to get identical output twice.

**Some documents describe design rather than behaviour.** The reference series in
[docs/](docs/README.md) also includes work that is not implemented. Those
documents say so at the top, and the index lists them separately. What a scan
actually does is what `vyql definitions -kind all` reports as loaded.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Two things to know before your
first change:

- **`go test` must always be `go test -count=1`.** The Go test cache keys on
  source and does not track the `.vyql` data files, so a cached pass can hide a
  change to the security knowledge base completely.
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
