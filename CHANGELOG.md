# Changelog

Notable changes to VyQL. The format follows [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html).

New rules and bindings change what a scan reports, so they get listed here like
any other user-visible change. A finding that suddenly appears in your CI is a
behaviour change, even if no code moved.

## [Unreleased]

## [0.4.0] - 2026-08-24

### Added

- **`vyql update`.** Checks the free definitions channel on `dl.vyprsec.ai`,
  reports with `-check`, and installs with confirmation or `-yes` into the
  current data directory or `~/.local/share/vyql/vyql`.
- **Interactive install when the data directory is missing.** On a terminal, a
  command that needs packs asks before downloading the free bundle. Without a
  terminal it exits 1 and names `vyql update -yes`.

### Changed

- **`go install` is the engine only.** Install with `install.sh`, run
  `vyql update -yes` after `go install`, or use Homebrew / Docker / a release
  archive.
- **`-data` pins the data directory via `datadir.Set`.** The flag no longer sets
  `$VYQL_HOME`. `$VYQL_HOME` remains for tools that cannot pass `-data` (notably
  `go test`).
- **CI fetches definitions into `$RUNNER_TEMP`**, moves any checked-in `vyql/`
  aside, runs CLI commands with `-data`, and points `go test` at the same tree
  through `$VYQL_HOME`.
- **`vyql update` compares semver** (`NeedsUpdate`) rather than string equality,
  so `1.0.0` vs `1.0.1` is detected.
- **Definition downloads use `dl.vyprsec.ai` only**, with retries and
  `Cache-Control: no-cache` when the CDN has not yet served a new object.

### Fixed

- **A release archive carries its definitions again.** The script that packs the
  free bundle unpacks from a temporary working directory, so a relative
  destination was written there and deleted with it. The caller got no data
  directory, and the check meant to catch that passed, because it was relative
  to the same wrong place. Both callers that pass a relative path were affected:
  the release archive, whose binary then reported "could not locate the data
  directory" on every platform, and `make fetch-definitions`, which silently
  fetched nothing. The destination is resolved before anything changes
  directory.

- **`--max-ram` is a hard limit on memory use.** It named a figure and then
  used a multiple of it: on a repository of 11,000 C files, `-max-ram 8GB`
  reached 24 GB of resident memory in 30 minutes and had not finished. Three
  things caused that, and all three are fixed.

  The budget was spent more than once. Half of it funded badger's block cache
  and a quarter the node-detail buffer, while the heap ceiling was set to half,
  and badger's block cache is ordinary Go heap, so the caches alone could reach
  the ceiling before a single node was stored. The collector then ran
  continuously against memory it was not allowed to release. The budget is now
  partitioned so that the pools fit inside the ceiling with room left for the
  graph: the block cache takes a sixteenth and at most half a gigabyte, the
  detail buffer a quarter, and the heap ceiling is the figure itself, less a
  reserve for tree-sitter's C parse trees and badger's mapped tables, which the
  Go runtime does not account for.

  The graph store went to `$TMPDIR`. On a systemd distribution `/tmp` is a
  tmpfs, so the mode whose whole purpose is to move the graph out of RAM wrote
  it back into RAM, and then paid the encode and write cost for nothing. The
  store now lives beside the scan cache, under the user cache directory, and a
  store that still lands on a memory filesystem is reported rather than
  silently accepted. A `kill -9` still leaves one behind, so a scan also removes
  any store there that has not been written to for a day.

  Nothing stopped a scan that outgrew the figure anyway. The graph a scan builds
  is live memory, so a heap ceiling cannot release it; a large enough tree grows
  past any ceiling and is killed by the kernel: no diagnostic, no exit status,
  a truncated report on stdout, and an OOM killer free to choose a different
  process as its victim. A scan now watches its own resident size and stops at
  the ceiling with a message naming what to do instead, exiting 1. What it
  watches is the memory the kernel cannot take back, meaning anonymous and
  shared pages, because mapped files are dropped under pressure rather than
  killed for. Without `--max-ram` the same watch guards what the machine or the
  cgroup allows, less a margin.

  A scan that needs more than the figure now fails instead of finishing over
  budget. On a large JavaScript monorepo, `-max-ram 2GB` took 9 min 43 s and
  peaked at 3.1 GB before returning findings; it now stops after 26 seconds and
  says the ceiling is too small for that tree.

- **The default ceiling reads the cgroup, not just the host.** `GOMEMLIMIT`
  defaulted to 80% of the host's physical memory. A scan in a container or a
  systemd unit capped well below that budgeted against memory it could never
  have. On a 4 GiB container on a 128 GiB host, that budget was 102 GiB. The
  smaller of the two figures is now used, on both cgroup v1 and v2.

## [0.3.1] - 2026-08-13

### Fixed

- **`-data` selects the data directory.** It parsed and set `$VYQL_HOME`, but
  every command that also takes `-profile` had already resolved the directory by
  then: naming the available profiles means loading them, and that happens while
  the flags are being registered. `scan`, `trace`, `explain`, `match`, `resolve`,
  `query` and `graph` were all affected, so pointing any of them at a different
  `vyql/` had no effect. `$VYQL_HOME` was the only way to select one.
- **`-h` works with no data directory.** The same ordering made a command fail
  before it read `-data`, which is the flag that says where the data is. Asking
  a fresh install how to run it now answers.
- **Each `definitions` subcommand takes `-data`.** `search`, `refs`,
  `show-policy`, `show-mechanic`, `validate`, `validate-binding` and `explain`
  all read the data directory and all rejected the flag as unknown.
- **`definitions` fails on a data directory holding nothing.** It reported
  `concepts=0 rules=0 bindings=0 reviews=0` and exited 0, which is the shape of a
  successful load of an empty knowledge base. A scan against the same directory
  finds nothing and passes its gate.
- **`-flag-category` rejects a category no review declares.** A mistyped
  category reported no flags and exited 0, which reads as a clean result.
  `-flag-kind` beside it has always rejected unknown values.
- **`vyql diff -h` exits 0** and prints on stdout, like every other command. It
  read its arguments directly, so `-h` was treated as a filename.

### Changed

- **Go decoding into a typed struct is no longer unsafe deserialization.**
  `json.Unmarshal` and `yaml.Unmarshal` are not sinks for `code.Deserialization`.
  CWE-502 describes decoding that can instantiate attacker-chosen types or run
  code while decoding; Go decodes into a caller-declared type, so no input makes
  it that. **`VYQL-DESER-001` will report far less on Go.**
- **Go recognises safe deserialization.** Nothing in the language emitted
  `core.SafeDeserialization`, so the `unless` clause of `VYQL-DESER-001` could
  not be satisfied by any code a user writes, and the remaining package sinks
  were unclearable rather than merely noisy.
- **A websocket connection is no longer attacker-controlled input.** The source
  is `ReadMessage`, `ReadJSON` and `NextReader` rather than `Upgrade`. Labelling
  the handle spread the label to every value derived from the connection.
- **A dependency finding names its advisory and why it matched.** It reported
  the package alone, so three different questions — is this release named, is the
  pin below the first fixed version, does the declared range permit versions
  nobody vetted — all read the same.

### Removed

- **The `requests` advisory describing HTTPie's pin.** It recorded that HTTPie
  had to cap requests at 2.31.0, but was filed under `requests`, so it fired on
  any project permitting a later release. No advisory of ours now covers
  `requests`.

## [0.3.0] - 2026-08-12

### Changed

- **Exit codes are one contract across every command.** `0` the command run successfully,
  `1` VyQL could not complete, `2` the invocation cannot mean anything, `3` the
  check ran and did not pass. `scan` gates at `3` rather than `1`, so "this code
  has findings" and "the scanner could not run" are no longer the same status.
  **A pipeline branching on exit 1 to mean "findings" needs updating.**
- **`-exclude` takes glob patterns and is repeatable.** A bare name still means
  that directory at any depth, so existing single-value invocations are
  unchanged. `*_templ.go` and `**/*.{test,spec}.ts` now work, and excluded
  directories are pruned during the walk rather than filtered afterwards.
  **Comma-separated lists are rejected**; repeat the flag instead, because a
  comma would be ambiguous with a valid glob pattern.
- **Applying `-baseline` gates on any new finding** unless `-fail-on` is given.
  A baseline asks "did this change add anything", where every addition counts;
  the plain `high` default passed the build on every new finding below it while
  the report listed them. An explicit `-fail-on` still wins.
- **stdout carries exactly one document.** `-stats` and `-coverage` go to
  stderr, so `scan -format sarif -coverage . > results.sarif` writes SARIF
  rather than SARIF followed by text no parser accepts.
- **`-h`, `--help` and `help` exit 0** and print on stdout. `-v` is `--version`.
- `-all` becomes `-flags with`; `-binding-overlay` becomes `-bindings`;
  `-incremental-cache` becomes `-cache-incremental`; `definitions -max` becomes
  `-limit`. An unrecognised `-format` or `-profile` is a usage error rather than
  a silent fallback.
- `-data`, `-cpuprofile` and `-memprofile` are flags; their environment
  variables remain as fallbacks. `-stats=rule,binding,sink` replaces the five
  `VYQL_*_TIMING` variables.

### Removed

- **`-exit-code`.** It existed to work around the gate sharing code `1` with a
  failed run, which code `3` settles.
- **`query -from/-to` and `graph -taint`.** Both are `vyql trace`, which reports
  where taint stops as well as where it arrives; `trace -brief` and `-count`
  give the terse renderings. `query -from/-to` printed only the sources that
  reached a sink, which reads exactly like a clean result.
- **`vyql bindings`** is `vyql definitions -kind bindings -lang <lang>`, keeping
  the role-grouped vocabulary and collapsing repeated rows to a count.
- **`vyql validate-binding`** is `vyql definitions validate-binding <path>`.
- **`definitions check-v2`** is `definitions validate`, whose output it
  duplicated exactly. **`definitions lint`** is `definitions validate -unstable`.

Every retired spelling names its replacement when used.


## [0.2.5] - 2026-08-10

### Added

- **`vyql cache clear` and `vyql cache path`.** The scan cache trusts size and
  mtime like any build cache, so a content change preserving both is missed; the
  source named `vyql cache clear` as the recovery path and the command did not
  exist. `path` prints the directory this build would use, which is derived
  rather than fixed, so "delete the cache" no longer requires guessing which one.

- **Rolling a baseline forward.** `-baseline old.json -baseline-write next.json`
  applies the old baseline and records the next one in a single scan, which is
  what a default branch needs in order to gate on what is new while keeping its
  suppression set current. The run reports and gates on what the old baseline
  does not cover. The file it writes keeps the verdict and reason of every entry
  carried over, records new findings below `-fail-on` as `accepted`, holds back
  new findings that meet `-fail-on` so a failing build cannot silently absorb
  them, and drops entries matching nothing in the current scan.

### Changed

- **Interface dispatch no longer routes through every implementation.** The
  abstract branch of call resolution documented that an interface method's
  runtime target is unknown and the call must stay unresolved; the code
  underneath routed through each concrete body instead. Because those bodies are
  shared across call sites, that merged taint between unrelated callers. Making
  the code match its documented behaviour removed the need for three OWASP
  Benchmark class names that had been hardcoded into the shared resolver to work
  around it.

  Measured across 24 corpora: OWASP BenchmarkJava +1.00 and BenchmarkPython
  +0.90 unchanged, 21 of 22 language ports at +1.00 unchanged, and on the 62-repo
  RealVuln corpus **15 fewer false positives with recall unchanged**.

- **Source files over 2 MiB are skipped by default.** A huge file that dodges
  every other filter explodes into a single enormous graph — and, for
  tree-sitter languages, a C parse tree several times the source size that the
  Go heap limit cannot see, which is the one remaining way a single file could
  exhaust a machine. `-max-file-size` raises the ceiling (`0` disables), the
  skipped count appears under `-coverage`, and the ceiling is part of the scan
  cache fingerprint so changing it never replays another ceiling's findings.
  Naming an oversized file directly still scans it: the filter applies to
  walking a tree, not to an explicit instruction.

  This is a behaviour change: findings in oversized files disappear from the
  report unless the ceiling is raised. Hand-written source files of that size
  are vanishingly rare; generated artifacts of that size are common and were
  already the dominant cost of the scans that hit them.

### Removed

- **Baseline files are keyed differently and must be re-recorded.** A finding had
  two identities: baseline files and `graph-json` hashed every binding's name and
  location, while the text report, SARIF, Nexus and `vyql diff` used the identity
  policy declared in `vyql/policies` — rule id, primary target location, primary
  target concept. One scan therefore emitted two different ids for the same
  finding, and the `fp=` you copied out of a report could never match a baseline
  entry whenever a finding had more than one binding, which is most of them.

  There is now one identity, the policy-declared one. Baseline files bump to
  version 2; a version 1 file is rejected with instructions rather than silently
  matching nothing, because failing open would un-suppress an entire triaged
  backlog without saying so. **Re-record with `-baseline-write` after reviewing
  the current findings** — a blind re-record accepts anything that appeared since
  the file was written.

### Fixed

- **A rebuild no longer replays the previous binary's analysis.** The incremental
  lowering delta caches were keyed on file content and signature fingerprint, with
  nothing identifying the build that wrote them, while every other cache namespace
  folds in the executable's identity. After rebuilding with a change to lowering,
  an unchanged file still hashed the same, both delta caches hit, and the replayed
  graph was the one the previous binary produced — so new lowering code silently
  did not run on unchanged files, which is every file on the scan right after a
  rebuild. Only affects `-incremental-cache`.
- **A rule using `can_access` no longer compiles into silence.** The parser
  accepted the verb and the evaluator had no branch for it, so such a rule
  compiled, ran, and reported nothing for the life of the pack. The verb is
  wired up, and any solver verb the evaluator cannot answer is now a
  rule-compile error rather than a permanent silent false. Same for `taint` in a
  `where` clause.
- **A SARIF document no longer contradicts itself.** Two severity-to-level
  mappings disagreed on `low`: the result came out `note` while the rule's
  default configuration came out `warning`, so a consumer filtering on either
  field saw a different set. The location a consumer sees is also now the same
  binding the fingerprint is built from; three copies of that selection rule
  existed and did not agree.
- **`--max-ram` stores a node faithfully.** The disk-backed graph dropped the
  four inline hot properties (`method`, `callee_path`, `str_args`, `vkind`), so a
  node put in did not come back out. Measured on 300 real files, findings were
  identical either way because lowering compensates for stores that lack them —
  but correctness should not depend on every producer remembering to. The store
  also gained the structural epoch it was missing, without which every binding
  applicator rebuilt its shared index from scratch, in the low-memory mode chosen
  precisely because resources were tight.
- **Cached deltas with trailing bytes are rejected** rather than merged as if
  complete, and the graph size hint — gated on a store type that is never used,
  so never written — now actually presizes the graph.

- **`--max-ram` could authorise several times what it named.** The flag's
  budget was spent twice over — badger's caches and the on-heap node-detail
  buffer were each sized from the same figure — while the heap ceiling was only
  applied on an error path, leaving the normal path at 80% of physical RAM.
  The budget is now partitioned once (half to badger's block cache, a quarter
  to the detail buffer, heap ceiling at half, restored on exit), the index
  cache no longer receives 30% of the cache budget (it is only consulted for
  encrypted stores, so it was funded but never populated), and the memtable
  shrinks from 128 MiB to 32 MiB. Measured on a ~5,900-file Java repository:
  the previous build peaked at 5.05 GB under a `-max-ram 6GB` flag; this one
  peaks at 4.06 GB under the same flag, and completes at 4.2 GB under a 4 GB
  flag that previously bounded nothing. A ceiling below the working set is
  slow — the spilled-detail read path is random point reads, and making that
  path sequential is the next piece of this work.
- **`-baseline-write` reports the scan it recorded.** Writing a baseline ended
  the run: no SARIF, no JSON, no text report, no coverage, no stats. A CI job
  adopting the scanner had to choose between recording a baseline and publishing
  results for that run, and nobody could see what had just been accepted on their
  behalf. The recording run now prints its findings in the requested format. An
  adoption run — `-baseline-write` with no `-baseline` — does not fail the build,
  because everything it reported was accepted a moment earlier, and it still
  fails outright, before printing, if the baseline cannot be written.
- **`-baseline` pointed at the file `-baseline-write` records is rejected.** The
  combination was accepted and the loaded baseline silently ignored. Recording
  writes every finding as `accepted` with an empty reason, so aiming it at a file
  you had triaged replaced those verdicts and their reasoning with a blank
  acceptance, and the run exited 0. The two flags are compared by resolved path,
  so an uncleaned spelling or a symlink is caught too.

### Performance

- **The `--max-ram` store no longer decodes node detail it holds in RAM.**
  Profiling showed 74.7% of all allocation — 51 GB on a ~5,900-file Java scan —
  in the graph's read path, decoding node-detail blobs and copying every string
  per read, for detail that had never left RAM: detail was encoded on write and
  decoded on every read, and the binding pass reads every node once per
  applicator. Detail now stays in struct form and is encoded once, at actual
  spill time; node types additionally live in the resident core, because
  `AddNode` consults the type on every call and must never pay a disk read for
  it. Resident point reads drop from 7 allocations to 0, a resident 100-node
  type-range pass from 700 to 1.

  Measured on the same Java repository: `-max-ram 6GB` goes from 115.8 s wall
  at 5.05 GB peak to 40.2 s at 4.06 GB. The default (no-flag) path does not use
  this store and is unchanged: 20.6 s. Findings are fingerprint-identical
  across the default, 6 GB and 4 GB modes — 1,460 on this repository, the same
  multiset in all three.

## [0.2.4] - 2026-08-07

**The scanner is unchanged from 0.2.3.** No engine, rule or binding differences —
same findings, same fingerprints. This release exists to publish the container
image, which is built from a release archive and so can only be produced by a
tagged release.

### Added
- **The container image is published.** `docker run --rm -v "$PWD:/work"
  ghcr.io/vyprai/vyql scan .` now works. The Dockerfile had been in the tree
  since 0.2.1 and nothing ever pushed it, so four documents told people to run an
  image that did not exist. Built for `linux/amd64` and `linux/arm64`, tagged with
  the version and `latest`, and the release job proves the published image both
  runs and detects before it finishes.
- **A landing page** for the CLI at `vyql.vyprsec.ai`, served from `site/`.

## [0.2.3] - 2026-08-06

### Added
- **Swift lock lifecycle.** A `.lock()` / `.unlock()` pair (the shape `NSLock`,
  `NSRecursiveLock`, `NSCondition` and `NSConditionLock` all share), plus
  `os_unfair_lock` and `pthread_mutex` called directly, now emit
  `code.LockAcquire` and `core.LockRelease`, so `VYQL-LIFE-001` covers Swift. It
  previously had no lock vocabulary at all, so the rule could not fire there in
  either direction. Matching is on the method name, so a `.lock()` that is not a
  mutex is reported too; the rule is medium-severity advisory for that reason,
  and Go's equivalent binding is broader still.

### Changed
- **Node ids no longer embed the file path.** The id namespace is a 17-byte hash
  of the path instead of the path itself, which was repeated on every node in a
  module — over a hundred bytes per node on a deep Java tree. `query`, `graph`
  and `match` output shows ids as `m4be5c7…Call#14` rather than `app.jsCall#14`;
  the loc column still names the file and line. Finding fingerprints hash rule
  id + location + concept, not ids, so existing `-baseline` files are unaffected.
  Two files hashing to one namespace would silently merge their nodes, so the
  scan now refuses that program outright (~3e-10 at a hundred thousand files).

### Fixed
- **`VYQL_CPUPROFILE` and `VYQL_MEMPROFILE` produced nothing on a real scan.**
  `main` exited through `os.Exit`, which does not run deferred functions, so the
  deferred profile flushes were skipped whenever a scan met its `-fail-on`
  threshold — that is, on any codebase worth profiling. The CPU profile was a
  0-byte file and the heap profile was never written at all.

- **Swift's `defer { … }` ran where it was written, not at function exit.** Swift's
  grammar has no `defer_statement`. `defer` parses as a call to an identifier of
  that name carrying a trailing closure, so the block fell through to the generic
  trailing-closure handling and was lowered inline. That is accidentally right when
  the `defer` follows what it cleans up and wrong otherwise: a release written
  above its acquisition landed *before* it in CFG order and read as never
  released. `defer` is now recognised by shape and lowered as `nir.Defer`.

  Shipping Swift lock bindings without this would have created exactly the false
  positive that PR #27 fixed for Go.

- **Go's `defer` was dropped from the IR, so a deferred release read as no
  release at all.** The frontend's statement conversion had no case for
  `*ast.DeferStmt`, so `defer mu.Unlock()` produced no node. Nothing emitted
  `core.LockRelease`, and `VYQL-LIFE-001` reported every `mu.Lock()` paired with
  a deferred unlock as a lock that may never be released. The idiomatic Go
  spelling was the one that failed; writing `mu.Unlock()` on its own line worked.

  This was never specific to locks. Every rule asking "is this released on every
  path" reads the same coverage, so `defer f.Close()`, `defer resp.Body.Close()`
  and `defer tx.Rollback()` were invisible to it too. The whole reason `defer`
  exists in Go is to make cleanup unconditional, and it was the one form the
  engine could not see.

  `defer` now lowers to `nir.Defer`, and the lowerer places the call after the
  function body so its CFG order post-dominates everything the body acquired.
  The region stays the one the `defer` was written in, so a defer registered
  inside a branch still does not cover code outside that branch, and registrations
  are emitted LIFO to match the order they run in.

  All 24 benchmark corpora are byte-identical before and after. They contain no
  lifecycle cases, so they could not see this in either direction. See
  `benchmarks/RESULTS.md` §3.1.3.

- **A resource released in a `finally` block counted as never released.** The
  lowerer gave `finally` a control region of its own, nested under the try. A
  control region means "may be skipped", which is true of the try body and of every
  handler, and false of a `finally`, which is the one nested block that always
  runs. Post-dominance rejects a release nested deeper than its acquisition as
  conditionally skipped, so the most conventional way to write the safe form
  reported a leak:

  ```java
  lock.lock();
  try { work(); } finally { lock.unlock(); }   // reported as never released
  ```

  `finally` now lowers into the region the try statement itself sits in, after
  the body and the handlers, so a release there post-dominates the acquisition
  whether that acquisition is above the try, inside its body, or inside a
  handler. Java try-with-resources was already correct, because its implicit `close()`
  is appended to the try body, not to a `finally`.

  C# reached the same false positive by a second route and is fixed with it: its
  frontend folded `finally` into the try body rather than populating
  `Try.Finally`, so `Monitor.Enter(o); try { … } finally { Monitor.Exit(o); }`
  reported a lock that is never released. The clause is now split out. C#
  `using` and Python `with` are a different gap and still uncovered: their
  release is implicit, so there is no node to post-dominate; Python has no lock
  bindings at all, so it reports nothing either way rather than reporting
  wrongly.

  The distinction against a `defer`, which keeps the region it was written in, is
  real: a `defer` inside a branch is conditionally *registered*, while a `finally`
  is unconditionally attached to its try statement.

  All 24 benchmark corpora are unchanged, BenchmarkJava's 2,740 cases included.

### Performance
- **A scan allocates a third less, and is materially faster on generated code.**
  Found by profiling rather than by reading, and each step measured: the C
  frontend recompiled 47 constant regexes per call (7.3% of scan CPU); a shared
  tree-sitter helper allocated three times per node visit, including a cursor at
  every leaf; nine `strings.NewReplacer` values were rebuilt per call; and branch
  lowering copied the whole variable scope four times per `if` — quadratic within
  one function, which is why a single large generated file could exhaust memory
  while thousands of ordinary files did not.

  Measured against 0.2.2 on a ~5,900-file Java repository: **11.58 GB allocated →
  9.49 GB (−18%)**. On generated code, where the quadratic bit hardest: **22.98 GB
  → 8.33 GB (−64%)** and **15.3 s → 11.3 s wall (−26%)**.

  Peak memory is unchanged. It tracks live heap plus GC headroom rather than
  allocation rate, so a third less garbage does not lower the ceiling — bounding
  the caches that hold the live heap was tried, measured, and reverted because it
  made both memory and time worse.

  Findings are byte-identical throughout: the same 1,460 findings with the same
  fingerprints on that repository, and all 24 benchmark corpora unchanged.

## [0.2.2] - 2026-08-05

### Fixed
- **A binding generated for a package matched every call sharing its method
  name.** Package bindings query a bare method behind a `dependency()` gate, so
  once any listed package exposed `parse`, every `.parse()` in the project became
  a deserialization sink. `csv.parse(req.body)` on a local module was reported as
  CRITICAL CWE-502 because `prettier` appeared in `devDependencies`. A call now
  has to be on the package the binding was generated for.

  This reaches further than the deserialization noise it was reported as.
  **25,587 bindings** query a bare method: 16,821 sinks, 5,476 taint sources that
  multiply across every other rule, and **2,301 checks**. A check matching too
  broadly does not add noise, it removes a real finding. A stray `.validate()`
  satisfying `core.InputValidation` suppresses an injection report with nothing to
  show for it. One fix covers all of them.

  Rejection requires positive evidence: a receiver resolved to a *different*
  package. An unresolved receiver still matches, because an instance carries no
  import identity. `const zip = new AdmZip(...); zip.extractAllTo(...)` reaches
  its package through a variable. `VYQL_UNRESOLVED_RECEIVER=skip` selects the
  stricter policy.

  Measured on RealVuln (62 real repositories): **no true positive lost**, 8 false
  positives removed. BenchmarkJava, BenchmarkPython and owasp-js are unchanged at
  +1.00 / +0.90 / +1.00. This class of binding contributes nothing there, which
  is why every gate was blind to it. See `benchmarks/RESULTS.md` §6.1.1.

## [0.2.1] - 2026-08-05

### Added
- **An install script.** `curl -fsSL https://dl.vyprsec.ai/vyql/install.sh | sh`
  detects the platform, verifies the published SHA-256, unpacks under
  `~/.local/share/vyql` and puts `vyql` in `~/.local/bin`. POSIX `sh`, because it
  runs before VyQL exists on the machine. `VYQL_INSTALL_BASE_URL` points the
  download at a mirror serving the same `<base>/<version>/<asset>` layout.
- **A container image.** `docker run --rm -v "$PWD:/work" ghcr.io/vyprai/vyql scan .`
  Runs as a non-root user, so it leaves no root-owned files in a mounted tree.
  `debian:stable-slim` rather than Alpine: the parsers are C linked against glibc.

### Fixed
- **A binary reached through a symlink could not find its data.**
  `os.Executable` reports the symlink's own path on macOS, so a linked `vyql`
  searched the wrong directory and panicked with "could not locate the data
  directory". It now follows the link, preferring data beside the link itself
  where someone put it there deliberately. This blocked every packaged install,
  Homebrew included.
- **`JSON.parse` was reported as critical CWE-502.** Package bindings for
  libraries whose API exposes `parse` matched any `.parse()` call once the
  dependency gate opened, so a project with a parser package anywhere in
  `devDependencies` had `JSON.parse(req.body)` reported as deserialization of
  untrusted data. `JSON`, `Date`, `url` and `querystring` parse are now
  recognised as safe; `node-serialize.unserialize` and friends still report, at
  higher confidence than before.
- **Checkouts are byte-identical across platforms.** Git converts line endings
  on Windows by default, and the NIR golden files are compared as bytes, so all
  ten golden tests failed there and nowhere else.

### Changed
- **Sink concepts that exported a null operation are now mapped**: 58 mappings
  in `vyql/exports/sink_operations.tsv`, up from 32, matched against the
  consuming vocabulary on the CWE both sides record. The six with no honest
  counterpart stay unmapped and say why. A wrong operation is
  indistinguishable from a right one, where a null is visibly absent. A test
  requires every sink concept to be either mapped or listed.
- The generated binding tree no longer nests files under numeric shard
  directories.

## [0.2.0] - 2026-08-05

First public release.

### Added
- **Taint and graph scanning across 22 languages.** Java, Python and
  JavaScript/TypeScript are the reference frontends and carry the most complete
  modelling; the rest range from full taint tracking to call-and-concat
  coverage. `vyql definitions -kind all` reports what is actually loaded.
- **The security knowledge ships as data**, not compiled in: 858 concepts, 728
  rules and 31,541 bindings under `vyql/`, loaded at startup from `VYQL_HOME` or
  a `vyql/` directory above the working directory. Edits take effect on the next
  run without rebuilding.
- **Findings explain themselves.** Each one names the source, the sink, the path
  between them, and the neutralizing controls it looked for and did not find.
  `explain`, `trace`, `match`, `resolve` and `graph` interrogate the graph
  directly.
- **`--format json` and `--format sarif`** for CI, with a stable finding
  fingerprint.
- **Build gating.** `scan` exits 1 on any HIGH or CRITICAL finding, so adding it
  to a pipeline gates that pipeline with no further configuration. `-fail-on`
  moves the threshold or turns it off with `none`; `-exit-code` sets the status,
  which is how to distinguish "found something" from "VyQL could not run", since
  a failed scan also exits 1.
- **`diff`** compares two `--format json` runs by finding fingerprint, for
  asking whether a branch introduced anything new.
- **Triage baselines.** `-baseline` keeps already-triaged findings out of the
  report and the gate, keyed on the fingerprint, so a scan reports what is new;
  `-baseline-write` records the current findings as accepted, which is how a
  codebase with a backlog adopts the scanner. Entries that stop matching are
  reported rather than left to outlive the code they excused.
- **Coverage reporting.** Files no frontend read are reported unconditionally,
  because a clean result over a tree that was mostly skipped reads exactly like
  a clean result over one that was fully read. `-coverage` gives the full
  account of what was parsed, excluded and left unanalysed.
- **An [Agent Skill](https://github.com/vyprai/claude-plugins)** for scanning and triage,
  written to the open SKILL.md format so it works across agent tools rather than
  one vendor's.
- **A [GitHub Action](https://github.com/vyprai/vyql-action)**:
  `uses: vyprai/vyql-action@v1`.
- **`vyql scan` with no path** scans the working directory and says so.
- **Release archives for linux/amd64, linux/arm64, darwin/amd64 and
  darwin/arm64**, each built on a native runner and carrying both the binary and
  the data directory, with SHA-256 sums. Two builds of the same commit from
  different source paths are asserted byte-identical.
- **`go install github.com/vyprai/vyql/cmd/vyql@latest`** works without further
  setup: the module carries the data directory and the binary resolves it from
  the module cache.

### Notes
- Measured on the public OWASP Benchmark suites by Youden index: BenchmarkJava
  **+1.00**, BenchmarkPython **+0.90**. `benchmarks/fetch-corpora.sh` fetches
  the corpora; [benchmarks/RESULTS.md](benchmarks/RESULTS.md) records the method
  and the known corpus defects.
- The CLI is stable under semantic versioning. **The rule and binding language
  is not**. See [Stability](README.md#stability) before writing bindings.
- Requires a C toolchain to build from source; the parsers are C compiled by
  cgo.
- Every Go package except `cmd/` is under `internal/`. The command is the
  supported interface; the packages stay free to change. Promoting one out of
  `internal/` later is not a breaking change, so nothing is foreclosed.

### Retracted
- **0.1.0** produced a binary that could not locate its data directory when
  installed with `go install`. It is retracted in `go.mod`; use 0.2.0.
