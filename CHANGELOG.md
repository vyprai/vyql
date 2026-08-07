# Changelog

Notable changes to VyQL. The format follows [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html).

New rules and bindings change what a scan reports, so they get listed here like
any other user-visible change. A finding that suddenly appears in your CI is a
behaviour change, even if no code moved.

## [Unreleased]

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
