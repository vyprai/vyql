# Changelog

Notable changes to VyQL. The format follows [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html).

Rule and binding additions change what a scan reports, so they are treated as
user-visible changes and listed here — a new finding appearing in CI is a
behaviour change even when no code changed.

## [Unreleased]

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
  counterpart stay unmapped and say why — a wrong operation is
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
- **An [Agent Skill](skills/vyql-security-scan/)** for scanning and triage,
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
  is not** — see [Stability](README.md#stability) before writing bindings.
- Requires a C toolchain to build from source; the parsers are C compiled by
  cgo.
- Every Go package except `cmd/` is under `internal/`. The command is the
  supported interface; the packages stay free to change. Promoting one out of
  `internal/` later is not a breaking change, so nothing is foreclosed.

### Retracted
- **0.1.0** produced a binary that could not locate its data directory when
  installed with `go install`. It is retracted in `go.mod`; use 0.2.0.
