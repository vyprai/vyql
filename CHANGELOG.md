# Changelog

Notable changes to VyQL. The format follows [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html).

Rule and binding additions change what a scan reports, so they are treated as
user-visible changes and listed here — a new finding appearing in CI is a
behaviour change even when no code changed.

## [Unreleased]

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
