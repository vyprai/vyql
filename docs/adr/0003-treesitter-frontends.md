# ADR 0003 — Tree-sitter for real multi-language parser frontends

Status: **Accepted** (build loop, multi-language milestone)
Supersedes/extends: docs/20 (extraction frontends)

## Context

The Go product shipped with one real frontend (native `go/ast`) wired into
`vyql scan`. The other languages (Python/JS/Ruby) existed only at the engine
level — NIR-fixture tests + framework adapters — with no real parser, so the CLI
could not scan them. To make `vyql scan` genuinely multi-language on real repos
we need real `source → NIR` frontends for Python, JavaScript/TypeScript, Ruby,
and Java.

Two options were on the table:

1. **tree-sitter** via Go CGO bindings (`github.com/tree-sitter/go-tree-sitter` +
   per-grammar modules). docs/20's recommended path: a uniform node API across
   100+ languages, error recovery, build-free grammars.
2. **Subprocess frontends** — shell out to the language's own tooling (CPython
   `ast`, `node`+acorn, Ruby `Ripper`), as the PoC did. No CGO, but requires each
   language runtime installed on the scanning host and a subprocess per file.

## Decision

**Use tree-sitter.** A feasibility spike confirmed it works in this environment:
`CGO_ENABLED=1` with Apple clang, the bindings + grammar modules fetch via
`go get`, and the CGO grammar compiles and parses real source (verified end to
end by parsing Python and finding an interprocedural SQLi).

Tree-sitter is preferred because: one dependency model covers every language; no
runtime-tool dependency on the scanning host; in-process (no subprocess
overhead); and it is the path docs/20 already committed to.

## Consequences

- The project now requires **CGO** to build the tree-sitter frontends and the
  CLI. The core engine, ontology, solvers, USG, and the native Go frontend stay
  CGO-free; tree-sitter is isolated in `go/extract/frontend/treesitter` (and
  pulled in by `cmd/vyql`). A pure-Go build of the engine remains possible.
- Each grammar's CST node vocabulary is a distinct shape; each frontend maps it
  to the SAME NIR and runs through the SAME lowering engine — so resolution and
  rules are untouched, per docs/20. The Python frontend is a direct port of the
  PoC `frontend_ts.py`.
- Grammar modules are versioned Go dependencies (`tree-sitter-python`, etc.),
  upgraded like any other.
- If a future target environment lacks CGO, the subprocess approach remains the
  documented fallback (not implemented).

## Status of frontends

- **Go** — native `go/ast` (no tree-sitter needed). Shipped.
- **Python** — tree-sitter. Shipped (this milestone).
- **JavaScript/TypeScript, Ruby, Java** — tree-sitter, in progress.
