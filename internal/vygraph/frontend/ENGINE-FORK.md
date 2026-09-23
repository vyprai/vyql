# v3 frontend fork record

Approach: fork-and-retarget - share the upstream
go-tree-sitter runtime + grammar bindings (already vendored in go.mod) with
fresh v3-NIR emission. No v2 package is imported or modified.

## Merge-base

v2 reference frontends at `main` = `b09e433f6` (the branch point of this v3
branch). Post-fork v2 extraction fixes are cherry-picked from upstream v2 in batches at sync boundaries.

## Re-derived traversal classes

The v2 reference frontend's hardened decisions this fork re-derives (each has a
fixture in this package's tests):

- decorated definitions: raw decorator tokens recorded on ParamEntry facts for
  framework models (never interpreted in the frontend)
- attribute/subscript paths: dotted syntactic path with method segment split;
  qualified_path left to the lowering pass (resolution owns it)
- string construction: concatenation and %-formatting lower to Format with
  parts (the taint substrate)
- assignment shapes: target and value both emitted; def-use FLOWS computed by
  the shared lowering
- structured control flow: region paths (if/elif/else, for/while, try/except/
  finally) with monotonic program order — the cfg solver's substrate
- unknown constructs: approximate transparent lowering, stamped
  approx_lowered — never silently dropped
- identity: (Type, file:line:col) — a construct and its first child share a
  start position, so type-qualified IDs prevent cross-type collisions

## Languages

- python: landed (this package)
- javascript, java: same pattern, pending
- golang: fresh go/ast frontend, pending
