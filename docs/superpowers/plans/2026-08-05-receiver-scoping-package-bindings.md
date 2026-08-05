# Receiver Scoping for Package-Gated Bindings — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A binding generated for package `P` matches only calls whose receiver resolves to `P`, instead of every call sharing that method name.

**Architecture:** Lowering already builds a per-module `local → importEntry` table and already
writes `callee_path` onto every `code.Call` node. Resolve the root segment of `callee_path`
through that table, store the result as a new `recv_package` node property, and make the
binding matcher require `recv_package ∈ spec.Packages` for specs that are both `ByMethod`
and package-gated. No `.vyql` data changes: one engine change re-scopes all 24,546 bindings.

**Tech Stack:** Go 1.x (module at repo root, `github.com/vyprai/vyql`), cgo + tree-sitter,
VyQL `.vyql` data loaded from `VYQL_HOME`.

## Global Constraints

- **Run `go` commands from the repository root.** The module is at the root; there is no `go/` directory.
- **`CGO_ENABLED=1` is required.** Vendored tree-sitter grammars are C compiled by cgo.
- **Always `go test -count=1`.** The test cache does not track `.vyql` data files.
- **Comments describe the present.** No "was", "previously", "used to", "renamed from". History belongs in git.
- **No `Co-Authored-By: Claude` trailer** on commits.
- Protected baselines that must not drop: BenchmarkJava **+1.00**, BenchmarkPython **+0.90**, owasp-js **+1.00**.
- Shell is zsh; unquoted `$var` is not word-split.

---

## Problem, measured

`vyql/bindings/packages/generated/javascript/prettier.vyql`:

```
binding deserialization0 {
  requires { dependency("prettier") }
  query pattern callExpr where callee.method == "parse"
  emit sink code.Deserialization at args[0]
}
```

The `dependency()` gate is correct. The query is not: once the gate opens, `callee.method
== "parse"` matches every `.parse()` in the repository. A project with `prettier` in
`devDependencies` reports `JSON.parse(req.body)` as CRITICAL CWE-502.

Measured on `main` at `e85551084` over `vyql/bindings/packages/generated`:

| | count |
|---|---|
| bindings queried by bare `callee.method` with no receiver/path/type constraint | **24,546** |
| share of all generated bindings (24,835) | **98.8%** |
| …emitting `sink` / `source` / `check` / `issue` | 16,151 / 5,373 / 2,113 / 909 |
| …reaching `code.Deserialization` | 5,530 |
| …reaching `code.SqlExecution` | 1,101 |
| …reaching `code.CodeEval` | 618 |
| all of them gated by `dependency()` | 24,546 (100%) |

Most frequent bare method names: `parse` 1122, `read` 342, `write` 255, `send` 235,
`load` 203, `decode` 198, `get` 178, `query` 176, `run` 171, `escape` 160, `connect` 158.

**Bracket measurement.** Deleting all 24,546 bindings (upper bound on what scoping can
remove, worst case for what it can cost):

| Suite | `main` | all bare-method bindings deleted |
|---|---|---|
| BenchmarkJava | +1.00 | **+1.00** |
| BenchmarkPython | +0.90 | **+0.90** |
| owasp-js | +1.00 | **+1.00** |
| RealVuln (62 repos) | TP=977 FP=2530 | **TP=974 FP=2444** |

So the entire class contributes **nothing** to the three protected suites, and on RealVuln
it is worth **−86 FP for −3 TP**. Correct receiver scoping should keep most of the −86
while recovering the −3, because those 3 are calls genuinely made on the gated package.

**Why path rewriting cannot work.** `callee.path` holds source text, not a resolved
package. Verified with `vyql graph` on a file importing `@hapi/bourne` as `Bourne` and
`js-yaml` as `yaml`:

```
path=Bourne.parse      not @hapi/bourne.parse
path=yaml.load         not js-yaml.load
path=JSON.parse
```

Rewriting 24,546 bindings to `callee.path ~= "<package>.<method>"` would therefore miss
every aliased import. Resolution must happen in the engine, where the import table lives.

## Out of scope — needs its own plan

Receiver scoping does **not** fix semantic misclassification. Even correctly scoped:

- `defusedxml.parse` remains a `code.Deserialization` sink, though defusedxml exists to
  *prevent* XXE. The corpus contradicts itself: `vyql/bindings/packages/python/m3d9ccbad.vyql:709`
  models `defusedxml.ElementTree.fromstring` as a `core.XmlHardening` **check**, while
  `vyql/bindings/packages/generated/python/defusedxml.vyql` models the same library as a sink.
- `@hapi/bourne.safeParse` remains a sink, though it is a hardened JSON parser.
- `esprima.parse`, `prettier.parse`, `postcss.parse` return ASTs, not deserialized objects.

That is a classifier problem in the generator (which package APIs are CWE-502 at all), and
belongs with the generator work planned in `vyprai/vyql-internal#44`. Fixing it requires
distinguishing text/AST parsers from object deserializers and teaching the classifier that
some libraries are safety controls. **Do not attempt it in this plan.**

## File structure

| File | Responsibility |
|---|---|
| `internal/extract/lowering/receiver_package.go` *(new)* | Resolve a `callee_path` root to a package root via the module import table. One function, no state. |
| `internal/extract/lowering/receiver_package_test.go` *(new)* | Unit tests for that resolution, including aliases, destructured imports, and scoped npm names. |
| `internal/extract/lowering/lowering.go` | Call `resolveReceiverPackage` when materializing a `code.Call` node; write the `recv_package` prop. |
| `internal/extract/frontend/bindings.go` | Enforce `recv_package ∈ Packages` for `ByMethod` specs that are package-gated. |
| `internal/extract/frontend/package_alias.go` *(new)* | Distribution-name → import-name table (`PyYAML`→`yaml`). Data plus one lookup. |
| `cmd/vyql/receiver_scoping_test.go` *(new)* | End-to-end: prettier devDependency + `JSON.parse` yields no finding; `node-serialize.unserialize` still does. |
| `benchmarks/RESULTS.md` | Record the measured before/after. |

---

### Task 1: Pin the bug with an end-to-end failing test

**Files:**
- Create: `cmd/vyql/receiver_scoping_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `writeFixture(t *testing.T, dir string, files map[string]string)` helper reused by Task 6.

- [ ] **Step 1: Write the failing test**

```go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFixture materializes a throwaway project tree and returns its root.
func writeFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A package whose API happens to expose parse() must not turn every .parse()
// in the project into a deserialization sink.
func TestBareMethodDoesNotMatchForeignReceiver(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"package.json": `{"name":"t","devDependencies":{"prettier":"^3.0.0"}}`,
		"app.js":       "function handler(req, res) { return JSON.parse(req.body); }\n",
	})

	findings := scanFixture(t, dir)
	for _, f := range findings {
		if strings.Contains(f.Rule, "DESER") {
			t.Fatalf("JSON.parse reported as deserialization: %+v", f)
		}
	}
}

// The genuine case must survive: a call actually made on the gated package.
func TestBareMethodStillMatchesOwnReceiver(t *testing.T) {
	dir := writeFixture(t, map[string]string{
		"package.json": `{"name":"t","dependencies":{"node-serialize":"^0.0.4"}}`,
		"app.js": "const serialize = require('node-serialize');\n" +
			"function handler(req, res) { return serialize.unserialize(req.body); }\n",
	})

	findings := scanFixture(t, dir)
	found := false
	for _, f := range findings {
		if strings.Contains(f.Rule, "DESER") {
			found = true
		}
	}
	if !found {
		t.Fatal("node-serialize.unserialize is a real sink and must still be reported")
	}
}
```

- [ ] **Step 2: Add the scan helper the tests call**

`scanFixture` must run the same code path as the CLI. Find the existing in-process scan
helper used by `cmd/vyql`'s other tests with:

```bash
grep -rn "func.*Fixture\|func runScan\|func scanDir" cmd/vyql/*_test.go
```

Reuse it. If none exists, add this one, adjusting `runScan` to the actual entry point that
`TestOWASPBenchmark` uses (find it with `grep -n "func TestOWASPBenchmark" -A40 cmd/vyql/*_test.go`):

```go
type fixtureFinding struct {
	Rule       string
	Severity   string
	Confidence string
	Sink       string
}

func scanFixture(t *testing.T, dir string) []fixtureFinding {
	t.Helper()
	// Mirror TestOWASPBenchmark's in-process scan entry point rather than
	// shelling out, so the test fails fast and reports Go stack traces.
	out := runScanForTest(t, dir)
	res := make([]fixtureFinding, 0, len(out))
	for _, f := range out {
		res = append(res, fixtureFinding{
			Rule: f.Rule, Severity: f.Severity,
			Confidence: f.Confidence, Sink: f.Sink,
		})
	}
	return res
}
```

- [ ] **Step 3: Run the tests to verify the first fails and the second passes**

```bash
# from the repository root
CGO_ENABLED=1 go test -count=1 -run 'TestBareMethod' ./cmd/vyql/ -v
```

Expected: `TestBareMethodDoesNotMatchForeignReceiver` FAILS with "JSON.parse reported as
deserialization"; `TestBareMethodStillMatchesOwnReceiver` PASSES. If the second one fails,
stop — the fixture is wrong, not the engine.

- [ ] **Step 4: Commit**

```bash
git add cmd/vyql/receiver_scoping_test.go
git commit -m "test: pin bare-method bindings matching a foreign receiver"
```

---

### Task 2: Resolve a callee path root to its package

**Files:**
- Create: `internal/extract/lowering/receiver_package.go`
- Create: `internal/extract/lowering/receiver_package_test.go`

**Interfaces:**
- Consumes: `importEntry{kind string; module string; symbol string}` and
  `importPackageRoot(module string) string`, both already in
  `internal/extract/lowering/lowering.go`.
- Produces: `resolveReceiverPackage(calleePath string, table map[string]importEntry) string`
  — returns the package root the call is made on, or `""` when unresolvable.

- [ ] **Step 1: Write the failing test**

```go
package lowering

import "testing"

func TestResolveReceiverPackage(t *testing.T) {
	table := map[string]importEntry{
		// import Bourne from '@hapi/bourne'
		"Bourne": {kind: "mod", module: "@hapi/bourne"},
		// const yaml = require('js-yaml')
		"yaml": {kind: "mod", module: "js-yaml"},
		// const { parse } = require('qs')
		"parse": {kind: "sym", module: "qs", symbol: "parse"},
		// import defusedxml.ElementTree as ET
		"ET": {kind: "mod", module: "defusedxml.ElementTree"},
	}

	cases := []struct{ path, want string }{
		{"Bourne.parse", "@hapi/bourne"},   // aliased scoped package
		{"yaml.load", "js-yaml"},           // aliased plain package
		{"parse", "qs"},                    // destructured symbol, no receiver
		{"ET.fromstring", "defusedxml"},    // submodule collapses to package root
		{"JSON.parse", ""},                 // builtin, not imported
		{"this.parse", ""},                 // dynamic receiver
		{"", ""},                           // no callee path at all
		{"unknown.parse", ""},              // receiver not in the import table
	}
	for _, c := range cases {
		if got := resolveReceiverPackage(c.path, table); got != c.want {
			t.Errorf("resolveReceiverPackage(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
# from the repository root
CGO_ENABLED=1 go test -count=1 -run TestResolveReceiverPackage ./internal/extract/lowering/ -v
```

Expected: FAIL, `undefined: resolveReceiverPackage`.

- [ ] **Step 3: Implement it**

```go
package lowering

import "strings"

// resolveReceiverPackage reports which package a call is made on, by resolving the
// root segment of its callee path through the enclosing module's import table.
//
// A call reaches a package two ways. `yaml.load(x)` has the package bound to a
// receiver, so the root segment ("yaml") is the import local. `parse(x)` after
// `const { parse } = require('qs')` has no receiver at all, and the callee path
// is itself the import local. Both resolve here; anything else -- a builtin, a
// dynamic receiver, a local variable -- returns "" and is treated as unresolved.
func resolveReceiverPackage(calleePath string, table map[string]importEntry) string {
	if calleePath == "" || len(table) == 0 {
		return ""
	}
	root := calleePath
	if i := strings.IndexByte(root, '.'); i > 0 {
		root = root[:i]
	}
	entry, ok := table[root]
	if !ok || entry.module == "" {
		return ""
	}
	return importPackageRoot(entry.module)
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
CGO_ENABLED=1 go test -count=1 -run TestResolveReceiverPackage ./internal/extract/lowering/ -v
```

Expected: PASS.

Note `importPackageRoot("defusedxml.ElementTree")` returns `defusedxml.ElementTree`, not
`defusedxml` — it splits on `/`, which is npm/Go syntax, not Python's `.`. If the
`ET.fromstring` case fails, that is why. Fix it inside `resolveReceiverPackage` by
trimming the dotted tail *before* calling `importPackageRoot`, and only for modules with
no `/`:

```go
	mod := entry.module
	if !strings.Contains(mod, "/") {
		if i := strings.IndexByte(mod, '.'); i > 0 {
			mod = mod[:i]
		}
	}
	return importPackageRoot(mod)
```

- [ ] **Step 5: Commit**

```bash
git add internal/extract/lowering/receiver_package.go internal/extract/lowering/receiver_package_test.go
git commit -m "feat(lowering): resolve a callee path root to its package"
```

---

### Task 3: Record `recv_package` on call nodes

**Files:**
- Modify: `internal/extract/lowering/lowering.go` (the `code.Call` materialization near line 3880–3906)
- Modify: `internal/extract/lowering/receiver_package_test.go`

**Interfaces:**
- Consumes: `resolveReceiverPackage` from Task 2; `l.importTables[l.curModule]`.
- Produces: node property `recv_package` on `code.Call` nodes, read by Task 5.

- [ ] **Step 1: Write the failing test**

Add to `internal/extract/lowering/receiver_package_test.go`. Model it on the existing
`TestLowerMaterializesImportNodes` in `internal/extract/lowering/lowering_test.go:628` —
read that first for how to build a `nir.Module` and run the lowerer.

```go
func TestCallNodeCarriesReceiverPackage(t *testing.T) {
	// Build a module that imports js-yaml as `yaml` and calls yaml.load(x),
	// following the construction in TestLowerMaterializesImportNodes.
	mod := nir.Module{
		File:    "app.js",
		Imports: []nir.Import{{Local: "yaml", Module: "js-yaml", IsModule: true}},
		Body:    callBody("yaml.load", "load"), // see lowering_test.go helpers
	}
	g := lowerForTest(t, mod)

	ids, _ := g.NodesOfType("code.Call")
	if len(ids) == 0 {
		t.Fatal("no call nodes lowered")
	}
	var got string
	for _, id := range ids {
		if g.Prop(id, "callee_path") == "yaml.load" {
			got = g.Prop(id, "recv_package")
		}
	}
	if got != "js-yaml" {
		t.Fatalf("recv_package = %q, want %q", got, "js-yaml")
	}
}
```

Adjust `callBody` / `lowerForTest` / `g.Prop` to the real helper names in
`lowering_test.go`; find them with:

```bash
grep -n "func lower\|func.*Body(\|Prop(" internal/extract/lowering/lowering_test.go | head -20
```

- [ ] **Step 2: Run it to verify it fails**

```bash
CGO_ENABLED=1 go test -count=1 -run TestCallNodeCarriesReceiverPackage ./internal/extract/lowering/ -v
```

Expected: FAIL with `recv_package = "", want "js-yaml"`.

- [ ] **Step 3: Write the property during call materialization**

In `internal/extract/lowering/lowering.go`, inside the `code.Call` materialization, the
property map is built only when `propCount > 0`. Compute the package first so it
participates in that count. Immediately **before** the `var props map[string]string`
declaration, add:

```go
	// Which package this call is made on, so a binding gated on package P can
	// require the call to be on P rather than on any receiver sharing the name.
	recvPackage := resolveReceiverPackage(calleePath, l.importTables[l.curModule])
	if recvPackage != "" {
		propCount++
	}
```

and inside the `if propCount > 0` block, alongside the existing `recv` / `recv_type`
writes, add:

```go
		if recvPackage != "" {
			props["recv_package"] = recvPackage
		}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
CGO_ENABLED=1 go test -count=1 -run TestCallNodeCarriesReceiverPackage ./internal/extract/lowering/ -v
```

Expected: PASS.

- [ ] **Step 5: Verify nothing else regressed**

```bash
CGO_ENABLED=1 go test -count=1 ./internal/extract/...
```

Expected: all PASS. `TestNIRGolden` compares bytes; if golden files record node
properties, they now include `recv_package` and must be regenerated. Regenerate only
after confirming by eye that the added property is the sole difference:

```bash
CGO_ENABLED=1 go test -count=1 -run TestNIRGolden ./internal/extract/... 2>&1 | head -40
```

- [ ] **Step 6: Commit**

```bash
git add internal/extract/lowering/
git commit -m "feat(lowering): record the package a call is made on"
```

---

### Task 4: Distribution-name to import-name table

**Files:**
- Create: `internal/extract/frontend/package_alias.go`
- Create: `internal/extract/frontend/package_alias_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `importNamesForPackage(pkg string) []string` — the import roots a
  distribution can appear under, always including `pkg` itself.

**Why this task exists:** `dependency("PyYAML")` gates on the PyPI distribution name, but
the code says `import yaml`. Without this mapping, scoping would drop every true positive
for such packages. Only divergent names need an entry.

- [ ] **Step 1: Write the failing test**

```go
package frontend

import (
	"slices"
	"testing"
)

func TestImportNamesForPackage(t *testing.T) {
	cases := []struct {
		pkg  string
		want []string
	}{
		{"PyYAML", []string{"PyYAML", "yaml"}},
		{"beautifulsoup4", []string{"beautifulsoup4", "bs4"}},
		{"python-dateutil", []string{"python-dateutil", "dateutil"}},
		{"js-yaml", []string{"js-yaml"}},            // no divergence
		{"@hapi/bourne", []string{"@hapi/bourne"}},  // scoped npm, no divergence
	}
	for _, c := range cases {
		got := importNamesForPackage(c.pkg)
		for _, w := range c.want {
			if !slices.Contains(got, w) {
				t.Errorf("importNamesForPackage(%q) = %v, missing %q", c.pkg, got, w)
			}
		}
	}
}

func TestImportNamesAlwaysIncludesPackageItself(t *testing.T) {
	if got := importNamesForPackage("totally-unknown-pkg"); !slices.Contains(got, "totally-unknown-pkg") {
		t.Fatalf("got %v, want it to contain the package name itself", got)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
CGO_ENABLED=1 go test -count=1 -run TestImportNames ./internal/extract/frontend/ -v
```

Expected: FAIL, `undefined: importNamesForPackage`.

- [ ] **Step 3: Implement it**

```go
package frontend

// packageImportAliases maps a distribution name to the import root it is used
// under, for the cases where the two differ. A package absent here is imported
// under its own name.
var packageImportAliases = map[string][]string{
	"PyYAML":          {"yaml"},
	"beautifulsoup4":  {"bs4"},
	"python-dateutil": {"dateutil"},
	"Pillow":          {"PIL"},
	"protobuf":        {"google"},
	"scikit-learn":    {"sklearn"},
	"opencv-python":   {"cv2"},
	"attrs":           {"attr"},
	"msgpack-python":  {"msgpack"},
	"PyJWT":           {"jwt"},
	"pycryptodome":    {"Crypto"},
	"python-magic":    {"magic"},
	"Django":          {"django"},
	"Flask":           {"flask"},
}

// importNamesForPackage returns every import root a distribution can appear
// under, starting with the distribution name itself.
func importNamesForPackage(pkg string) []string {
	out := []string{pkg}
	return append(out, packageImportAliases[pkg]...)
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
CGO_ENABLED=1 go test -count=1 -run TestImportNames ./internal/extract/frontend/ -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/extract/frontend/package_alias.go internal/extract/frontend/package_alias_test.go
git commit -m "feat(bindings): map distribution names to import roots"
```

---

### Task 5: Enforce scoping in the matcher, behind a flag

**Files:**
- Modify: `internal/extract/frontend/bindings.go`
- Modify: `cmd/vyql/receiver_scoping_test.go`

**Interfaces:**
- Consumes: `recv_package` node property (Task 3); `importNamesForPackage` (Task 4);
  existing `sinkSpec.ByMethod bool` and `sinkSpec.Packages []string`.
- Produces: `receiverScopeSatisfied(nodePkg string, packages []string, unresolved unresolvedPolicy) bool`.

**The one real decision in this plan.** When `recv_package` is `""` — a builtin, a dynamic
receiver, a language whose frontend does not populate import tables — the matcher must
either keep matching (recall) or stop (precision). Implement both, measure, then pick.
Default to `unresolvedSkips` and let Task 6's measurement overturn it.

- [ ] **Step 1: Write the failing test**

```go
package frontend

import "testing"

func TestReceiverScopeSatisfied(t *testing.T) {
	pkgs := []string{"prettier"}
	cases := []struct {
		name     string
		nodePkg  string
		policy   unresolvedPolicy
		want     bool
	}{
		{"call on the gated package", "prettier", unresolvedSkips, true},
		{"call on another package", "js-yaml", unresolvedSkips, false},
		{"builtin receiver, skip policy", "", unresolvedSkips, false},
		{"builtin receiver, match policy", "", unresolvedMatches, true},
	}
	for _, c := range cases {
		if got := receiverScopeSatisfied(c.nodePkg, pkgs, c.policy); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestReceiverScopeUsesImportAliases(t *testing.T) {
	// dependency("PyYAML") must match code that did `import yaml`.
	if !receiverScopeSatisfied("yaml", []string{"PyYAML"}, unresolvedSkips) {
		t.Fatal("PyYAML must match an import of yaml")
	}
}

func TestReceiverScopeIgnoredWhenUngated(t *testing.T) {
	// No dependency() gate means no package to scope to; match as before.
	if !receiverScopeSatisfied("", nil, unresolvedSkips) {
		t.Fatal("an ungated spec must not be scoped")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
CGO_ENABLED=1 go test -count=1 -run TestReceiverScope ./internal/extract/frontend/ -v
```

Expected: FAIL, `undefined: receiverScopeSatisfied`.

- [ ] **Step 3: Implement the predicate**

Add to `internal/extract/frontend/bindings.go`:

```go
// unresolvedPolicy decides whether a package-gated bare-method spec matches a
// call whose receiver does not resolve to any import -- a builtin, a dynamic
// receiver, or a language whose frontend has no import table.
type unresolvedPolicy int

const (
	unresolvedSkips unresolvedPolicy = iota
	unresolvedMatches
)

// receiverScopeSatisfied reports whether a call made on package nodePkg is in
// scope for a spec gated on packages. A spec with no package gate is unscoped
// and always satisfied.
func receiverScopeSatisfied(nodePkg string, packages []string, policy unresolvedPolicy) bool {
	if len(packages) == 0 {
		return true
	}
	if nodePkg == "" {
		return policy == unresolvedMatches
	}
	for _, p := range packages {
		for _, name := range importNamesForPackage(p) {
			if name == nodePkg {
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 4: Run the predicate test to verify it passes**

```bash
CGO_ENABLED=1 go test -count=1 -run TestReceiverScope ./internal/extract/frontend/ -v
```

Expected: PASS.

- [ ] **Step 5: Call it from the match path**

Find every site that matches a spec by bare method. They read `n.Prop("method")` against a
spec with `ByMethod: true`; the candidate list is built at
`internal/extract/frontend/bindings.go:4341` via `flagIdx.candidates(n.Prop("method"),
n.Prop("callee_path"))`. Enumerate the sites first:

```bash
grep -n "ByMethod" internal/extract/frontend/bindings.go
```

At each site that accepts a candidate spec for a node, add the guard before accepting:

```go
	if spec.ByMethod && !receiverScopeSatisfied(n.Prop("recv_package"), spec.Packages, scopePolicy) {
		continue
	}
```

Thread `scopePolicy` from a single package-level variable so Task 6 can flip it:

```go
// scopePolicy governs bare-method specs whose receiver does not resolve.
// VYQL_UNRESOLVED_RECEIVER=match relaxes it for measurement.
var scopePolicy = func() unresolvedPolicy {
	if os.Getenv("VYQL_UNRESOLVED_RECEIVER") == "match" {
		return unresolvedMatches
	}
	return unresolvedSkips
}()
```

- [ ] **Step 6: Run the end-to-end tests from Task 1**

```bash
CGO_ENABLED=1 go test -count=1 -run 'TestBareMethod' ./cmd/vyql/ -v
```

Expected: **both** PASS. `TestBareMethodDoesNotMatchForeignReceiver` now passes because
`JSON.parse` resolves to no import; `TestBareMethodStillMatchesOwnReceiver` still passes
because `serialize` resolves to `node-serialize`.

- [ ] **Step 7: Run the full suite**

```bash
CGO_ENABLED=1 go test -count=1 ./...
```

Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/extract/frontend/bindings.go cmd/vyql/receiver_scoping_test.go
git commit -m "feat(bindings): scope package-gated bare-method specs to their package"
```

---

### Task 6: Measure, choose the unresolved policy, record it

**Files:**
- Modify: `benchmarks/RESULTS.md`
- Modify: `internal/extract/frontend/bindings.go` (only if measurement overturns the default)

**Interfaces:**
- Consumes: `VYQL_UNRESOLVED_RECEIVER` from Task 5.
- Produces: a recorded measurement and a fixed policy.

- [ ] **Step 1: Build the binary**

```bash
# from the repository root
CGO_ENABLED=1 go build -o /tmp/vyql-scoped ./cmd/vyql
```

- [ ] **Step 2: Run the three protected gates**

```bash
for b in BenchmarkJava BenchmarkPython ports/owasp-js; do
  echo "== $b"
  VYQL_BENCH=1 BENCH_DIR=/tmp/bench/$b CGO_ENABLED=1 \
    go test -count=1 -v ./cmd/vyql/ -run TestOWASPBenchmark 2>&1 | grep -E 'OVERALL'
done
```

Expected: BenchmarkJava **+1.00**, BenchmarkPython **+0.90**, owasp-js **+1.00**. Any drop
is a regression — stop and investigate before continuing. Deleting these bindings entirely
cost nothing on all three, so scoping them must not cost anything either.

- [ ] **Step 3: Run RealVuln under both policies**

Each run is roughly 30 minutes over 62 repositories.

```bash
python3 benchmarks/score_realvuln.py /tmp/bench/Real-Vuln-Benchmark /tmp/vyql-scoped "$PWD/vyql" \
  | tee /tmp/rv-skip.txt | grep -A3 '^POOLED'

VYQL_UNRESOLVED_RECEIVER=match \
python3 benchmarks/score_realvuln.py /tmp/bench/Real-Vuln-Benchmark /tmp/vyql-scoped "$PWD/vyql" \
  | tee /tmp/rv-match.txt | grep -A3 '^POOLED'
```

Compare against these measured references, same corpus and same scorer:

| variant | TP | FP |
|---|---|---|
| `main` | 977 | 2530 |
| all bare-method bindings deleted | 974 | 2444 |

- [ ] **Step 4: Choose the policy**

Keep `unresolvedSkips` if it loses no more than one true positive against
`unresolvedMatches` — precision is the point of this work. Switch the default to
`unresolvedMatches` if skipping costs more than one TP, which would mean import tables are
too sparse in some frontend to scope safely. Record the actual numbers either way; do not
describe the outcome without them.

- [ ] **Step 5: Record the measurement**

Add to `benchmarks/RESULTS.md` under §6.1, replacing nothing:

```markdown
#### 6.1.1 Receiver scoping for package-gated bindings

Bindings generated for package `P` match only calls whose receiver resolves to `P`.

| VyQL at | TP | FP | Precision | Youden |
|---|---|---|---|---|
| before scoping | 977 | 2530 | 0.2786 | −0.3519 |
| after scoping | ... | ... | ... | ... |

The three protected suites are unchanged at +1.00 / +0.90 / +1.00: this class of binding
contributes nothing there, which is why the noise was invisible to the gates.
```

- [ ] **Step 6: Commit**

```bash
git add benchmarks/RESULTS.md internal/extract/frontend/bindings.go
git commit -m "docs(benchmarks): record receiver scoping against RealVuln"
```

---

### Task 7: Retire the JSON.parse whitelist if it is now redundant

**Files:**
- Modify: `vyql/bindings/javascript/deserialization.vyql`
- Modify: `vyql/tests/deser_js_safe_parsers.test.vyql`

**Interfaces:**
- Consumes: the scoping from Task 5.

PR #17 added exact-path `core.SafeDeserialization` checks for `JSON.parse`, `Date.parse`,
`url.parse` and `querystring.parse`. Those four are builtins, so scoping already excludes
them — the whitelist may now be dead weight. Confirm before removing: it is cheap
insurance if some frontend does resolve a builtin receiver to a package.

- [ ] **Step 1: Check whether the tests still pass without it**

```bash
# from the repository root
git rm --cached vyql/bindings/javascript/deserialization.vyql >/dev/null
git stash push vyql/bindings/javascript/deserialization.vyql
CGO_ENABLED=1 go test -count=1 -run 'TestBareMethod' ./cmd/vyql/ -v
```

Expected: both PASS without the whitelist. If either fails, restore it and stop —
scoping does not subsume it.

```bash
git stash pop
```

- [ ] **Step 2: If it passed, remove the now-redundant checks**

Delete only the four `core.SafeDeserialization` bindings PR #17 added, keeping any
pre-existing content of the file. Identify them with:

```bash
git log --oneline -1 --all --grep='JSON.parse' -- vyql/bindings/javascript/deserialization.vyql
git show <that-sha> -- vyql/bindings/javascript/deserialization.vyql
```

- [ ] **Step 3: Re-run the JS gate and the deserialization tests**

```bash
VYQL_BENCH=1 BENCH_DIR=/tmp/bench/ports/owasp-js CGO_ENABLED=1 \
  go test -count=1 -v ./cmd/vyql/ -run TestOWASPBenchmark 2>&1 | grep OVERALL
CGO_ENABLED=1 go test -count=1 ./... 2>&1 | tail -20
```

Expected: owasp-js **+1.00**, all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add vyql/bindings/javascript/deserialization.vyql vyql/tests/deser_js_safe_parsers.test.vyql
git commit -m "refactor(js/deser): drop the safe-parser whitelist subsumed by receiver scoping"
```

If Step 1 showed the whitelist is still needed, skip Steps 2–4 and record why in the PR
description instead.

---

## Self-review

**Spec coverage.** Receiver scoping for package-gated bindings: Tasks 2, 3, 5. Alias
divergence (`PyYAML`→`yaml`): Task 4. The unresolved-receiver decision: Task 5 implements
both, Task 6 decides by measurement. Regression protection: Task 6 Step 2. The `#17`
stopgap: Task 7. Classifier semantics (`defusedxml`, `safeParse`) is explicitly out of
scope and routed to `vyprai/vyql-internal#44`.

**Known gap, deliberate.** Task 4's alias table is hand-written and covers the common
Python divergences. It is not exhaustive across 1,183 gated packages. A package whose
distribution name differs from its import root and is missing from the table loses its
true positives silently. Task 6's RealVuln measurement is what catches that: a TP drop
larger than the −3 upper bound means the table needs more entries. If it grows past
roughly fifty entries, generate it from package metadata instead of maintaining it by hand.

**Type consistency.** `resolveReceiverPackage(string, map[string]importEntry) string` is
defined in Task 2 and called in Task 3. `importNamesForPackage(string) []string` is defined
in Task 4 and called in Task 5. `receiverScopeSatisfied(string, []string, unresolvedPolicy)
bool` is defined in Task 5 and used in the same task. `unresolvedPolicy` with
`unresolvedSkips` / `unresolvedMatches` is declared once, in Task 5. The node property is
spelled `recv_package` in Tasks 3 and 5.
