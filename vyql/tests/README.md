# VyQL test specs (`*.test.vyql`)

Declarative, language-agnostic behavior tests for the **shipped ruleset**, co-located
with the VyQL data they exercise. Each spec is a code snippet plus the rule ids it must
(`expect`) or must not (`reject`) produce when scanned by the real pipeline (all packs
in `vyql/packs`, the ontology, and every language adapter).

Adding a rule or adapter? Add a spec here — no Go test code. The runner is
`go/cmd/vyql/vyqlspec_test.go` (`go test ./cmd/vyql/ -run TestVyqlSpecs`).

## Format

```
test "short human description"
  lang   java                 # one of the supported languages (see below)
  expect VYQL-CRY-002         # repeatable — every listed rule MUST fire
  reject VYQL-INJ-001         # repeatable — every listed rule must NOT fire
  code
  ```
  class C { void f() { Cipher.getInstance("DES/CBC/PKCS5Padding"); } }
  ```
```

- A `test` block runs until the next `test` (or end of file).
- `#` / `//` lines and blank lines are ignored (outside code fences).
- Code is a triple-backtick (```` ``` ````) fenced block, captured verbatim. The `code`
  keyword before the fence is optional.
- Provide at least one `expect` or one `reject`.

### Graph specs (cloud / identity / business / runtime / SCA)

Rules that run over an asset/identity graph rather than source code (the `reach`,
`assume`, `match … where`, `transition` packs) are tested with a `graph` block instead of
`code` — same `expect`/`reject`, no `lang`. The block is a tiny line DSL compiled into a
USG store and evaluated against the shipped packs:

```
test "internet reaches a PII database (CLD-001)"
  expect VYQL-CLD-001
  graph
  ```
  node internet cloud.Internet
  node db cloud.Database { asset_kinds = data.Pii }
  edge NET internet -> db { rule = sg-pub:5432 }
  ```
```

- `node <id> <type/concept> [{ k = v, … }]` — a vertex, auto-labelled with the concept
  (props are mirrored onto the label so `asset_kinds`/`priv_level`/`image`/`dst` reach the
  right place).
- `label <id> <concept> [{ k = v, … }]` — an additional concept label on a node.
- `edge <TYPE> <src> -> <dst> [{ k = v, … }]` — a typed edge (`NET` for reach, `STEP` for
  assume, `FLOWS` for runtime taint, `CHECKS`/`PROTECTS` for guards).

These live in `graph/*.test.vyql` and run through the same `TestVyqlSpecs` runner.

### Multi-file specs

For cross-file flows (e.g. interprocedural taint), give each block a `file <name>`:

```
test "python: input crosses routes.py -> db.py into cursor.execute"
  lang python
  expect VYQL-INJ-001
  file routes.py
  ```
  from db import run_query
  def login():
      run_query(request.form['name'])
  ```
  file db.py
  ```
  def run_query(v):
      cursor.execute("SELECT * FROM users WHERE name = '" + v + "'")
  ```
```

## Languages

`go, python, javascript, ruby, java, php, csharp, c, cpp, rust, bash, scala, lua,
kotlin, powershell, swift, perl, solidity, objc` (the snippet is written to a file with
that language's extension and routed through its frontend + adapters).

## Files

| File | Covers |
|---|---|
| `weak_crypto.test.vyql` | WeakHash / WeakCipher (CRY-001/002) across languages |
| `misconfig.test.vyql` | CORS, cookie, cert, JWT, cleartext, session-fixation, CSRF (CFG-00x) |
| `injection.test.vyql` | XPath, LDAP, SSTI, EL, email-header, CSV, mass-assign, proto-pollution, ReDoS, upload, format-string, sanitizer (INJ/DOS) |
| `languages.test.vyql` | per-language SQLi / command / code-injection / smart-contract idioms |
| `interprocedural.test.vyql` | multi-file call-trace cases — framework controller → service → sink, with sanitization in the source / intermediate / sink file or from the framework, positive and negative |
| `insecure_temp_file.test.vyql` | insecure temp file (PATH-003) |

## Cross-file (interprocedural) support

The lowering resolves imports + function calls to trace taint across files. Reach, per
`interprocedural.test.vyql`:

| Language | Cross-file trace |
|---|---|
| Python, Ruby, PHP, Go | ✅ 2–3 hop chains, sanitizers in any file, framework-parameterized forms |
| Java | ✅ cross-class controller → service → repo: static calls, `new T().m()`, fields (incl. Spring `@Autowired` DI), and `@RequestParam`/handler params as sources |
| JavaScript | ✅ CommonJS `require('./x')` with `exports.fn = …`, `module.exports.fn = …`, and `module.exports = { fn: … }` |

Imported aliases resolve to their dotted paths, so both bare-imported **sinks** and
**sanitizers** are recognized — e.g. `from markupsafe import escape; escape(x)` neutralizes
like `markupsafe.escape`, and `from pathlib import Path; Path(p)` is a file-path sink.

> Note: a few engine-level checks (e.g. relative confidence tiering in
> `fidelity_test.go`) remain as Go tests because they assert on behavior that isn't a
> simple "rule fired / didn't fire" outcome.
