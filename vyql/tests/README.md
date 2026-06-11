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

The lowering resolves imports + function calls to trace taint across files. Current
reach, per `interprocedural.test.vyql`:

| Language | Cross-file trace |
|---|---|
| Python, Ruby, PHP, Go | ✅ full — 2–3 hop chains, sanitizers in any file, framework-parameterized forms |
| JavaScript | 🟡 partial — `module.exports = { … }` object methods resolve; bare `exports.fn = function` does not |
| Java | 🚫 cross-class method calls (controller → service → repo) are not yet traced |

Known sanitizer-resolution gap: a bare `from pkg import fn; fn(x)` alias is not mapped to
the dotted control name (`pkg.fn`), so use the dotted form (`import pkg; pkg.fn(x)`) for
sanitizers in specs.

> Note: a few engine-level checks (e.g. relative confidence tiering in
> `fidelity_test.go`) remain as Go tests because they assert on behavior that isn't a
> simple "rule fired / didn't fire" outcome.
