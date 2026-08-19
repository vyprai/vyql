# Install and first scan

## Install

The convenience path installs the engine and the free definitions together:

```sh
curl -fsSL https://dl.vyprsec.ai/vyql/install.sh | sh
```

`go install` is the engine only (Go 1.26+ and a C toolchain; the parsers are C,
and without cgo the build constraints exclude them silently rather than failing):

```sh
go install github.com/vyprai/vyql/cmd/vyql@latest
curl -fsSLO https://dl.vyprsec.ai/vyql/definitions/free/latest.tar.gz
curl -fsSLO https://dl.vyprsec.ai/vyql/definitions/free/latest.tar.gz.sha256
shasum -a 256 -c latest.tar.gz.sha256
mkdir -p "$HOME/.local/share/vyql"
tar -xzf latest.tar.gz -C "$HOME/.local/share/vyql"
export VYQL_HOME="$HOME/.local/share/vyql/vyql"
```

From source:

```sh
git clone https://github.com/vyprai/vyql
cd vyql
make build      # -> bin/vyql
```

## The data directory

The binary carries no security knowledge. It loads all of it at startup from a
directory containing `ontology/`, `packs/`, `bindings/` and `taxonomy/`.

It finds that directory in this order:

1. `-data` or `$VYQL_HOME`, if set
2. a `vyql/` directory in the working directory or any ancestor
3. a `vyql/` directory next to the executable (and through a symlink, as Homebrew does)

A `go install`ed binary run from an unrelated directory has none of those, and
exits 1:

```
vyql: could not locate the data directory; go install installs the engine only
```

Install with `install.sh`, Homebrew, Docker, or a release archive; or unpack the
free bundle from `https://dl.vyprsec.ai/vyql/definitions/free/latest.tar.gz` and
set `$VYQL_HOME` to that `vyql/` directory.

Check what loaded:

```sh
vyql definitions -kind all
# loaded: concepts=858 rules=728 bindings=31537 reviews=552
```

Those counts are worth a glance. A number near zero means the directory is wrong
or partial, and a scan against a partial knowledge base **finds less without
telling you** — it does not error.

## Scan

```sh
vyql scan ./my-project
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

Reading it:

- **`[P3] [HIGH]`** — priority and severity. Priority folds in the analysis profile.
- **`conf=medium`** — how sure the engine is that the source and sink are what it
  thinks. A syntactic match is lower confidence than a resolved one.
- **`fp=...`** — a stable fingerprint. It survives line moves, so you can suppress
  or diff on it.
- **`source` / `sink`** — what was found, where, and which binding labelled it.
- **`unless ...: not satisfied`** — the controls that would have made this safe,
  and the fact that none were found. This is the part most tools omit.

## Profiles

The profile changes prioritisation, not detection: a hardcoded credential matters
more in a deployed API than in a CLI tool.

```sh
vyql scan --profile api ./my-project
vyql scan --profile library ./my-project
```

`auto` detects from the project's shape and is the default. `vyql scan -h` lists
the rest.

## Speed

Two things dominate a slow scan, and both are usually content you did not mean to
scan:

```sh
vyql scan --exclude node_modules,vendor,_vendor,testdata ./my-project
vyql scan --stats ./my-project      # per-phase timing and node counts
```

Large generated files are the common surprise — a vendored parser or a bundled
minified library can cost more than the entire rest of a repository.

## Next

- [Output formats and CI](output-formats.md)
- [Why did this fire, or not?](debugging-findings.md)
