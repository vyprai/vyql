# Install and first scan

## Install

VyQL needs Go 1.26+ and a C toolchain — the parsers are C, and without cgo the
build constraints exclude them silently rather than failing.

```sh
go install github.com/vyprai/vyql/cmd/vyql@latest
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

It finds that directory in one of two ways:

1. `$VYQL_HOME`, if set
2. otherwise, a `vyql/` directory in the working directory or any ancestor

A `go install`ed binary run from an unrelated directory has neither, and says so:

```
could not locate the data directory; set $VYQL_HOME to the path of your `vyql/` dir
```

Point it at the `vyql/` from a clone:

```sh
export VYQL_HOME=/path/to/vyql/vyql
```

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
