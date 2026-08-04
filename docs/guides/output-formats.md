# Output formats and CI

```sh
vyql scan --format text  ./src     # default, for humans
vyql scan --format json  ./src     # for scripting
vyql scan --format sarif ./src     # for code-scanning tools
vyql scan --format graph-json ./src
```

## JSON

An array of findings. Each carries its rule, severity, confidence, fingerprint,
and the source/sink bindings with locations.

```sh
vyql scan --format json ./src | jq -r '.[] | "\(.rule)\t\(.severity)"' | sort | uniq -c
vyql scan --format json ./src | jq '[.[] | select(.severity=="critical")] | length'
```

The **fingerprint** is the field to build on. It is stable across line moves, so
it works as a suppression key and as the identity for diffing.

## SARIF

SARIF 2.1.0, which GitHub code scanning and most IDEs consume directly.

```yaml
- name: VyQL
  run: vyql scan --format sarif . > vyql.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: vyql.sarif
```

Findings then appear as annotations on the pull request, with the rule metadata
and CWE mapping attached.

## Failing a build

`vyql scan` exits 0 whether or not it found anything — finding a vulnerability is
a successful scan. Decide your own threshold:

```sh
crit=$(vyql scan --format json . | jq '[.[] | select(.severity=="critical")] | length')
[ "$crit" -eq 0 ] || { echo "$crit critical finding(s)"; exit 1; }
```

A non-zero exit means the scan itself failed — unreadable path, bad rule file,
missing data directory.

## Only new findings

Failing on the total count fails forever on day one. `diff` compares two JSON
runs by fingerprint:

```sh
git stash && vyql scan --format json . > /tmp/base.json && git stash pop
vyql scan --format json . > /tmp/head.json
vyql diff /tmp/base.json /tmp/head.json
```

This is usually the right gate for an existing codebase: block what the change
introduced, and burn down the rest separately.

## graph-json

A cross-referenced export of the whole analysis — functions, call edges,
findings, and the taint path for each, plus a concept legend. Intended for
tooling that wants the graph rather than a findings list.

```sh
vyql scan --format graph-json . | jq '.code_map'
```

Sinks carry an `operation` from `vyql/exports/sink_operations.tsv`, mapping the
concept to a downstream operation vocabulary. That file currently covers 22 of
the 62 sink concepts the bindings emit; the rest export a null operation.

## Caching

Scan results are cached by default (`--cache auto`). The cache keys on the source
files **and** on the `vyql/` data, so editing a binding correctly invalidates it.

```sh
vyql scan --cache off ./src        # force a full run
```

`graph-json` and the flag outputs always run the full pipeline — the cache stores
findings, not the graph.
