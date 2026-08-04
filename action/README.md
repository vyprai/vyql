# VyQL scan action

Runs a VyQL scan in GitHub Actions, fails the build on what it finds, and puts
the results in the Security tab.

```yaml
- uses: vyprai/vyql/action@v0.2.0
```

That is the whole minimal usage. It scans the checked-out repository, fails on
any HIGH or CRITICAL finding, and uploads SARIF to code scanning.

## A complete workflow

```yaml
name: security
on: [push, pull_request]

jobs:
  vyql:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write     # required for the SARIF upload
    steps:
      - uses: actions/checkout@v5
      - uses: vyprai/vyql/action@v0.2.0
        with:
          path: .
          fail-on: high
```

## Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Path to scan, relative to the workspace |
| `version` | `latest` | VyQL release to use, e.g. `v0.2.0`. Pin it for reproducible runs |
| `fail-on` | `high` | Fail at or above this severity: `none`, `info`, `low`, `medium`, `high`, `critical` |
| `exit-code` | `1` | Status used when `fail-on` is met |
| `format` | `sarif` | `sarif`, `json` or `text` |
| `output` | `vyql-results.sarif` | File to write to. Empty writes to the log |
| `exclude` | | Comma-separated path segments to skip, e.g. `vendor,node_modules` |
| `profile` | `auto` | Analysis profile |
| `upload-sarif` | `true` | Upload to code scanning |
| `working-directory` | `.` | Directory to run from |

## Outputs

| Output | What it is |
|---|---|
| `results-file` | Path to the report that was written |
| `findings` | Number of findings reported |
| `exit-code` | The scanner's status. `0` means nothing met the threshold |

## Report without failing

```yaml
- uses: vyprai/vyql/action@v0.2.0
  with:
    fail-on: none
```

Findings still reach the Security tab; the build stays green. Useful for
adopting the scanner on a codebase with a backlog.

## Telling findings apart from a broken scan

Both exit 1 by default. Give findings their own status if the difference
matters:

```yaml
- uses: vyprai/vyql/action@v0.2.0
  id: scan
  with:
    exit-code: "3"
```

`3` means findings met the threshold, `1` means VyQL could not complete the
scan, `2` means it was invoked incorrectly.

## Requirements

**Linux and macOS runners.** VyQL publishes `linux/amd64`, `linux/arm64`,
`darwin/amd64` and `darwin/arm64`. On Windows the action fails with that
message rather than something obscure.

**`security-events: write`** for the SARIF upload. On a *private* repository
that upload also needs GitHub Advanced Security; without it the upload step
fails while the scan result still stands, because the step is
`continue-on-error`. Set `upload-sarif: false` to skip it.

**VyQL v0.2.0 or newer.** The action passes `-fail-on` and `-exit-code`, which
earlier builds do not have.

## What it does

Downloads the release archive for the runner's platform, verifies its published
SHA-256, extracts it, and runs the scan with `VYQL_HOME` pointed at the data
directory that shipped with that exact binary — so a `vyql/` directory in the
repository being scanned cannot change the result.

The archive is cached by exact version. A repeat run on the same version skips
the download and the extraction, which is most of the wall clock: the archive is
about 14 MB compressed and 200 MB extracted, nearly all of it the security
knowledge base.
