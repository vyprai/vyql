# vyqld — HTTP service wrapper for the vyql scanner

`vyqld` is a thin HTTP front end over the `vyql` CLI. It does **no analysis of
its own**: each request lands source code on local disk (uploaded archive, git
clone, or a server-local path), runs `vyql scan -format <fmt>`, and streams the
scanner's output back. The engine stays a black box, so the scanner can be
rebuilt or its `vyql/` data updated without touching the service.

## Build

```sh
cd go
go build -o /tmp/vyql  ./cmd/vyql      # the scanner
go build -o /tmp/vyqld ./cmd/vyqld     # the service
```

## Run

```sh
/tmp/vyqld -bin /tmp/vyql -home /path/to/vyql/data -addr :8080
```

`-home` is the `VYQL_HOME` data directory (the repo's `vyql/` folder). All flags
have env equivalents — see the doc comment in `main.go`.

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `-addr` | `VYQLD_ADDR` | `:8080` | listen address |
| `-bin` | `VYQL_BIN` | `vyql` (PATH) | scanner binary |
| `-home` | `VYQL_HOME` | — | scanner data dir |
| `-max-concurrency` | `VYQLD_MAX_CONCURRENCY` | `NumCPU` | in-flight scans |
| `-scan-timeout` | `VYQLD_SCAN_TIMEOUT` | `5m` | per-scan timeout |
| `-max-upload` | `VYQLD_MAX_UPLOAD` | `256MiB` | max archive bytes |
| `-allow-local-path` | `VYQLD_ALLOW_LOCAL_PATH` | `false` | permit `path` mode |

## Endpoints

### `GET /healthz`
Returns resolved config and `{"status":"ok"}`.

### `POST /scan`
Three input modes; all accept an optional `profile` and `format`
(`json` default, `sarif`, or `text`).

**Archive upload** (`multipart/form-data`, field `archive` — `.tar.gz`/`.tgz`/`.zip`):
```sh
tar -czf src.tgz -C /my/project .
curl -X POST localhost:8080/scan -F archive=@src.tgz -F format=json
```

**Git clone** (`application/json`):
```sh
curl -X POST localhost:8080/scan -H 'Content-Type: application/json' \
  -d '{"git_url":"https://github.com/org/repo","ref":"main"}'
```

**Server-local path** (`application/json`, requires `-allow-local-path`):
```sh
curl -X POST localhost:8080/scan -H 'Content-Type: application/json' \
  -d '{"path":"/srv/code/project"}'
```

## Notes & limits

- **Concurrency** is bounded by a semaphore; excess requests wait, and a
  cancelled client frees its slot. Scans are CPU-heavy — size `-max-concurrency`
  to the host.
- **Isolation** is process-level: a crash or pathological input kills one scan,
  not the service. Each request unpacks into its own temp dir, removed on
  completion.
- **Archive safety**: path-traversal (`zip-slip`) entries are rejected; symlinks
  in tarballs are skipped.
- **Git**: shallow clone with credential prompts disabled
  (`GIT_TERMINAL_PROMPT=0`); private repos need credentials wired into the host's
  git environment.
- **Performance**: because this wraps the CLI, the ontology and rule packs are
  re-parsed and re-compiled on every request. If that overhead matters, promote
  the scan path into an importable package and compile rules once at startup
  (the "Option 2" library refactor).
- **Platform**: the Linux binary cannot scan Dart/Elixir/Groovy (darwin-only
  precompiled grammars), same as the CLI.
