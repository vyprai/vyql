# Application threat-model profiles

A **profile** makes VyQL's analysis context-aware. The same code carries different risk
depending on what kind of application it is — so a profile declares, per archetype:

- **the trust boundary** — `entrypoints:` lists the source families that count as
  attacker-controlled (e.g. a CLI's argv/env, a browser's DOM, an Android app's intents);
- **auto-detection predicates** — `detect:` uses v2 project-fact requirements such as
  `dependency("express")`, `file("openapi.yaml")`, and `project.has("ext:.tsx")`.

The scanner picks a profile with `--profile <name>`, or on `--profile auto` (the default)
fingerprints the project and chooses one. The chosen profile **gates source labelling**:
only its `entrypoints` source families produce taint, so a CLI scan never treats HTTP
params as attacker input, a server scan never treats argv as attacker input, etc. The
`generic` profile is a permissive union used when nothing is detected.

## The detection vocabulary — `projectfacts.vyql`

A profile says *which* facts identify its archetype. `policy projectFacts default` says
*what each fact means*: which manifests `dependency()` searches, what a `language()` name
is on disk, what makes a directory the project root, what a satisfied predicate is worth
when profiles are ranked, and how each `project.has("…")` fact is decided.

Adding an ecosystem is an edit there, not a Go change. Two things are worth knowing before
you make one:

- **The weights are relative.** A `fact:` is worth 2 and everything else 1, deliberately: a
  repository can depend on express *and* ship as a library, and the library reading is
  meant to win. Changing a weight re-ranks every profile against every other one.
- **`project.has("x")` must name a declared fact** (or an extension, `ext:.tsx`). One that
  names neither scores zero forever, so its profile silently stops competing — `vyql scan`
  prints a warning, and `TestShippedProjectFactsAreComplete` fails.

## Archetypes

| Profile | Trust boundary (entry points) | Detect |
|---|---|---|
| `generic` | permissive union (HTTP, process inputs, DB/external reads) — browser/mobile sources OFF | fallback |
| `web` | HTTP request: params/headers/cookies/body/uploads | flask/django/rails/express/laravel/spring |
| `api` | HTTP request + tokens | fastapi/nestjs/gin/grpc, openapi.* |
| `frontend` | DOM: `location`/hash/referrer/`window.name`/web-storage/`document.cookie` | react/vue/angular/svelte, .jsx/.vue |
| `cli` | argv, env, stdin, config files | cobra/click/argparse/clap/commander |
| `mobile_android` | intent extras, deep-link URIs (+ DB/network) | AndroidManifest.xml, build.gradle android |
| `mobile_ios` | pasteboard, URL schemes (+ DB/network) | Info.plist, *.xcodeproj, Package.swift |
| `electron` | IPC, files, protocols (+ the renderer config surface) | electron, electron-builder |
| `library` | any public-API param + external data | setup.py/pyproject, rollup/tsup |
| `worker` | message-queue payloads, webhooks, file drops | celery/sidekiq/bull/kafkajs/sqs |

## Archetype-specific detection (beyond the shared injection/crypto/config rules)

- **frontend** — DOM-XSS (`innerHTML`/`document.write`/`eval`/Angular `bypassSecurityTrust*`),
  location-based open redirect, `eval(location.*)` code injection.
- **mobile (Android/iOS)** — WebView injection (`loadUrl`/`evaluateJavaScript`/`loadHTMLString`,
  VYQL-MOB-001), `addJavascriptInterface` bridge exposure (MOB-002), intent/pasteboard → local
  SQLite / command / file.
- **electron** — insecure renderer config (`nodeIntegration:true` / `contextIsolation:false`,
  VYQL-DSK-001), `shell.openExternal`.

## Known gaps (deferred, with reason)

- **Manifest / plist config** (Android `exported`/`usesCleartextTraffic`, iOS ATS
  `NSAllowsArbitraryLoads`) — VyQL has no XML/plist frontend yet.
- **Delegate-param sources** (iOS `application(_:open:)` URL, `WKScriptMessageHandler`,
  Electron `ipcMain.on` handler arg, FastAPI/NestJS param-decorator binding) — these arrive
  as callback/handler parameters and need label/type-aware param seeding to source without
  false positives.
- **Severity weighting by profile** — the profile gates the trust boundary and labels the
  threat model; per-context severity re-scoring is not yet wired (low value vs. effort).
