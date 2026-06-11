# Application threat-model profiles

A **profile** makes VyQL's analysis context-aware. The same code carries different risk
depending on what kind of application it is — so a profile declares, per archetype:

- **the trust boundary** — `entrypoints:` lists the source families that count as
  attacker-controlled (e.g. a CLI's argv/env, a browser's DOM, an Android app's intents);
- **auto-detection fingerprints** — `detect:` lists `dep:<x>` (a dependency in
  package.json/go.mod/etc.), `file:<rel>` (a marker file), or `ext:<.x>` (a file extension).

The scanner picks a profile with `--profile <name>`, or on `--profile auto` (the default)
fingerprints the project and chooses one. The chosen profile **gates source labelling**:
only its `entrypoints` source families produce taint, so a CLI scan never treats HTTP
params as attacker input, a server scan never treats argv as attacker input, etc. The
`generic` profile is a permissive union used when nothing is detected.

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
| `electron` | IPC, files, protocols (+ the renderer config surface) | dep:electron, electron-builder |
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
