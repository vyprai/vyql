# Phase 1 Heuristics Audit & Declarative Extraction Matrix

This document maps all hardcoded security and framework heuristics identified in [internal/extract/lowering/lowering.go](internal/extract/lowering/lowering.go) to their corresponding `.vyql` concepts, patterns, and bindings.

---

## Heuristics Audit Matrix

| Go Function / Heuristic | Current Trigger in `lowering.go` | Target `.vyql` Concept | Rule / Threat Class | Declarative Migration Status |
|---|---|---|---|---|
| `insecureHeaderStore` / `insecureHeaderPair` | Subscript store or `send_header`/`set_header` configuring CORS `*`, `X-Frame-Options: allowall`, `X-XSS-Protection: 0`, weak CSP, `max-age=0` HSTS | `code.InsecureHeaderConfig`, `code.PermissiveCors` | `vypr.misconfig.insecure_header`, `vypr.misconfig.cors` | Present in `vyql/ontology/concepts/code/InsecureHeaderConfig.vyql` |
| `plaintextPasswordColumn` | ORM column named `password`, `pwd`, etc., without hashing/encryption | `code.PlaintextPasswordStorage` | `vypr.crypto.plaintext_password` | Present in `vyql/ontology/concepts/code/PlaintextPasswordStorage.vyql` |
| `allowedHostsWildcard` | Assignment to `ALLOWED_HOSTS`, `CORS_ORIGIN_WHITELIST` with `['*']` | `code.PermissiveCors`, `code.InsecureHeaderConfig` | `vypr.misconfig.cors` | Present in `vyql/ontology/concepts/code/PermissiveCors.vyql` |
| `certCheckDisabled` | `check_hostname = False`, `verify_mode = CERT_NONE` | `code.CertValidationDisabled` | `vypr.crypto.cert_validation` | Present in `vyql/ontology/concepts/code/CertValidationDisabled.vyql` |
| `exposesInternalConfig` | `os.environ`, `os.getenv`, `BASE_DIR` reaching returns | `code.DebugInfoExposure` | `vypr.disclosure.debug_info` | Present in `vyql/ontology/concepts/code/DebugInfoExposure.vyql` |
| `exposesExceptionDetail` | `str(e)`, `repr(e)` in HTTP response return | `code.ErrorDetailDisclosure` | `vypr.disclosure.error_detail` | Present in `vyql/ontology/concepts/code/ErrorDetailDisclosure.vyql` |
| `exposesRecordReturn` | ORM model / database record returned directly from route | `code.DataExposureSmell` | `vypr.disclosure.data_exposure` | Present in `vyql/ontology/concepts/code/DataExposureSmell.vyql` |
| `buildsRawHTMLString` | Dynamic string concatenation embedding HTML tags returned from route | `code.RawHtmlResponse` | `vypr.injection.xss.raw_html` | Present in `vyql/ontology/concepts/code/RawHtmlResponse.vyql` |
| `isOwnershipComparison` | Comparison between `obj.owner` / `obj.user` and authenticated principal | `core.OwnershipCheck` | `vypr.access.idor` | Present in `vyql/ontology/concepts/core/OwnershipCheck.vyql` |
| `clientMarkerCompareOperand` | Comparison between client-controlled request marker and role | `code.ClientControlledSecurityDecision` | `vypr.access.client_decision` | Present in `vyql/ontology/concepts/code/ClientControlledSecurityDecision.vyql` |
| `privilegeLiteral` / `weak_authz` | Comparison against hardcoded role strings (`"admin"`, `"superuser"`) | `code.WeakAuthzSmell` | `vypr.access.weak_authz` | Present in `vyql/ontology/concepts/code/WeakAuthzSmell.vyql` |
| `catastrophicRegex` | Regex pattern with nested quantifiers or overlapping alternation | `code.CatastrophicRegex` | `vypr.dos.catastrophic_regex` | Present in `vyql/ontology/concepts/code/CatastrophicRegex.vyql` |
| `isSQLSinkCall` / `isDynamicStringExpr` | Query string built via f-string / concatenation passed to SQL executor | `code.DynamicSqlQuery` | `vypr.injection.dynamic_sql` | Present in `vyql/ontology/concepts/code/DynamicSqlQuery.vyql` |
| `isCommandSinkCall` / `isDynamicStringExpr` | Dynamically-built string passed to shell execution primitive | `code.DynamicCommandExec` | `vypr.injection.dynamic_command` | Present in `vyql/ontology/concepts/code/DynamicCommandExec.vyql` |
| `debugNamedTarget` / `debug_on` | `DEBUG = True` / `app.run(debug=True)` | `code.DebugEnabled` | `vypr.misconfig.debug_enabled` | Present in `vyql/ontology/concepts/code/DebugEnabled.vyql` |
| `enumerationErrorResponse` | Auth error messages revealing user existence (e.g., "user not found") | `code.UserEnumSmell` | `vypr.auth.user_enumeration` | Present in `vyql/ontology/concepts/code/UserEnumSmell.vyql` |
| `businessStateKey` | Assignment to sensitive fields (`state`, `role`, `balance`, `tier`) from input | `code.BusinessLogicSmell` | `vypr.business.state_tampering` | Present in `vyql/ontology/concepts/code/BusinessLogicSmell.vyql` |

---

## Verification Plan

All synthetic analysis concepts are already formally modeled in `vyql/ontology/concepts/code/` and `vyql/ontology/concepts/core/`. Declarative bindings can now target raw NIR Call/Attr nodes directly via language bindings rather than relying on synthetic analysis calls injected during lowering.
