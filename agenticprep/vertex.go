package agenticprep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/vyprai/vyql/extract/sca"
	"golang.org/x/oauth2/google"
)

type VertexConfig struct {
	Project         string
	Location        string
	Model           string
	CredentialsFile string
	Temperature     float64
	Timeout         time.Duration
	StepTimeout     time.Duration
	ContextCache    bool
	ContextCacheTTL time.Duration
	Debug           bool
}

type VertexProvider struct {
	project         string
	location        string
	model           string
	temperature     float64
	stepTimeout     time.Duration
	contextCache    bool
	contextCacheTTL time.Duration
	debug           bool
	http            *http.Client
	token           func(context.Context) (string, error)
}

func NewVertexProvider(ctx context.Context, cfg VertexConfig) (*VertexProvider, error) {
	if cfg.Location == "" {
		cfg.Location = "global"
	}
	if cfg.Model == "" {
		cfg.Model = "gemini-3.5-flash"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 90 * time.Second
	}
	if cfg.StepTimeout == 0 {
		cfg.StepTimeout = 75 * time.Second
	}
	if cfg.ContextCacheTTL == 0 {
		cfg.ContextCacheTTL = time.Hour
	}
	const scope = "https://www.googleapis.com/auth/cloud-platform"
	var creds *google.Credentials
	if strings.TrimSpace(cfg.CredentialsFile) != "" {
		data, err := os.ReadFile(cfg.CredentialsFile)
		if err != nil {
			return nil, err
		}
		creds, err = google.CredentialsFromJSON(ctx, data, scope)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		creds, err = google.FindDefaultCredentials(ctx, scope)
		if err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(cfg.Project) == "" {
		cfg.Project = creds.ProjectID
	}
	if strings.TrimSpace(cfg.Project) == "" {
		return nil, errors.New("agentic prep: vertex project is required")
	}
	ts := creds.TokenSource
	return &VertexProvider{
		project:         cfg.Project,
		location:        cfg.Location,
		model:           cfg.Model,
		temperature:     cfg.Temperature,
		stepTimeout:     cfg.StepTimeout,
		contextCache:    cfg.ContextCache,
		contextCacheTTL: cfg.ContextCacheTTL,
		debug:           cfg.Debug,
		http:            &http.Client{Timeout: cfg.Timeout},
		token: func(ctx context.Context) (string, error) {
			tok, err := ts.Token()
			if err != nil {
				return "", err
			}
			return tok.AccessToken, nil
		},
	}, nil
}

func (p *VertexProvider) ProposeOverlay(ctx context.Context, profile Profile) (Proposal, error) {
	payload, err := json.Marshal(profile)
	if err != nil {
		return Proposal{}, err
	}
	p.debugf("start languages=%v packages=%d dep_gaps=%d samples=%d", profile.Languages, len(profile.Packages), len(profile.DepGaps), len(profile.Samples))
	prompt := `You are a repo-local VyQL adapter preparation agent.

Use tools to inspect bounded repo evidence, then call finish_overlay.

Rules:
- Generate only adapter declarations for languages present in the profile.
- The profile may include programmatic_findings. Those are already handled by
  deterministic prep before the LLM runs. Do not recreate adapters for the same
  evidence path and concept. Use the LLM only for dependency semantics, trust
  boundaries, framework APIs, or repo-local security meaning that the
  deterministic layer did not already identify.
- Use explicit package-scoped adapter blocks only for third-party dependency
  APIs with import/manifest evidence. This is locality for the proposed
  mapping, not a concept-level package gate. Do not package-gate first-party
  workspace crates/modules/binaries from local manifests such as Cargo.toml
  [package] names. Example:
  adapter python {
    package "fastapi-sso" {
      source param -> code.ExternalEntryInput
      sink path "RedirectResponse" arg 0 -> code.RedirectTarget
    }
  }
- Keep mappings conservative and selector-backed.
- Do not wrap exact analysis.function.context, analysis.module.context, or
  analysis.class.context marks in package blocks. Those marks are already
  localized by exact repo evidence; put dependency evidence in the adapter file
  evidence list instead of creating a package gate.
- For first-party/local project APIs, prefer generalized API mappings already
  meaningful across projects, narrow analysis.function.context marks, or an
  empty overlay with notes. Empty-overlay notes must explicitly say whether a
  core scan concept/rule already covers the relevant surface, or whether no
  validated adapter target exists. Do not create adapters whose only locality
  is a local command, binary, crate, module, controller, or utility package name.
- Adapter source must be valid VyQL DSL, for example:
  adapter python {
    source "request.args" -> code.HttpInput
    sink path "open" -> code.FilePathAccess
  }
- Valid sink syntax puts arg after the quoted pattern:
  sink path "do_cmd" arg 2 -> code.CommandExecution
  sink path "do_local_cmd" arg 0 -> code.CommandExecution
  sink path "run" arg all -> code.CommandExecution
- For libraries/frameworks, public API parameters may be marked as external
  entry input only when the same overlay also adds a concrete sink, mark, or
  control that gives those parameters security meaning. Do not submit a
  source-only source param overlay; the validator rejects broad entry-point
  expansion. If source-only parameter expansion is the best available idea,
  call finish_overlay with no adapter files and explain the missing concrete
  security mapping.
- For repo-local anti-patterns that need context instead of taint, use an
  exact analysis mark with existing review concepts:
  mark exact "analysis.function.context" val "name=orderBy" val "$direction" val "processOrderBy" nval "QUERY_ORDER_DESC" -> code.UnparameterizedSqlQueryParser
  mark exact "analysis.function.context" val "name=verify_and_process" val "request.query_params.get(\"state\")" nval "request.cookies.get(\"sso_state\")" -> code.ProtocolStateReview
- Invalid syntax examples: sink arg 2 "do_cmd" -> ...,
  sink "do_cmd" -> concept:, sink path "do_cmd" concept: ...
- Do not put JSON/YAML/object fields such as concept:, confidence:, evidence:,
  rationale:, or selectors: inside the adapter source string.
- Do not generate rules, ontology, CWE metadata, or prose outside JSON.
- If evidence is insufficient, call finish_overlay with an empty adapter_files
  array and notes explaining why.
- Do not map generic standard library APIs unless the repo evidence shows a
  project/framework-specific meaning that shipped adapters cannot know.
- Prefer repo-specific wrappers, public API boundaries, and narrow context
  marks over broad generic mappings. If a CVE shape is visible in one function
  and existing concepts already describe it, a narrow mark exact overlay is
  usually better than trying to invent a source/sink flow.
- Do not broaden an entire package just because it handles requests, protocols,
  plugins, controllers, or model objects. Generated adapters should identify a
  specific framework API, wrapper, sink, sanitizer/control, or narrow context
  mark. Broad source-only overlays tend to increase noise without improving
  scan precision.
- Before writing mark exact "analysis.function.context", call function_context
  for the target function and choose val/nval substrings from that returned
  single function context. Do not combine vals from different functions. For Go
  function contexts, use the returned suggested_vals token
  function_name:<Name>; do not use name=<Name>, which is not emitted by the Go
  frontend and will not match.
- Before writing mark exact "analysis.module.context", call module_context
  for the target file and choose val/nval substrings from one returned top-level
  declaration context. Use this for static role, permission, route, or policy maps.
- Before writing mark exact "analysis.class.context", call class_context
  for the target class and choose val/nval tokens from one returned class
  context. Prefer structured tokens such as class_name:, class_base:,
  function_name:, call_path:, and annotation: over loose source-text substrings.
- For scan catch-rate work, prefer concepts with surface=scan from
  concept_reference. surface=review_only can be useful for review/ATTENTION,
  but it will not make vyql scan emit a finding unless a scan rule matches it.
- Once validate_overlay returns ok=true with at least one valid adapter, call
  finish_overlay immediately unless a specific validation warning requires a
  correction.
- Prefer repo_structure, symbol_inventory, call_inventory, search_context, and read_files over repeated
  single-file reads. Use symbol_inventory to map classes/functions/methods, then
  call_inventory and assignment_inventory to find API callers, state writes,
  config/trust-boundary updates, and persistent display fields before opening
  exact files. Use read_file only when one exact file or offset is needed.
- Prefer this workflow:
  1. inspect_profile
  2. trust_model and entrypoint_inventory to understand the repo archetype,
     active trust boundary, request/API/CLI/config surfaces, and whether prep
     should mostly adjust scan configuration rather than adapters.
  3. adapter_coverage, then dependency_gaps. The returned gaps are ranked by deterministic security
     score and may include recommended_probe. If any gap is returned, call
     probe_dependency on recommended_probe before security_relevant_files,
     search_text, or read_file. Prefer dependencies that appear in request handling,
     parsing, upload, auth/session, redirect, command, filesystem, template,
     database, crypto, XML, archive, or network code.
  4. repo_structure for unfamiliar repositories, then adapter_reference,
     package_reference, and concept_reference
  5. security_relevant_files, then symbol_inventory, call_inventory,
     assignment_inventory, list_files,
     search_context, or search_text for exact wrappers/routes/config. Use
     symbol_inventory before opening many files just to discover class, method,
     or function names; use call_inventory to find security API call sites and
     their enclosing declarations; use assignment_inventory to find raw values
     assigned into model/entity/config/session/permission/title/name/path/url
     fields and to compare nearby escaping/sanitization assignments. For PHP
     and similar ecosystems, include helper
     files such as .inc/.phtml and search command sinks plus restore/import,
     upload, archive, and filename flows. For Java/C#/server frameworks,
     inspect lifecycle/concurrency files containing ThreadLocal, request/session
     context, begin/end, activate/deactivate, associate/dissociate, cache set,
     or cleanup/remove before chasing unrelated example SQL/deserialization code.
     For authz/data-model CVEs, inspect public methods returning relationship,
     resource, field, permission, or metadata lists and look for missing enabled,
     access, ownership, or visibility checks before returns.
     For privilege/permission CVEs, inspect static role, group, route, policy,
     and permission maps such as PermissionsByRole, roles, grants, ACLs, backup,
     restore, admin, manager, operator, or support-bundle permission lists.
     Also inspect privileged identity parsers that parse UID, GID, user, group,
     role, or capability values into zero-initialized process/security structs.
     If a parser can return on a delimiter/end-of-string check before assigning
     the parsed UID/GID/role into the target struct, use function_context and a
     narrow scan mark such as code.ParsedUserIdDefaultRootPrivilegeEscalation.
     For filesystem permission and secret-storage shapes, inspect functions
     that write private keys, credentials, tokens, kubeconfigs, cloud-init,
     ignition, or other boot/config artifacts and check for chmod, mode,
     set_permissions, or setPosixFilePermissions hardening in the same context.
     For command-wrapper CVEs, inspect wrappers and services named execute,
     run, process, command, shell, CmdExecuteService, ProcessExecutor, or
     generateDerivativeResponse. Check whether request headers, query/body
     values, paths, or args are interpolated into one command string before a
     wrapper execute call. Prefer argv arrays, process builders, or explicit
     shell escaping as hardening evidence; use function_context before proposing
     a narrow command-string wrapper mark. Do not model generic execute wrappers
     as code.CommandExecution sinks when the safe form is an argv array; that
     catches fixed code. Prefer code.CommandStringWrapperExecution exact context.
     CommandStringWrapperExecution exact marks must include an nval for the
     fixed form, such as $Env:, cmdEnv, argv array, process builder, execFile,
     or array_merge; otherwise the overlay will catch patched code.
     For Go/Windows PowerShell wrappers, inspect functions and calls named
     RunPowershellCmd, powershell, -Command, fmt.Sprintf, Get-Volume,
     Get-Item, Add-PartitionAccessPath, and Remove-PartitionAccessPath. If a
     parameter such as volumeID, path, mountpath, linkpath, or drivepath is
     interpolated into a PowerShell command string before RunPowershellCmd,
     prefer a narrow code.CommandStringWrapperExecution function_context mark
     with nvals for fixed hardening such as $Env: variables or
     RunPowershellCmd(cmd, cmdEnv...). Do not finish empty merely because
     os/exec.Command is a core sink; local string-command wrappers usually need
     an exact context mark to distinguish vulnerable string interpolation from
     fixed env/argv forms.
     For CLI option-taking commands such as gpg, git, tar, ssh, curl, unzip,
     or package managers, do not treat shell escaping alone as sufficient.
     escapeshellarg, shlex.quote, Shellwords.escape, or similar APIs prevent
     shell metacharacter injection, but an attacker value beginning with "-"
     can still be parsed as a command option unless the command inserts "--"
     before positional user arguments or validates an option allowlist. Search
     operation/argument assembly, call function_context for the builder, and
     prefer a narrow code.CommandOptionInjection mark with an nval for the fixed
     "--" delimiter or argv/allowlist hardening. CommandOptionInjection is a
     scan mark, not a taint-only sink; do not finish empty merely because a
     library has no HTTP/request source if the command builder itself has the
     missing delimiter pattern. Public API parameters and CLI/library wrapper
     arguments are sufficient context for this mark.
     For MCP server repositories, treat server.tool callback parameters as
     externally supplied tool input. Inspect @modelcontextprotocol/sdk imports,
     McpServer construction, server.tool schemas such as z.number/string/object,
     and child_process exec/execFile calls inside tool handlers. If a tool
     handler interpolates callback parameters into shell command templates,
     prefer a narrow function_context mark to code.McpToolCommandTemplateExecution
     with execFile or argv-array calls as hardening evidence. If the
     framework call that establishes the tool boundary is outside the handler
     body, call module_context and use a narrow analysis.module.context mark
     containing both server.tool and the command templates. MCP command marks
     must include concrete exec command-template vals and an nval for fixed
     hardening such as execFile or argv arrays; schema-only marks like
     server.tool plus z.number are too broad and will catch fixed code. Do not
     finish empty merely because child_process.exec is already a core command sink.
     For archive or filesystem-image extraction CVEs, inspect directory entry
     names read from image/archive buffers before mkdir, open, write, recursive
     expand, or extraction calls. In C, prioritize functions and calls named
     do_directory, expand_fs, romfs_read, namelen, dirent, readdir, extract,
     unpack, mkdir, open, and memcpy into path buffers. Check for explicit
     rejection of ".", "..", path separators, absolute paths, and traversal
     components before recursive extraction or filesystem writes. Prefer a
     narrow function_context mark for local parser/extractor ordering bugs.
     For manual Go zip extraction, inspect zip.OpenReader/NewReader loops that
     join f.Name into a destination path and call os.OpenFile with os.O_TRUNC.
     If the patch adds os.Stat plus a GetInput/confirmation prompt before
     truncation, prefer a narrow ManualZipEntryFileWrite function-context mark
     with nvals for os.Stat/GetInput rather than a broad path sink.
     For request-body resource DoS in Go or similar HTTP servers, inspect
     functions that derive allocation sizes from request ContentLength or
     Content-Length and then use make/read-full/read-all body buffering.
     Fixed forms usually use io.LimitReader, http.MaxBytesReader, explicit
     max body size defaults, read deadlines, or oversized-body drop/partial
     actions. If the vulnerable shape is generic stdlib behavior already
     represented by code.LengthDerivedAllocation, prefer noting the base
     scanner concept over emitting a repo-local overlay.
     For secure-cookie CVEs, inspect functions and methods that call SetCookie,
     http.SetCookie, response cookie helpers, or framework cookie wrappers while
     a Secure option/field/flag exists nearby. If a token, session, CSRF, auth,
     or credential cookie is set with a literal false secure argument, or a
     cookie object has Secure:false, prefer code.InsecureCookie. Use
     function_context and a narrow analysis.function.context mark when the
     insecure value is positional in a framework wrapper; include an nval for
     the fixed option/field such as opt.Secure, Secure: true, or setSecure(true).
     Do not finish empty merely because net/http cookies are standard library
     concepts; local/framework SetCookie wrappers often need adapter context.
     For token, webhook secret, API key, BasicAuth, CSRF, password, or signature
     comparison side-channel CVEs, inspect validation functions that compare an
     attacker-supplied candidate to stored/generated secret material using ==,
     ===, equals, or string comparison helpers. Prefer code.SecretComparisonReview
     with nvals for constant-time helpers such as scmp, timingSafeEqual,
     crypto.timingSafeEqual, subtle.ConstantTimeCompare, MessageDigest.isEqual,
     or hmac.compare_digest. Use function_context for local validate/check
     functions and do not finish empty unless core scan coverage for
     SecretComparisonReview/VYQL-CRY-006 is explicitly applicable.
     For upload XSS CVEs, inspect upload services/helpers that derive extensions
     from client filenames or MIME types and store SVG, HTML, or XML-capable files;
     check for SVG/XML sanitizers before storeAs/move/save/write.
     For stored/reflected XSS or output-encoding gaps, inspect title/name/label/html/body/content
     assignments and rendering/snapshot paths. Use assignment_inventory with
     name_contains values such as title, name, html, body, content, snapshot,
     encode, escape, and sanitize; then call function_context before proposing
     a narrow analysis.function.context mark.
     For sensitive data exposure through JSON/API responses, inspect model
     serialization helpers such as asModelSuccess, serialize, toArray, fields,
     extraFields, modelName, response.data, asJson, and getAcceptsJson. Full
     user/account/model objects returned through JSON success helpers are more
     important than adjacent redirect or request-parameter APIs. Use
     function_context and narrow context marks for local model serialization
     shapes; do not substitute redirect adapters for model exposure evidence.
     For Jenkins credential/provider startup CVEs, inspect classes named
     SystemCredentialsProvider, CredentialsProvider, or CredentialsStore that
     read credentials.xml, call XmlFile.unmarshal, or migrate persisted
     DomainCredentials. Check whether the same class has an @Initializer after
     InitMilestone.JOB_LOADED that force-loads getInstance() under SYSTEM during
     startup. If missing, call class_context for SystemCredentialsProvider and
     prefer a narrow analysis.class.context mark to
     code.JenkinsCredentialsStartupLoadContextExposure rather than ordinary
     credential endpoint or authorization-check review concepts. Do not use
     analysis.function.context for this concept: the fixed @Initializer method
     is outside the constructor body, so function-context marks catch fixed code.
     For that concept, use minimal positive vals from class_context:
     class_name:SystemCredentialsProvider, function_name:SystemCredentialsProvider,
     call_path:xml.unmarshal, call_path:DomainCredentials.migrateListToMap,
     and function_name:getInstance. Do not add class_base:* or positive
     annotation:* vals. Use structured nvals such as annotation:Initializer or
     function_name:forceLoadDuringStartup for the hardening absence check.
     For Jenkins descriptor form-validation endpoints, inspect methods named
     doTest*, doCheck*, or doFill* that accept @QueryParameter values and then
     build a remote client/configuration or call testConnection, getProjects,
     connect, request, openConnection, or similar outbound test APIs. These
     endpoints should normally require @POST and an admin/item permission check
     such as checkPermission or hasPermission before connecting. Prefer a narrow
     function_context mark to code.JenkinsRemoteValidationMissingPostPermission
     with nvals for annotation:POST and checkPermission/hasPermission hardening;
     do not finish empty just because the remote client class is first-party.
     For server-side template injection, host-header poisoning, canonical URL,
     or request URL helper shapes, inspect helpers that call absolute URL
     builders such as absoluteUrlWithProtocol, siteUrl, urlFor, canonicalUrl,
     currentUrl, getHostInfo, getPathInfo, and request Host/X-Forwarded-Host
     accessors. Check sanitizer ordering: sanitizing a path before absolute URL
     or host expansion can reintroduce attacker-controlled host text. Prefer
     function_context over broad source/sink mappings for local ordering bugs.
     For relay, websocket, proxy, tunneling, or polling helpers, inspect explicit
     default host fallback logic that builds URLs containing tokens,
     credentials, connection metadata, or encoded upstream URLs. Do not treat
     ordinary configured API clients, URL parsing, API tokens, or token storage
     as relay exposure without hardcoded/default relay/proxy/tunnel evidence.
     If a helper uses a hardcoded third-party/default host while embedding
     token/gurl/conman/original URL metadata, call function_context and prefer a narrow
     DefaultExternalRelaySecretExposure exact mark with an nval for trusted-host
     hardening. Do not finish empty merely because URL parsing or websocket
     libraries are standard.
     For Java Bean Validation, inspect ConstraintValidator implementations and
     ConstraintValidatorContext.buildConstraintViolationWithTemplate call sites.
     That method is already a code.ExpressionEval sink in the Java adapter; do
     not finish empty solely because javax.validation is a standard framework.
     If the sink is present but scan misses, suspect source/flow/reviewer
     mechanics before adding a duplicate overlay.
     For PHP/Symfony/Pimcore repositories, treat Request parameter bags such as
     $request->query->get/all/filter and raw query-condition builders such as
     addConditionParam, whereRaw, havingRaw, orderByRaw, and selectRaw as high-priority
     source/sink candidates. Prefer executable SQL fragment arguments only; bound
     parameter value arguments should not become SQL sinks.
     For legacy PHP applications, inspect project-local SQL wrappers named
     RunQuery, queryDB, DBQuery, ExecuteQuery, or similar. If a request-derived
     value flows into a concatenated SQL string variable such as $sSQL before
     one of these wrappers, add or rely on a SQL execution sink for the wrapper
     instead of returning an empty overlay.
     For scheduler, automation, or plugin-runner repositories, inspect child
     job output handlers such as handleChildResponse, detachedJobUpdate,
     finishLocalJob, update_event, listFindUpdate, and global/schedule. If
     child/plugin JSON output can copy update_event into job state and later
     persist it to schedule/event configuration, prefer a narrow
     JobOutputEventUpdateAuthorizationBypass function-context mark with nvals
     for explicit config/delete hardening such as allow_event_updates_from_jobs
     or delete data.update_event. Do not finish empty merely because the same
     repository also uses child_process command execution. Do not anchor this
     concept only on the later listFindUpdate/storage update context; the
     patched guard may be in the earlier child-output handler, so the mark must
     include child-output copy evidence such as job[key]=data[key].
     For CORS, Origin, callback, trusted-origin, or wildcard host validators,
     call symbol_inventory with name_contains values such as origin, wildcard,
     cors, validate, and match before opening files. Inspect parsers that split,
     slice, or wildcard-match trusted origins and validators that use HasPrefix,
     startsWith, HasSuffix, regex, or glob matching before accepting request
     Origin/callback/redirect values. If the repo profile, packages, samples, or
     security_relevant_files mention these terms, finish_overlay will be rejected
     until symbol_inventory has been called.
     For signature, attestation, certificate, policy, predicate, transparency-log,
     or provenance verification, inspect the full flow from verification result to
     accepted output. Check that filtered or policy-matched subsets are non-empty
     before output/trust, and that code emits only the checked subset rather than
     the original verified collection.
     For cryptographic blinding, timing, Rabin-Williams/RW, or private-key
     operation CVEs, inspect functions and calls named CalculateInverse,
     Randomize, MultiplicativeInverse, Jacobi, Square, ModularSquareRoot,
     blind, and unblind. If a randomized blinding factor is inverted or used for
     unblinding before required subgroup/Jacobi/square hardening, call
     function_context and prefer code.CryptoImproperBlinding with an nval for
     the fixed hardening such as r = modn.Square(r) before
     MultiplicativeInverse. Do not finish empty merely because the repository is
     a standard cryptography library; these are semantic side-channel marks, not
     framework dependency adapters.
     For .NET/C# dynamic assembly loading, inspect calls such as
     AssemblyLoadContext.Default.LoadFromAssemblyPath, Assembly.LoadFrom, and
     Assembly.LoadFile. If a caller-controlled type or assembly name is split or
     concatenated with AppContext.BaseDirectory and a .dll suffix before dynamic
     loading, use code.AssemblyLoadPathTraversal or rely on shipped coverage; the
     fixed form rejects traversal and drive-qualified path components such as
     ".." and ":" before loading.
     For information-disclosure CVEs, inspect filesystem drivers and methods
     using rename/copy/unlink/touch/move_uploaded_file/readfile on absolute
     paths, especially when failures become exceptions or framework warnings;
     check for warning suppression, sanitized error handling, or path removal.
     For native memory-safety repositories in C, C++, Rust, or Swift, call
     symbol_inventory and call_inventory before broad text search or file reads.
     Focus call_inventory on allocation/copy/size terms such as alloc, malloc,
     calloc, realloc, memcpy, copy, size, length, capacity, offset, escape, and
     unicode; then open only the enclosing functions returned by inventory.
  6. read_files or read_file on exact evidence
  7. function_context before analysis.function.context marks,
     class_context before analysis.class.context marks,
     or module_context before exact marks for top-level policy/config maps
  8. validate_overlay if producing any non-empty adapter
  9. finish_overlay only after validation is clean, or empty if no useful
     repo-local adapter can improve scan.

Repo profile:
` + string(payload)
	fullPromptContents := []map[string]any{{
		"role":  "user",
		"parts": []map[string]any{{"text": prompt}},
	}}
	contents := fullPromptContents
	var cacheName string
	var log []AgentStep
	var lastValid Proposal
	var notes []string
	decisionCheckpointSent := false
	noToolCorrectionSent := false
	if p.contextCache {
		p.debugf("creating vertex context cache ttl=%s", p.contextCacheTTL)
		var err error
		cacheName, err = p.createContextCache(ctx, fullPromptContents)
		if err != nil {
			notes = append(notes, "vertex context cache unavailable: "+err.Error()+"; using uncached prompt")
			p.debugf("context cache unavailable: %v", err)
			cacheName = ""
		} else {
			notes = append(notes, "vertex context cache enabled: "+cacheName)
			p.debugf("context cache enabled name=%s", cacheName)
			contents = []map[string]any{{
				"role":  "user",
				"parts": []map[string]any{{"text": "Begin the repo-local VyQL prep workflow now."}},
			}}
		}
	}
	const maxAgentSteps = 24
agentLoop:
	for step := 1; step <= maxAgentSteps; step++ {
		p.debugf("step=%d request cached=%t turns=%d", step, cacheName != "", len(contents))
		text, calls, modelParts, finish, err := p.generateAgentStep(ctx, contents, cacheName)
		if err != nil {
			if cacheName != "" {
				notes = append(notes, "vertex context cache generate failed: "+err.Error()+"; retrying uncached")
				p.debugf("step=%d cached generate failed: %v; retrying uncached", step, err)
				cacheName = ""
				contents = fullPromptContents
				text, calls, modelParts, finish, err = p.generateAgentStep(ctx, contents, cacheName)
			}
		}
		if err != nil {
			p.debugf("step=%d error=%v", step, err)
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				notes = append(notes, "agent stopped after Vertex deadline without finish_overlay")
				return Proposal{AgentLog: log, Notes: notes}, nil
			}
			return Proposal{AgentLog: log, Notes: notes}, err
		}
		p.debugf("step=%d finish=%s text_bytes=%d tool_calls=%s", step, finish, len(text), toolCallNames(calls))
		entry := AgentStep{Index: step, Text: text, Finish: finish}
		for _, call := range calls {
			entry.ToolCalls = append(entry.ToolCalls, AgentToolCall{ID: call.ID, Name: call.Name, Arguments: call.Arguments})
		}
		if len(calls) == 0 {
			if !noToolCorrectionSent && step < maxAgentSteps {
				noToolCorrectionSent = true
				entry.ToolResults = append(entry.ToolResults, AgentToolResult{
					Name: "agent_control",
					Result: map[string]any{
						"ok":    false,
						"error": "no tool call returned; continue with the required inventory workflow or call finish_overlay explicitly",
					},
				})
				if len(modelParts) > 0 {
					contents = append(contents, map[string]any{"role": "model", "parts": modelParts})
				}
				contents = append(contents, map[string]any{
					"role": "user",
					"parts": []map[string]any{{
						"text": "No tool call was returned. Continue by calling the next required inventory tool, validate_overlay, or finish_overlay explicitly. Do not end the workflow with plain text.",
					}},
				})
				log = append(log, entry)
				p.debugf("step=%d no tool call; sent corrective prompt", step)
				continue agentLoop
			}
			proposal := Proposal{AgentLog: append(log, entry), Notes: append([]string{}, notes...)}
			if strings.TrimSpace(text) != "" {
				if err := json.Unmarshal([]byte(text), &proposal); err == nil {
					proposal.AgentLog = append(log, entry)
					proposal.Notes = append(notes, proposal.Notes...)
				} else {
					proposal.Notes = append(proposal.Notes, "agent returned text without finish_overlay tool call")
				}
			} else {
				proposal.Notes = append(proposal.Notes, "agent returned no tool calls without finish_overlay")
			}
			return proposal, nil
		}
		resultParts := make([]map[string]any, 0, len(calls))
		for _, call := range calls {
			if call.Name == "finish_overlay" {
				proposal, warn := proposalFromToolArgs(call.Arguments)
				if warn != "" {
					proposal.Notes = append(proposal.Notes, warn)
				}
				needsSymbols := requiresSymbolInventory(profile)
				requiredCallTerms := requiredCallInventoryTerms(profile)
				needsAssignments := requiresAssignmentInventory(profile)
				requiredAssignmentTerms := requiredAssignmentInventoryTerms(profile)
				missingRequiredSymbols := needsSymbols && !agentLogHasTool(log, "symbol_inventory")
				missingRequiredCalls := needsSymbols && !agentLogHasTool(log, "call_inventory")
				missingFocusedCalls := len(requiredCallTerms) > 0 && !agentLogHasCallInventoryTerm(log, requiredCallTerms)
				missingRequiredAssignments := needsAssignments && !agentLogHasTool(log, "assignment_inventory")
				missingFocusedAssignments := needsAssignments && len(requiredAssignmentTerms) > 0 && !agentLogHasAssignmentInventoryTerm(log, requiredAssignmentTerms)
				validationWarnings := []string(nil)
				validAdapterCount := 0
				if warn == "" && !missingRequiredSymbols && !missingRequiredCalls && !missingFocusedCalls && !missingRequiredAssignments && !missingFocusedAssignments {
					filtered, warnings := FilterValidProposal(profile, proposal, Config{})
					validationWarnings = warnings
					validAdapterCount = len(filtered.AdapterFiles)
				}
				emptyJenkinsStartupOverlay := jenkinsCredentialStartupProfile(profile) && validAdapterCount == 0 && len(proposal.AdapterFiles) == 0
				emptyJenkinsRemoteValidationOverlay := jenkinsRemoteValidationProfile(profile) && validAdapterCount == 0 && len(proposal.AdapterFiles) == 0 && !agentLogHasTool(log, "function_context")
				emptyJobOutputEventOverlay := jobOutputEventUpdateProfile(profile) && validAdapterCount == 0 && len(proposal.AdapterFiles) == 0 && !agentLogHasTool(log, "function_context")
				emptyDefaultRelayOverlay := defaultRelaySecretProfile(profile) && validAdapterCount == 0 && len(proposal.AdapterFiles) == 0 && !agentLogHasTool(log, "function_context")
				emptyCommandWrapperOverlay := commandWrapperProfile(profile) && validAdapterCount == 0 && len(proposal.AdapterFiles) == 0 && (!agentLogHasNonEmptyToolResult(log, "function_context") || (!notesMentionAny(proposal.Notes, []string{"commandstringwrapperexecution", "argv", "process builder", "processbuilder", "$env:", "env var", "environment variable"}) || notesMentionAny(proposal.Notes, []string{"interprocedural", "automatically handled", "generic command execution", "os/exec", "exec.command"})))
				emptyCommandOptionOverlay := commandOptionProfile(profile) && validAdapterCount == 0 && len(proposal.AdapterFiles) == 0 && (!notesMentionAny(proposal.Notes, []string{"commandoptioninjection", "end-of-options", "--", "option injection"}) || notesMentionAny(proposal.Notes, []string{"no direct untrusted", "no untrusted entry", "no source", "map as a source"}))
				emptySecureCookieOverlay := secureCookieProfile(profile) && validAdapterCount == 0 && len(proposal.AdapterFiles) == 0 && (!agentLogHasNonEmptyToolResult(log, "function_context") || !notesMentionAny(proposal.Notes, []string{"insecurecookie", "vyql-cfg-007", "secure cookie", "secure flag", "setcookie"}))
				emptySecretComparisonOverlay := secretComparisonProfile(profile) && validAdapterCount == 0 && len(proposal.AdapterFiles) == 0 && (!agentLogHasNonEmptyToolResult(log, "function_context") || !notesMentionAny(proposal.Notes, []string{"secretcomparisonreview", "vyql-cry-006", "constant-time", "constant time", "timingsafeequal", "scmp"}))
				cryptoBlindingEvidence := cryptoBlindingProfile(profile)
				emptyCryptoBlindingOverlay := cryptoBlindingEvidence && validAdapterCount == 0 && len(proposal.AdapterFiles) == 0 && (!agentLogHasNonEmptyToolResult(log, "function_context") || !notesMentionAny(proposal.Notes, []string{"cryptoimproperblinding", "vyql-cry-011", "core scan", "base scanner", "existing scanner"}))
				ok := warn == "" && !missingRequiredSymbols && !missingRequiredCalls && !missingFocusedCalls && !missingRequiredAssignments && !missingFocusedAssignments && len(validationWarnings) == 0 && !emptyJenkinsStartupOverlay && !emptyJenkinsRemoteValidationOverlay && !emptyJobOutputEventOverlay && !emptyDefaultRelayOverlay && !emptyCommandWrapperOverlay && !emptyCommandOptionOverlay && !emptySecureCookieOverlay && !emptySecretComparisonOverlay && !emptyCryptoBlindingOverlay
				toolResult := map[string]any{
					"ok":                  ok,
					"valid_adapter_count": validAdapterCount,
				}
				if warn != "" {
					toolResult["error"] = warn
				}
				if missingRequiredSymbols && missingRequiredCalls {
					toolResult["error"] = "symbol_inventory and call_inventory are required before finish_overlay for repositories with security-relevant framework, verification, or native memory evidence; call symbol_inventory to map declarations, then call_inventory with focused API terms such as validate, origin, attestation, predicate, verify, print, policy, alloc, copy, size, capacity, escape, or unicode"
					p.debugf("step=%d finish_overlay rejected: symbol_inventory and call_inventory required", step)
				} else if missingRequiredSymbols {
					toolResult["error"] = "symbol_inventory is required before finish_overlay for repositories with security-relevant framework, verification, or native memory evidence; call symbol_inventory with focused name_contains terms before finish_overlay"
					p.debugf("step=%d finish_overlay rejected: symbol_inventory required", step)
				} else if missingRequiredCalls {
					toolResult["error"] = "call_inventory is required before finish_overlay for repositories with security-relevant framework, verification, or native memory evidence; call call_inventory with focused API terms such as validate, origin, attestation, predicate, verify, print, policy, alloc, copy, size, capacity, escape, or unicode, then finish_overlay"
					p.debugf("step=%d finish_overlay rejected: call_inventory required", step)
				} else if missingFocusedCalls {
					toolResult["error"] = "call_inventory must be focused on the repo evidence before finish_overlay; call call_inventory with one of these name_contains terms: " + strings.Join(requiredCallTerms, ", ")
					p.debugf("step=%d finish_overlay rejected: focused call_inventory required terms=%s", step, strings.Join(requiredCallTerms, ","))
				} else if missingRequiredAssignments {
					toolResult["error"] = "assignment_inventory is required before finish_overlay for repositories with output-encoding, stored display, model field, or trust-boundary assignment evidence; call assignment_inventory with focused terms such as " + strings.Join(requiredAssignmentTerms, ", ")
					p.debugf("step=%d finish_overlay rejected: assignment_inventory required", step)
				} else if missingFocusedAssignments {
					toolResult["error"] = "assignment_inventory must be focused on repo output/trust-boundary evidence before finish_overlay; call assignment_inventory with one of these name_contains terms: " + strings.Join(requiredAssignmentTerms, ", ")
					p.debugf("step=%d finish_overlay rejected: focused assignment_inventory required terms=%s", step, strings.Join(requiredAssignmentTerms, ","))
				} else if emptyJenkinsStartupOverlay {
					toolResult["error"] = "Jenkins credentials startup-load evidence is present; do not return an empty overlay until you have called concept_reference with topic \"jenkins credentials startup\", class/function context for SystemCredentialsProvider, and validate_overlay with an analysis.class.context mark to code.JenkinsCredentialsStartupLoadContextExposure or concrete evidence that @Initializer after InitMilestone.JOB_LOADED already force-loads getInstance"
					p.debugf("step=%d finish_overlay rejected: empty Jenkins credentials startup overlay", step)
				} else if emptyJenkinsRemoteValidationOverlay {
					toolResult["error"] = "Jenkins remote validation endpoint evidence is present; do not return an empty overlay until you have called concept_reference with topic \"jenkins remote validation\", function_context for the doTest/doCheck/doFill method containing QueryParameter plus outbound test/connect calls, and validate_overlay with an analysis.function.context mark to code.JenkinsRemoteValidationMissingPostPermission or concrete evidence that @POST and checkPermission/hasPermission already gate the connection"
					p.debugf("step=%d finish_overlay rejected: empty Jenkins remote validation overlay", step)
				} else if emptyJobOutputEventOverlay {
					toolResult["error"] = "job output event-update evidence is present; do not return an empty overlay until you have called concept_reference with topic \"job output event update\", function_context for the child-output handler containing update_event, and validate_overlay with an analysis.function.context mark to code.JobOutputEventUpdateAuthorizationBypass or concrete evidence that update_event is deleted or gated by allow_event_updates_from_jobs before copying child output into job state"
					p.debugf("step=%d finish_overlay rejected: empty job output event-update overlay", step)
				} else if emptyDefaultRelayOverlay {
					toolResult["error"] = "default relay URL evidence is present; do not return an empty overlay until you have called concept_reference with topic \"default relay host\", function_context for the URL builder containing host/token/encoded upstream URL assignments, and validate_overlay with an analysis.function.context mark to code.DefaultExternalRelaySecretExposure or concrete evidence that the default host is product-owned/trusted"
					p.debugf("step=%d finish_overlay rejected: empty default relay overlay", step)
				} else if emptyCommandWrapperOverlay {
					toolResult["error"] = "command-wrapper evidence is present; do not return an empty overlay until you have called concept_reference with topic \"command wrapper\", function_context for the wrapper caller containing command-string construction and execute evidence, and validate_overlay with code.CommandStringWrapperExecution or concrete evidence that the command uses argv/process-builder/env-variable hardening. Do not rely on generic interprocedural taint through a local helper as the empty-overlay rationale."
					p.debugf("step=%d finish_overlay rejected: empty command-wrapper overlay", step)
				} else if emptyCommandOptionOverlay {
					toolResult["error"] = "command option-injection evidence is present; empty-overlay notes must explicitly address code.CommandOptionInjection or end-of-options delimiter hardening such as --, and must not reject the mark merely because the library has no direct untrusted source. Shell escaping alone is not sufficient evidence for option-taking CLI arguments."
					p.debugf("step=%d finish_overlay rejected: empty command option overlay without specific rationale", step)
				} else if emptySecureCookieOverlay {
					toolResult["error"] = "secure-cookie evidence is present; do not return an empty overlay until you have called concept_reference with topic \"secure cookie\", function_context for the cookie setter containing SetCookie plus token/session/csrf evidence, and validate_overlay with code.InsecureCookie or concrete evidence that the secure flag is passed from the configured option such as opt.Secure"
					p.debugf("step=%d finish_overlay rejected: empty secure-cookie overlay", step)
				} else if emptySecretComparisonOverlay {
					toolResult["error"] = "secret/token comparison evidence is present; do not return an empty overlay until you have called concept_reference with topic \"secret comparison\", function_context for the validate/check function containing token/secret equality, and validate_overlay with code.SecretComparisonReview or concrete evidence that core VYQL-CRY-006 coverage already matches and a constant-time helper such as scmp or timingSafeEqual is used in fixed code"
					p.debugf("step=%d finish_overlay rejected: empty secret-comparison overlay", step)
				} else if emptyCryptoBlindingOverlay {
					toolResult["error"] = "crypto blinding/timing evidence is present; do not return an empty overlay until you have called concept_reference with topic \"blinding\", function_context for the private-key operation containing Randomize/MultiplicativeInverse/Jacobi/Square evidence, and validate_overlay with code.CryptoImproperBlinding or concrete evidence that the randomized blinding factor is squared/subgroup-hardened before inverse/unblinding use"
					p.debugf("step=%d finish_overlay rejected: empty crypto blinding overlay", step)
				}
				if len(validationWarnings) > 0 {
					toolResult["warnings"] = validationWarnings
					proposal.Notes = append(proposal.Notes, "agent overlay validation warnings: "+strings.Join(validationWarnings, "; "))
					p.debugf("step=%d finish_overlay validation warnings=%s", step, strings.Join(validationWarnings, " | "))
				}
				entry.ToolResults = append(entry.ToolResults, AgentToolResult{
					ID:     call.ID,
					Name:   call.Name,
					Result: toolResult,
				})
				if !ok && step < maxAgentSteps {
					resultParts = append(resultParts, map[string]any{
						"functionResponse": map[string]any{"name": call.Name, "response": toolResult},
					})
					contents = append(contents, map[string]any{"role": "model", "parts": modelParts})
					contents = append(contents, map[string]any{"role": "user", "parts": resultParts})
					log = append(log, entry)
					continue agentLoop
				}
				proposal.AgentLog = append(log, entry)
				proposal.Notes = append(notes, proposal.Notes...)
				return proposal, nil
			}
			result := map[string]any(nil)
			if gateErr := inventoryGateError(profile, log, call.Name); gateErr != "" && !allowExactReadAfterFocusedInventory(profile, log, call) {
				result = map[string]any{"ok": false, "error": gateErr}
				p.debugf("step=%d tool=%s rejected by inventory gate", step, call.Name)
			} else {
				result = p.executePrepTool(profile, call)
			}
			if call.Name == "validate_overlay" {
				if warnings, ok := result["warnings"].([]string); ok && len(warnings) > 0 {
					p.debugf("step=%d validate_overlay warnings=%s", step, strings.Join(warnings, " | "))
				}
				p.debugf("step=%d validate_overlay ok=%v valid_adapter_count=%v", step, result["ok"], result["valid_adapter_count"])
			}
			entry.ToolResults = append(entry.ToolResults, AgentToolResult{ID: call.ID, Name: call.Name, Result: result})
			if call.Name == "validate_overlay" {
				if ok, _ := result["ok"].(bool); ok {
					if count, _ := result["valid_adapter_count"].(int); count > 0 {
						if proposal, warn := proposalFromToolArgs(call.Arguments); warn == "" {
							lastValid = proposal
						}
					}
				}
			}
			resultParts = append(resultParts, map[string]any{
				"functionResponse": map[string]any{"name": call.Name, "response": result},
			})
		}
		contents = append(contents, map[string]any{"role": "model", "parts": modelParts})
		contents = append(contents, map[string]any{"role": "user", "parts": resultParts})
		if step >= 12 && !decisionCheckpointSent && !hasToolCall(calls, "validate_overlay") && !hasToolCall(calls, "finish_overlay") {
			decisionCheckpointSent = true
			p.debugf("step=%d injecting decision checkpoint", step)
			contents = append(contents, map[string]any{
				"role": "user",
				"parts": []map[string]any{{
					"text": "Decision checkpoint: stop searching now. Your next tool call must be validate_overlay if you have concrete source plus sink/mark/control evidence, or finish_overlay with adapter_files=[] if you do not. If finish_overlay is rejected because required symbol_inventory, call_inventory, or assignment_inventory is missing, call exactly those inventory tools with the requested focused terms, then call finish_overlay. Do not call search, read, repo, dependency, or reference tools after this checkpoint.",
				}},
			})
		}
		log = append(log, entry)
		validatorRequiredInventory := hasToolCall(calls, "symbol_inventory") || hasToolCall(calls, "call_inventory") || hasToolCall(calls, "assignment_inventory")
		if decisionCheckpointSent && validatorRequiredInventory && !hasToolCall(calls, "validate_overlay") && !hasToolCall(calls, "finish_overlay") {
			needsSymbols := requiresSymbolInventory(profile)
			requiredCallTerms := requiredCallInventoryTerms(profile)
			requiredAssignmentTerms := requiredAssignmentInventoryTerms(profile)
			missingSymbols := needsSymbols && !agentLogHasTool(log, "symbol_inventory")
			missingCalls := needsSymbols && !agentLogHasTool(log, "call_inventory")
			missingFocused := len(requiredCallTerms) > 0 && !agentLogHasCallInventoryTerm(log, requiredCallTerms)
			missingAssignments := requiresAssignmentInventory(profile) && !agentLogHasTool(log, "assignment_inventory")
			missingFocusedAssignments := requiresAssignmentInventory(profile) && len(requiredAssignmentTerms) > 0 && !agentLogHasAssignmentInventoryTerm(log, requiredAssignmentTerms)
			msg := "Required inventory is now satisfied. Next tool call must be finish_overlay with adapter_files=[] unless you have already validated a concrete adapter."
			switch {
			case missingSymbols:
				msg = "Checkpoint correction: symbol_inventory is still required before finish_overlay. Call symbol_inventory with focused declaration terms, then finish_overlay."
			case missingCalls:
				msg = "Checkpoint correction: call_inventory is still required before finish_overlay. Call call_inventory with focused API terms, then finish_overlay."
			case missingFocused:
				msg = "Checkpoint correction: call_inventory was too broad. Call call_inventory with one of these name_contains terms, then finish_overlay: " + strings.Join(requiredCallTerms, ", ")
			case missingAssignments:
				msg = "Checkpoint correction: assignment_inventory is still required before finish_overlay. Call assignment_inventory with focused write terms, then finish_overlay: " + strings.Join(requiredAssignmentTerms, ", ")
			case missingFocusedAssignments:
				msg = "Checkpoint correction: assignment_inventory was too broad. Call assignment_inventory with one of these name_contains terms, then finish_overlay: " + strings.Join(requiredAssignmentTerms, ", ")
			}
			p.debugf("step=%d post-inventory checkpoint correction", step)
			contents = append(contents, map[string]any{
				"role": "user",
				"parts": []map[string]any{{
					"text": msg,
				}},
			})
		}
		if decisionCheckpointSent && step >= 16 && !hasToolCall(calls, "validate_overlay") && !hasToolCall(calls, "finish_overlay") && !validatorRequiredInventory {
			p.debugf("step=%d corrective checkpoint after unrelated tool calls", step)
			contents = append(contents, map[string]any{
				"role": "user",
				"parts": []map[string]any{{
					"text": "Checkpoint correction: do not call more setup/search/reference tools. Next call must be finish_overlay, unless the last finish_overlay response required symbol_inventory, call_inventory, or assignment_inventory; in that case call only the required inventory tool with the requested focused terms, then finish_overlay.",
				}},
			})
		}
	}
	if len(lastValid.AdapterFiles) > 0 {
		lastValid.AgentLog = log
		lastValid.Notes = append(notes, lastValid.Notes...)
		lastValid.Notes = append(lastValid.Notes, "agent reached max_steps after validating overlay; using last valid proposal")
		p.debugf("max_steps using last valid adapters=%d", len(lastValid.AdapterFiles))
		return lastValid, nil
	}
	p.debugf("max_steps no valid overlay")
	return Proposal{AgentLog: log, Notes: append(notes, "agent reached max_steps without finish_overlay")}, nil
}

type vertexToolCall struct {
	ID        string
	Name      string
	Arguments map[string]any
}

func (p *VertexProvider) debugf(format string, args ...any) {
	if !p.debug {
		return
	}
	fmt.Fprintf(os.Stderr, "[agentic-prep:vertex] "+format+"\n", args...)
}

func toolCallNames(calls []vertexToolCall) string {
	if len(calls) == 0 {
		return "-"
	}
	names := make([]string, 0, len(calls))
	for _, call := range calls {
		names = append(names, call.Name)
	}
	return strings.Join(names, ",")
}

func hasToolCall(calls []vertexToolCall, name string) bool {
	for _, call := range calls {
		if call.Name == name {
			return true
		}
	}
	return false
}

func agentLogHasTool(log []AgentStep, name string) bool {
	for _, step := range log {
		for _, call := range step.ToolCalls {
			if call.Name == name {
				return true
			}
		}
	}
	return false
}

func agentLogHasCallInventoryTerm(log []AgentStep, terms []string) bool {
	for _, step := range log {
		for _, call := range step.ToolCalls {
			if call.Name != "call_inventory" {
				continue
			}
			arg := strings.ToLower(stringArg(call.Arguments, "name_contains"))
			if arg == "" {
				continue
			}
			for _, term := range terms {
				if strings.Contains(arg, strings.ToLower(term)) || strings.Contains(strings.ToLower(term), arg) {
					return true
				}
			}
		}
	}
	return false
}

func agentLogHasAssignmentInventoryTerm(log []AgentStep, terms []string) bool {
	for _, step := range log {
		for _, call := range step.ToolCalls {
			if call.Name != "assignment_inventory" {
				continue
			}
			arg := strings.ToLower(stringArg(call.Arguments, "name_contains") + " " + stringArg(call.Arguments, "value_contains"))
			if strings.TrimSpace(arg) == "" {
				continue
			}
			for _, term := range terms {
				term = strings.ToLower(term)
				if strings.Contains(arg, term) || strings.Contains(term, strings.TrimSpace(arg)) {
					return true
				}
			}
		}
	}
	return false
}

func agentLogResultHasAnyTerm(log []AgentStep, terms []string) bool {
	for _, step := range log {
		for _, result := range step.ToolResults {
			b, err := json.Marshal(result.Result)
			if err != nil {
				continue
			}
			hay := strings.ToLower(string(b))
			for _, term := range terms {
				if strings.Contains(hay, strings.ToLower(term)) {
					return true
				}
			}
		}
	}
	return false
}

func agentLogHasNonEmptyToolResult(log []AgentStep, name string) bool {
	for _, step := range log {
		for _, result := range step.ToolResults {
			if result.Name != name {
				continue
			}
			for key, val := range result.Result {
				if key == "ok" {
					continue
				}
				if isNonEmptyValue(val) {
					return true
				}
			}
		}
	}
	return false
}

func isNonEmptyValue(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(x) != ""
	case []any:
		return len(x) > 0
	case []map[string]any:
		return len(x) > 0
	default:
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Slice, reflect.Array, reflect.Map:
			return rv.Len() > 0
		}
		return true
	}
}

func notesMentionAny(notes []string, terms []string) bool {
	for _, note := range notes {
		note = strings.ToLower(note)
		for _, term := range terms {
			if strings.Contains(note, strings.ToLower(term)) {
				return true
			}
		}
	}
	return false
}

func inventoryGateError(profile Profile, log []AgentStep, toolName string) string {
	switch toolName {
	case "search_text", "search_context", "read_file", "read_files":
	default:
		return ""
	}
	needsSymbols := requiresSymbolInventory(profile)
	needsAssignments := requiresAssignmentInventory(profile)
	if !needsSymbols && !needsAssignments {
		return ""
	}
	requiredCallTerms := requiredCallInventoryTerms(profile)
	requiredAssignmentTerms := requiredAssignmentInventoryTerms(profile)
	missingSymbols := needsSymbols && !agentLogHasTool(log, "symbol_inventory")
	missingCalls := needsSymbols && !agentLogHasTool(log, "call_inventory")
	missingFocused := len(requiredCallTerms) > 0 && !agentLogHasCallInventoryTerm(log, requiredCallTerms)
	missingAssignments := needsAssignments && !agentLogHasTool(log, "assignment_inventory")
	missingFocusedAssignments := needsAssignments && len(requiredAssignmentTerms) > 0 && !agentLogHasAssignmentInventoryTerm(log, requiredAssignmentTerms)
	if !missingSymbols && !missingCalls && !missingFocused && !missingAssignments && !missingFocusedAssignments {
		return ""
	}
	if missingSymbols && missingCalls {
		return "call symbol_inventory and call_inventory before broad search/read tools for this repository; use focused terms such as " + strings.Join(requiredCallTerms, ", ")
	}
	if missingSymbols {
		return "call symbol_inventory before broad search/read tools for this repository"
	}
	if missingCalls || missingFocused {
		return "call call_inventory with focused terms before broad search/read tools: " + strings.Join(requiredCallTerms, ", ")
	}
	if missingAssignments || missingFocusedAssignments {
		return "call assignment_inventory with focused write terms before broad search/read tools: " + strings.Join(requiredAssignmentTerms, ", ")
	}
	return ""
}

func allowExactReadAfterFocusedInventory(profile Profile, log []AgentStep, call vertexToolCall) bool {
	if call.Name != "read_file" || strings.TrimSpace(stringArg(call.Arguments, "path")) == "" {
		return false
	}
	if !requiresSymbolInventory(profile) {
		return false
	}
	if !agentLogHasTool(log, "symbol_inventory") {
		return false
	}
	for _, step := range log {
		for _, seen := range step.ToolCalls {
			if seen.Name == "call_inventory" && strings.TrimSpace(stringArg(seen.Arguments, "name_contains")) != "" {
				return true
			}
		}
	}
	return false
}

func requiresSymbolInventory(profile Profile) bool {
	terms := []string{
		"asmodelsuccess", "modelname", "getacceptsjson", "response.data",
		"toarray", "extrafields", "serialize",
		"formvalidation", "queryparameter", "dotest", "docheck", "dofill",
		"testconnection", "checkpermission", "haspermission", "jenkins.administer",
		"systemcredentialsprovider", "domaincredentials.migratelisttomap",
		"xml.unmarshal", "credentials.xml", "initmilestone.job_loaded",
		"initializer", "forceloadduringstartup",
		"cmdexecuteservice", "$cmd_string", "x-islandora-args",
		"generatederivativeresponse", "$this->cmd->execute",
		"runpowershellcmd", "powershell", "-command", "fmt.sprintf",
		"$env:", "get-volume", "get-item", "add-partitionaccesspath",
		"remove-partitionaccesspath",
		"loadfromassemblypath", "assemblyloadcontext", "appcontext.basedirectory",
		"splitname[1]", "typename.split",
		"runquery", "querydb", "dbquery", "executequery", "$ssql",
		"legacyfilterinputarr", "where di_",
		"escapeshellarg", "shlex.quote", "shellwords.escape", "setoperation",
		"--list-secret-keys", "--list-public-keys", "--list-keys",
		"--delete-key", "--delete-secret-key", "--export", "end-of-options",
		"update_event", "handlechildresponse", "allow_event_updates_from_jobs",
		"listfindupdate", "global/schedule",
		"process::fromshellcommandline", "processbuilder", "command string",
		"@modelcontextprotocol", "mcpserver", "server.tool",
		"stdioservertransport", "child_process", "execfile", "z.number",
		"memcpy(newpath + pathlen", "child->namelen", "do_directory",
		"expand_fs", "romfs_read", "namelen", "dirent",
		"bad filename", "strchr(name", "strcmp(name", "extract", "unpack",
		"zip.openreader", "zip.newreader", "os.openfile", "os.o_trunc",
		"getinput", "overwrite",
		"cors", "alloworigins", "alloworiginfunc", "allowallorigins",
		"access-control-allow-origin", "trustedorigin", "trusted_origin",
		"wildcard", "validateorigin", "checkorigin", "callback",
		"x-csrf-token", "csrf.valid", "csrf.validate", "=== token",
		"== token", "timingsafeequal", "constant-time", "constant time",
		"setcookie", "cookiehttponly", "secure flag", "secure bool",
		"opt.secure", "secure=false",
		"attestation", "predicate", "signature", "provenance",
		"transparencylog", "fulcio", "rekor",
		"calculateinverse", "multiplicativeinverse", "randomize", "jacobi",
		"modularsquareroot", "modn.square", "blind", "unblind", "rabin",
		"malloc", "calloc", "realloc", "alloc", "memcpy", "memmove",
		"strcpy", "copy", "size", "length", "capacity", "offset",
		"bounds", "unicode", "escape",
	}
	hasTerm := func(s string) bool {
		s = strings.ToLower(s)
		for _, term := range terms {
			if strings.Contains(s, term) {
				return true
			}
		}
		return false
	}
	for _, pkg := range profile.Packages {
		if hasTerm(pkg) {
			return true
		}
	}
	for _, pkg := range profile.LocalPkgs {
		if hasTerm(pkg) {
			return true
		}
	}
	for _, imports := range profile.Imports {
		for _, imp := range imports {
			if hasTerm(imp) {
				return true
			}
		}
	}
	for _, sample := range profile.Samples {
		if hasTerm(sample.Path) || hasTerm(sample.Preview) {
			return true
		}
	}
	return false
}

func requiredCallInventoryTerms(profile Profile) []string {
	switch {
	case mcpToolProfile(profile):
		return []string{"tool", "server.tool", "mcpserver", "exec", "execfile", "child_process", "z.number", "port"}
	case jenkinsCredentialStartupProfile(profile):
		return []string{"unmarshal", "migratelisttomap", "getinstance", "initializer", "job_loaded", "credentials"}
	case jenkinsRemoteValidationProfile(profile):
		return []string{"testconnection", "connect", "getprojects", "buildclient", "queryparameter", "dotest", "docheck", "dofill", "checkpermission", "haspermission", "post"}
	case commandOptionProfile(profile):
		return []string{"escapeshellarg", "operation", "--", "setoperation", "gpg", "gnupg", "key", "fingerprint", "argument", "option"}
	case secretComparisonProfile(profile):
		return []string{"validate", "token", "secret", "csrf", "compare", "equal", "scmp", "timingsafeequal"}
	case secureCookieProfile(profile):
		return []string{"setcookie", "cookie", "secure", "httponly", "csrf", "token", "session"}
	case cryptoBlindingProfile(profile):
		return []string{"calculateinverse", "randomize", "multiplicativeinverse", "jacobi", "square", "modularsquareroot", "blind", "unblind", "rabin"}
	case dynamicAssemblyLoadPathProfile(profile):
		return []string{"loadfromassemblypath", "assemblyloadcontext", "basedirectory", "split", "path", "contains"}
	case phpSqlWrapperProfile(profile):
		return []string{"runquery", "querydb", "sql", "where", "legacyfilterinputarr", "get", "post"}
	case jobOutputEventUpdateProfile(profile):
		return []string{"update_event", "handlechildresponse", "listfindupdate", "schedule", "config", "delete"}
	case defaultRelaySecretProfile(profile):
		return []string{"host", "polling", "connect", "websocket", "url", "token", "gurl"}
	case commandWrapperProfile(profile):
		return []string{"execute", "command", "cmd", "process", "shell", "headers", "args", "generatederivative", "runpowershellcmd", "powershell", "sprintf", "get-volume", "get-item"}
	case profileContainsAnyTerm(profile, []string{"do_directory", "expand_fs", "romfs_read", "namelen", "dirent", "bad filename", "strchr(name", "strcmp(name"}):
		return []string{"expand", "extract", "directory", "dirent", "name", "path", "romfs", "read", "mkdir", "open"}
	case profileContainsAnyTerm(profile, []string{"contentlength", "content-length", "io.readfull", "limitreader", "maxbytesreader", "maxbodysize", "bodysizexceeded", "readrequestbody"}):
		return []string{"contentlength", "readfull", "readall", "limitreader", "maxbytesreader", "maxbodysize", "body", "request"}
	case profileContainsAnyTerm(profile, []string{"userspec", "strtoll", "uid", "gid", "process->user", "process user", "--user", "parse user"}):
		return []string{"strtoll", "userspec", "uid", "gid", "endptr", "user", "group"}
	case archiveOverwriteProfile(profile):
		return []string{"zip", "openreader", "openfile", "o_trunc", "stat", "getinput", "overwrite"}
	case nativeMemoryProfile(profile):
		return []string{"alloc", "malloc", "calloc", "realloc", "memcpy", "copy", "size", "length", "capacity", "offset", "escape", "unicode"}
	case profileContainsAnyTerm(profile, []string{"asmodelsuccess", "modelname", "getacceptsjson", "response.data", "toarray", "extrafields", "serialize"}):
		return []string{"asmodelsuccess", "model", "json", "data", "serialize", "toarray", "fields", "accepts"}
	case profileContainsAnyTerm(profile, []string{"attestation", "predicate", "provenance"}):
		return []string{"attestation", "predicate", "policy", "printverification", "provenance"}
	case profileContainsAnyTerm(profile, []string{"cors", "alloworigins", "alloworiginfunc", "allowallorigins", "access-control-allow-origin", "origin", "wildcard", "callback"}):
		return []string{"origin", "cors", "validate", "wildcard", "match", "callback"}
	case profileContainsAnyTerm(profile, []string{"signature", "fulcio", "rekor", "transparencylog"}):
		return []string{"signature", "verify", "policy", "certificate", "rekor", "fulcio"}
	default:
		return nil
	}
}

func requiresAssignmentInventory(profile Profile) bool {
	if commandOptionProfile(profile) {
		return true
	}
	if profileContainsAnyTerm(profile, []string{"userspec", "strtoll", "uid", "gid", "process->user", "process user", "--user", "parse user"}) {
		return true
	}
	if profile.Languages["php"] == 0 && profile.Languages["javascript"] == 0 && profile.Languages["typescript"] == 0 && profile.Languages["python"] == 0 && profile.Languages["ruby"] == 0 && profile.Languages["java"] == 0 && profile.Languages["go"] == 0 {
		return false
	}
	if archiveOverwriteProfile(profile) {
		return false
	}
	return profileContainsAnyTerm(profile, []string{
		"xss", "html::encode", "htmlspecialchars", "escapehtml", "template::raw",
		"twig\\markup", "html", "render", "title", "snapshot", "audit",
		"cmdexecuteservice", "$cmd_string", "x-islandora-args",
		"generatederivativeresponse", "$this->cmd->execute",
		"asmodelsuccess", "modelname", "getacceptsjson", "response.data",
		"toarray", "extrafields", "serialize",
		"ssti", "twig", "absoluteurlwithprotocol", "canonicalurl",
		"safecanonicalurl", "x-forwarded-host", "host header", "getpathinfo",
		"sanitizeurl",
		"permission", "role", "policy", "session", "redirect", "origin",
		"url", "path", "filename", "token", "secret",
	})
}

func requiredAssignmentInventoryTerms(profile Profile) []string {
	switch {
	case mcpToolProfile(profile):
		return []string{"port", "args", "command", "pid", "exec", "tool", "schema"}
	case jenkinsCredentialStartupProfile(profile):
		return []string{"credentials", "domaincredentialsmap", "initializer", "authentication", "system", "startup"}
	case jenkinsRemoteValidationProfile(profile):
		return []string{"url", "applicationname", "password", "proxy", "host", "port", "credential", "permission"}
	case commandOptionProfile(profile):
		return []string{"operation", "argument", "args", "keyid", "fingerprint", "option", "command", "escape", "delimiter"}
	case secretComparisonProfile(profile):
		return []string{"valid", "token", "secret", "csrf", "data", "compare"}
	case secureCookieProfile(profile):
		return []string{"secure", "cookie", "httponly", "token", "session", "csrf"}
	case commandWrapperProfile(profile):
		return []string{"cmd", "command", "args", "headers", "source", "execute", "shell", "process", "volumeid", "mountpath", "linkpath", "drivepath", "env"}
	case dynamicAssemblyLoadPathProfile(profile):
		return []string{"path", "typename", "splitname", "assembly", "basedirectory", "dll"}
	case jobOutputEventUpdateProfile(profile):
		return []string{"update_event", "job", "data", "schedule", "config", "allow_event_updates_from_jobs"}
	case defaultRelaySecretProfile(profile):
		return []string{"host", "polling", "url", "token", "gurl", "connection", "encode"}
	case profileContainsAnyTerm(profile, []string{"userspec", "strtoll", "uid", "gid", "process->user", "process user", "--user", "parse user"}):
		return []string{"uid", "gid", "user", "group", "endptr", "return", "assign"}
	case profileContainsAnyTerm(profile, []string{"asmodelsuccess", "modelname", "getacceptsjson", "response.data", "toarray", "extrafields", "serialize"}):
		return []string{"user", "model", "data", "response", "json", "secret", "token", "password", "credential", "fields"}
	case profileContainsAnyTerm(profile, []string{"ssti", "twig", "absoluteurlwithprotocol", "canonicalurl", "safecanonicalurl", "x-forwarded-host", "host header", "getpathinfo", "sanitizeurl"}):
		return []string{"url", "host", "canonical", "sanitize", "absolute", "path", "twig", "template", "x-forwarded-host"}
	case profileContainsAnyTerm(profile, []string{"xss", "html::encode", "htmlspecialchars", "escapehtml", "template::raw", "twig\\markup", "html", "render", "title", "snapshot", "audit"}):
		return []string{"title", "html", "body", "content", "snapshot", "name", "label", "encode", "escape", "sanitize", "raw", "render"}
	case profileContainsAnyTerm(profile, []string{"permission", "role", "policy", "admin", "authorization"}):
		return []string{"permission", "role", "policy", "admin", "access", "allow", "deny"}
	case profileContainsAnyTerm(profile, []string{"session", "redirect", "origin", "url", "callback"}):
		return []string{"session", "redirect", "origin", "url", "callback", "target", "return"}
	case profileContainsAnyTerm(profile, []string{"path", "filename", "file", "upload"}):
		return []string{"path", "filename", "file", "upload", "name", "extension"}
	case profileContainsAnyTerm(profile, []string{"token", "secret", "password", "key"}):
		return []string{"token", "secret", "password", "key", "credential"}
	default:
		return []string{"value", "target", "name", "path", "title", "permission"}
	}
}

func commandWrapperProfile(profile Profile) bool {
	if profile.Languages["php"] == 0 && profile.Languages["javascript"] == 0 && profile.Languages["typescript"] == 0 && profile.Languages["python"] == 0 && profile.Languages["ruby"] == 0 && profile.Languages["java"] == 0 && profile.Languages["go"] == 0 {
		return false
	}
	if profileContainsAnyTerm(profile, []string{
		"cmdexecuteservice", "$cmd_string", "x-islandora-args",
		"generatederivativeresponse", "$this->cmd->execute",
		"process::fromshellcommandline", "processbuilder", "command string",
	}) {
		return true
	}
	if profile.Languages["go"] > 0 {
		hasPowerShellWrapper := profileContainsAnyTerm(profile, []string{
			"runpowershellcmd", "powershell", "-command",
		})
		hasStringCommandTemplate := profileContainsAnyTerm(profile, []string{
			"fmt.sprintf", "get-volume", "get-item", "add-partitionaccesspath",
			"remove-partitionaccesspath", "$env:",
		})
		return hasPowerShellWrapper && hasStringCommandTemplate
	}
	return false
}

func commandOptionProfile(profile Profile) bool {
	if profile.Languages["php"] == 0 && profile.Languages["javascript"] == 0 && profile.Languages["typescript"] == 0 && profile.Languages["python"] == 0 && profile.Languages["ruby"] == 0 && profile.Languages["java"] == 0 && profile.Languages["go"] == 0 {
		return false
	}
	hasEscapedCommandArg := profileContainsAnyTerm(profile, []string{
		"escapeshellarg", "shlex.quote", "shellwords.escape", "processbuilder",
		"exec.command", "execfile", "spawn(", "argv",
	})
	hasOptionCommand := profileContainsAnyTerm(profile, []string{
		"gnupg", "gpg", "--list-secret-keys", "--list-public-keys", "--list-keys",
		"--delete-key", "--delete-secret-key", "--export", "setoperation",
		"end-of-options", " -- ", "option injection",
	})
	return hasEscapedCommandArg && hasOptionCommand
}

func secureCookieProfile(profile Profile) bool {
	hasCookieSetter := profileContainsAnyTerm(profile, []string{
		"setcookie", "http.setcookie", "set-cookie", "cookiehttponly", "secure=false",
	})
	if !hasCookieSetter {
		return false
	}
	hasSecureOption := profileContainsAnyTerm(profile, []string{
		"secure bool", "secure flag", "opt.secure", "setsecure", "cookie secure", "secure:",
	})
	hasSensitiveCookie := profileContainsAnyTerm(profile, []string{
		"csrf", "xsrf", "token", "session", "auth", "credential", "secret", "cookiehttponly",
	})
	return hasSecureOption && hasSensitiveCookie
}

func secretComparisonProfile(profile Profile) bool {
	hasSpecificSecretMaterial := profileContainsAnyTerm(profile, []string{
		"x-csrf-token", "csrf.valid", "csrf.validate", "secret",
		"password", "credential", "authorization", "basicauth", "signature",
	})
	hasTokenMaterial := profileContainsAnyTerm(profile, []string{"token"})
	hasComparison := profileContainsAnyTerm(profile, []string{
		"=== token", "== token", "!== token", "!= token",
		"password.equals", "secret.equals", "token.equals",
		"equals(password", "equals(secret", "equals(token",
		"compare_digest", "messagedigest.isequal",
		"timingsafeequal", "constant-time", "constant time", "scmp",
	})
	hasTokenEquality := profileContainsAnyTerm(profile, []string{"=== token", "== token", "!== token", "!= token"})
	if !hasSpecificSecretMaterial && !(hasTokenMaterial && hasTokenEquality) {
		return false
	}
	hasValidationContext := profileContainsAnyTerm(profile, []string{
		"validate", "valid", "check", "auth", "csrf", "token", "secret",
	})
	return hasComparison && hasValidationContext
}

func mcpToolProfile(profile Profile) bool {
	if profile.Languages["javascript"] == 0 && profile.Languages["typescript"] == 0 {
		return false
	}
	hasMcpBoundary := profileContainsAnyTerm(profile, []string{
		"@modelcontextprotocol", "mcpserver", "server.tool", "stdioservertransport",
	})
	if !hasMcpBoundary {
		return false
	}
	return profileContainsAnyTerm(profile, []string{"child_process", "execfile", "z.number", "z.string", "z.object", "port"})
}

func jenkinsCredentialStartupProfile(profile Profile) bool {
	if profile.Languages["java"] == 0 {
		return false
	}
	return profileContainsAnyTerm(profile, []string{
		"systemcredentialsprovider", "domaincredentials.migratelisttomap",
		"xml.unmarshal", "credentials.xml", "initmilestone.job_loaded",
		"initializer", "forceloadduringstartup",
	})
}

func jenkinsRemoteValidationProfile(profile Profile) bool {
	if profile.Languages["java"] == 0 {
		return false
	}
	hasJenkinsEndpoint := profileContainsAnyTerm(profile, []string{
		"formvalidation", "queryparameter", "hudson.util.formvalidation",
		"org.kohsuke.stapler.queryparameter", "dotest", "docheck", "dofill",
	})
	hasOutboundTest := profileContainsAnyTerm(profile, []string{
		"testconnection", "buildclient", "getprojects", "openconnection",
		"newrequest", "restcrowdclientfactory", "crowdconfigurationservice",
		"clientpropertiesimpl", "httpclient", "url",
	})
	hasJenkinsAuthContext := profileContainsAnyTerm(profile, []string{
		"jenkins.model.jenkins", "jenkins.administer", "checkpermission",
		"haspermission", "@post", "requirepost", "jenkins", "hudson",
	})
	return hasJenkinsEndpoint && hasOutboundTest && hasJenkinsAuthContext
}

func phpSqlWrapperProfile(profile Profile) bool {
	if profile.Languages["php"] == 0 {
		return false
	}
	return profileContainsAnyTerm(profile, []string{
		"runquery", "querydb", "dbquery", "executequery", "$ssql",
		"legacyfilterinputarr", "where di_", "select ", "from ",
	})
}

func jobOutputEventUpdateProfile(profile Profile) bool {
	if profile.Languages["javascript"] == 0 && profile.Languages["typescript"] == 0 {
		return false
	}
	return profileContainsAnyTerm(profile, []string{
		"update_event", "handlechildresponse", "allow_event_updates_from_jobs",
		"listfindupdate", "global/schedule",
	})
}

func archiveOverwriteProfile(profile Profile) bool {
	if profile.Languages["go"] == 0 {
		return false
	}
	return profileContainsAnyTerm(profile, []string{
		"zip.openreader", "zip.newreader", "os.openfile", "os.o_trunc",
		"getinput", "overwrite", "archive.file", "f.name",
	})
}

func nativeMemoryProfile(profile Profile) bool {
	if profile.Languages["c"] == 0 && profile.Languages["cpp"] == 0 && profile.Languages["rust"] == 0 && profile.Languages["swift"] == 0 {
		return false
	}
	return profileContainsAnyTerm(profile, []string{
		"malloc", "calloc", "realloc", "alloc", "memcpy", "memmove",
		"strcpy", "copy", "size", "length", "capacity", "offset",
		"bounds", "unicode", "escape",
	})
}

func cryptoBlindingProfile(profile Profile) bool {
	if profile.Languages["c"] == 0 && profile.Languages["cpp"] == 0 && profile.Languages["go"] == 0 && profile.Languages["java"] == 0 && profile.Languages["rust"] == 0 && profile.Languages["swift"] == 0 {
		return false
	}
	hasPrivateKeyOperation := profileContainsAnyTerm(profile, []string{
		"calculateinverse", "rabin", "rabin-williams", "rwss", "private key",
		"signature", "modularsquareroot",
	})
	hasBlindingMath := profileContainsAnyTerm(profile, []string{
		"multiplicativeinverse", "randomize", "jacobi", "modn.square",
		"blind", "unblind",
	})
	return hasPrivateKeyOperation && hasBlindingMath
}

func dynamicAssemblyLoadPathProfile(profile Profile) bool {
	if profile.Languages["csharp"] == 0 {
		return false
	}
	hasAssemblyLoad := profileContainsAnyTerm(profile, []string{
		"loadfromassemblypath", "assemblyloadcontext", "assembly.loadfrom", "assembly.loadfile",
	})
	hasPathAssembly := profileContainsAnyTerm(profile, []string{
		"appcontext.basedirectory", "splitname", "typename.split", ".dll",
	})
	return hasAssemblyLoad && hasPathAssembly
}

func profileContainsAnyTerm(profile Profile, terms []string) bool {
	hasTerm := func(s string) bool {
		s = strings.ToLower(s)
		for _, term := range terms {
			if strings.Contains(s, strings.ToLower(term)) {
				return true
			}
		}
		return false
	}
	for _, pkg := range profile.Packages {
		if hasTerm(pkg) {
			return true
		}
	}
	for _, pkg := range profile.LocalPkgs {
		if hasTerm(pkg) {
			return true
		}
	}
	for _, imports := range profile.Imports {
		for _, imp := range imports {
			if hasTerm(imp) {
				return true
			}
		}
	}
	for _, sample := range profile.Samples {
		if hasTerm(sample.Path) || hasTerm(sample.Preview) {
			return true
		}
	}
	return false
}

func defaultRelaySecretProfile(profile Profile) bool {
	if profile.Languages["javascript"] == 0 && profile.Languages["typescript"] == 0 && profile.Languages["python"] == 0 && profile.Languages["go"] == 0 && profile.Languages["java"] == 0 {
		return false
	}
	return profileSampleContainsAllTermGroups(profile, [][]string{
		{"pollinghost", "default host", "default_host", "defaulthost", "relay", "tunnel", "gurl", "conmanurl", "connectionmetadata"},
		{"token", "credential", "secret", "authorization", "connectionmetadata", "gurl", "conmanurl"},
		{"encodeuricomponent", "url.format", "urllib.format", "urlparse", "wsv2", "ws://", "wss://", "herokuapp.com"},
	})
}

func profileSampleContainsAllTermGroups(profile Profile, groups [][]string) bool {
	if len(groups) == 0 {
		return false
	}
	for _, sample := range profile.Samples {
		text := strings.ToLower(filepath.ToSlash(sample.Path) + "\n" + sample.Preview)
		matchedAll := true
		for _, group := range groups {
			matchedGroup := false
			for _, term := range group {
				if strings.Contains(text, strings.ToLower(term)) {
					matchedGroup = true
					break
				}
			}
			if !matchedGroup {
				matchedAll = false
				break
			}
		}
		if matchedAll {
			return true
		}
	}
	return false
}

func vertexPrepTools() []map[string]any {
	return []map[string]any{{"functionDeclarations": []map[string]any{
		{
			"name":        "inspect_profile",
			"description": "Return the bounded deterministic repository profile.",
			"parameters": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        "adapter_reference",
			"description": "Return concise VyQL adapter syntax examples and supported concept families.",
			"parameters": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        "trust_model",
			"description": "Return deterministic repo scan-configuration and trust-boundary evidence: selected profile, active source model, languages, manifests, and packages.",
			"parameters": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        "entrypoint_inventory",
			"description": "Return deterministic API/route/handler/CLI/config entrypoint candidates found in repo files so prep can configure trust model and target adapters.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"language": map[string]any{"type": "string"},
					"max":      map[string]any{"type": "integer"},
				},
			},
		},
		{
			"name":        "adapter_coverage",
			"description": "Return repo dependency/import coverage by existing VyQL package definitions, uncovered security-relevant gaps, and recommended package probes.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"language": map[string]any{"type": "string"},
					"max":      map[string]any{"type": "integer"},
				},
			},
		},
		{
			"name":        "concept_reference",
			"description": "Return existing VyQL concepts useful for repo-local prep marks and sinks.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"topic": map[string]any{"type": "string"},
				},
			},
		},
		{
			"name":        "package_reference",
			"description": "Return package/import/manifest candidates that should be used for explicit package-scoped adapter blocks.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"language": map[string]any{"type": "string"},
				},
			},
		},
		{
			"name":        "dependency_gaps",
			"description": "Return manifest/import dependencies observed in the repository that do not have an existing VyQL package definition.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"language": map[string]any{"type": "string"},
					"max":      map[string]any{"type": "integer"},
				},
			},
		},
		{
			"name":        "probe_dependency",
			"description": "Probe source usage of one uncovered dependency: import evidence, nearby usage lines, and files likely needing a repo-local adapter.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"language": map[string]any{"type": "string"},
					"package":  map[string]any{"type": "string"},
					"max":      map[string]any{"type": "integer"},
				},
				"required": []string{"package"},
			},
		},
		{
			"name":        "list_files",
			"description": "List bounded source/config files under scan roots, optionally filtered by extension or substring.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"contains":  map[string]any{"type": "string"},
					"extension": map[string]any{"type": "string"},
					"max":       map[string]any{"type": "integer"},
				},
			},
		},
		{
			"name":        "repo_structure",
			"description": "Return a ranked directory summary with language counts, security scores, and representative files for repo orientation.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"max": map[string]any{"type": "integer"},
				},
			},
		},
		{
			"name":        "security_relevant_files",
			"description": "Return source files ranked by deterministic security relevance: command/code execution, SQL, deserialization, redirects, file/path/archive/restore/import/upload flows, and user-controlled inputs.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"language": map[string]any{"type": "string"},
					"max":      map[string]any{"type": "integer"},
				},
			},
		},
		{
			"name":        "symbol_inventory",
			"description": "Return bounded AST-style class, method, function, type, and module declarations with signatures, enclosing class/module, and security snippets so prep can target files without opening them one-by-one.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"language":      map[string]any{"type": "string"},
					"kind":          map[string]any{"type": "string"},
					"name_contains": map[string]any{"type": "string"},
					"path_contains": map[string]any{"type": "string"},
					"max":           map[string]any{"type": "integer"},
				},
			},
		},
		{
			"name":        "call_inventory",
			"description": "Return bounded call-site inventory across repo source files, including callee, receiver, enclosing declaration, and snippets. Use after symbol_inventory to find where framework/security APIs are invoked.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"language":      map[string]any{"type": "string"},
					"name_contains": map[string]any{"type": "string"},
					"path_contains": map[string]any{"type": "string"},
					"max":           map[string]any{"type": "integer"},
				},
			},
		},
		{
			"name":        "assignment_inventory",
			"description": "Return bounded AST-style assignment/write inventory across repo source files, including target, operator, value preview, RHS calls, enclosing declaration, and snippets. Use it to find model/config/session/permission/title/path/url/html fields and compare raw writes against escaped or validated writes without opening files one-by-one.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"language":       map[string]any{"type": "string"},
					"name_contains":  map[string]any{"type": "string"},
					"value_contains": map[string]any{"type": "string"},
					"path_contains":  map[string]any{"type": "string"},
					"max":            map[string]any{"type": "integer"},
				},
			},
		},
		{
			"name":        "search_text",
			"description": "Search source/config files under scan roots with a Go regular expression or literal substring.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pattern":    map[string]any{"type": "string"},
					"regex":      map[string]any{"type": "boolean"},
					"ignoreCase": map[string]any{"type": "boolean"},
					"max":        map[string]any{"type": "integer"},
				},
				"required": []string{"pattern"},
			},
		},
		{
			"name":        "search_context",
			"description": "Search source/config files and return bounded surrounding context lines around each match.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pattern":    map[string]any{"type": "string"},
					"regex":      map[string]any{"type": "boolean"},
					"ignoreCase": map[string]any{"type": "boolean"},
					"before":     map[string]any{"type": "integer"},
					"after":      map[string]any{"type": "integer"},
					"max":        map[string]any{"type": "integer"},
				},
				"required": []string{"pattern"},
			},
		},
		{
			"name":        "read_file",
			"description": "Read bounded bytes from a source file under the scanned repository. Supports relative paths and byte offsets.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":      map[string]any{"type": "string"},
					"offset":    map[string]any{"type": "integer"},
					"max_bytes": map[string]any{"type": "integer"},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "read_files",
			"description": "Read multiple bounded source files under the scanned repository in one tool call.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"paths":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"max_bytes": map[string]any{"type": "integer"},
				},
				"required": []string{"paths"},
			},
		},
		{
			"name":        "function_context",
			"description": "Return matchable function context previews for exact analysis.function.context marks. Use before writing mark exact overlays.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":     map[string]any{"type": "string"},
					"name":     map[string]any{"type": "string"},
					"contains": map[string]any{"type": "string"},
					"max":      map[string]any{"type": "integer"},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "class_context",
			"description": "Return matchable class context previews for exact analysis.class.context marks. Use before writing class-level exact marks.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":     map[string]any{"type": "string"},
					"name":     map[string]any{"type": "string"},
					"contains": map[string]any{"type": "string"},
					"max":      map[string]any{"type": "integer"},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "module_context",
			"description": "Return matchable top-level declaration previews for exact analysis.module.context marks. Use for static role, route, permission, ACL, or policy maps.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":     map[string]any{"type": "string"},
					"contains": map[string]any{"type": "string"},
					"max":      map[string]any{"type": "integer"},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "validate_overlay",
			"description": "Validate proposed VyQL adapter overlay JSON before finalizing.",
			"parameters":  finishOverlayParameters(),
		},
		{
			"name":        "finish_overlay",
			"description": "Finish with repo-local VyQL adapter overlay files.",
			"parameters":  finishOverlayParameters(),
		},
	}}}
}

func (p *VertexProvider) generateAgentStep(ctx context.Context, contents []map[string]any, cachedContent string) (string, []vertexToolCall, []map[string]any, string, error) {
	if p.stepTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.stepTimeout)
		defer cancel()
	}
	body := p.generateAgentStepBody(contents, cachedContent)
	b, _ := json.Marshal(body)
	token, err := p.token(ctx)
	if err != nil {
		return "", nil, nil, "", err
	}
	data, status, err := p.doGenerateContent(ctx, token, b)
	if err != nil {
		return "", nil, nil, "", err
	}
	if status < 200 || status >= 300 {
		return "", nil, nil, "", fmt.Errorf("agentic prep: vertex HTTP %d: %s", status, string(data))
	}
	return vertexResponseParts(data)
}

func (p *VertexProvider) generateAgentStepBody(contents []map[string]any, cachedContent string) map[string]any {
	body := map[string]any{
		"contents": contents,
		"tools":    vertexPrepTools(),
		"generationConfig": map[string]any{
			"temperature": p.temperature,
		},
	}
	if cachedContent != "" {
		body["cachedContent"] = cachedContent
		delete(body, "tools")
	}
	return body
}

func (p *VertexProvider) createContextCache(ctx context.Context, contents []map[string]any) (string, error) {
	token, err := p.token(ctx)
	if err != nil {
		return "", err
	}
	ttl := p.contextCacheTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	body := map[string]any{
		"displayName": fmt.Sprintf("vyql-agentic-prep-%d", time.Now().Unix()),
		"model":       p.modelResource(),
		"contents":    contents,
		"tools":       vertexPrepTools(),
		"ttl":         fmt.Sprintf("%ds", int(ttl.Seconds())),
	}
	b, _ := json.Marshal(body)
	data, status, err := p.doVertexPost(ctx, token, p.cachedContentsEndpoint(), b)
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("vertex HTTP %d: %s", status, compactSnippet(string(data), 500))
	}
	var raw struct {
		Name          string `json:"name"`
		ExpireTime    string `json:"expireTime"`
		UsageMetadata struct {
			TotalTokenCount int `json:"totalTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", err
	}
	if raw.Name == "" {
		return "", errors.New("vertex cache response missing name")
	}
	return raw.Name, nil
}

func (p *VertexProvider) doGenerateContent(ctx context.Context, token string, body []byte) ([]byte, int, error) {
	return p.doVertexPost(ctx, token, p.endpoint(), body)
}

func (p *VertexProvider) doVertexPost(ctx context.Context, token string, endpoint string, body []byte) ([]byte, int, error) {
	var lastData []byte
	var lastStatus int
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			delay := time.Duration(1<<uint(attempt)) * time.Second
			select {
			case <-ctx.Done():
				return lastData, lastStatus, ctx.Err()
			case <-time.After(delay):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		res, err := p.http.Do(req)
		if err != nil {
			if attempt < 3 {
				continue
			}
			return nil, 0, err
		}
		data, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
		_ = res.Body.Close()
		lastData, lastStatus = data, res.StatusCode
		if !retryableVertexStatus(res.StatusCode) {
			return data, res.StatusCode, nil
		}
	}
	return lastData, lastStatus, nil
}

func retryableVertexStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusInternalServerError || status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

func (p *VertexProvider) executePrepTool(profile Profile, call vertexToolCall) map[string]any {
	switch call.Name {
	case "inspect_profile":
		return map[string]any{"ok": true, "profile": profile}
	case "adapter_reference":
		return map[string]any{"ok": true, "reference": adapterReferenceText()}
	case "trust_model":
		return map[string]any{"ok": true, "trust_model": trustModelSummary(profile)}
	case "entrypoint_inventory":
		lang, _ := call.Arguments["language"].(string)
		entries, err := entrypointInventory(profile, lang, intArg(call.Arguments, "max", 60))
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "entrypoints": entries}
	case "adapter_coverage":
		lang, _ := call.Arguments["language"].(string)
		return map[string]any{"ok": true, "coverage": adapterCoverage(profile, lang, intArg(call.Arguments, "max", 80))}
	case "concept_reference":
		topic, _ := call.Arguments["topic"].(string)
		return map[string]any{"ok": true, "concepts": conceptReference(topic)}
	case "package_reference":
		lang, _ := call.Arguments["language"].(string)
		return map[string]any{"ok": true, "packages": packageReference(profile, lang), "syntax": `adapter <language> { package "<package>" { ...mappings... } }`}
	case "dependency_gaps":
		lang, _ := call.Arguments["language"].(string)
		gaps := filteredDependencyGaps(profile, lang, intArg(call.Arguments, "max", 80))
		out := map[string]any{"ok": true, "gaps": gaps}
		if len(gaps) > 0 {
			out["recommended_probe"] = map[string]any{"language": gaps[0].Language, "package": gaps[0].Package}
			out["instruction"] = "Call probe_dependency with recommended_probe before generic file search."
		}
		return out
	case "probe_dependency":
		lang, _ := call.Arguments["language"].(string)
		pkg, _ := call.Arguments["package"].(string)
		probe, err := probeDependency(profile, lang, pkg, intArg(call.Arguments, "max", 40))
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "probe": probe}
	case "list_files":
		contains, _ := call.Arguments["contains"].(string)
		ext, _ := call.Arguments["extension"].(string)
		files, err := listProfileFiles(profile, contains, ext, intArg(call.Arguments, "max", 80))
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "files": files}
	case "repo_structure":
		dirs, err := repoStructure(profile, intArg(call.Arguments, "max", 40))
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "directories": dirs}
	case "security_relevant_files":
		lang, _ := call.Arguments["language"].(string)
		files, err := securityRelevantFiles(profile, lang, intArg(call.Arguments, "max", 40))
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "files": files}
	case "symbol_inventory":
		q := symbolInventoryQuery{
			Language:     stringArg(call.Arguments, "language"),
			Kind:         stringArg(call.Arguments, "kind"),
			NameContains: stringArg(call.Arguments, "name_contains"),
			PathContains: stringArg(call.Arguments, "path_contains"),
			Max:          intArg(call.Arguments, "max", 120),
		}
		symbols, err := symbolInventory(profile, q)
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "symbols": symbols}
	case "call_inventory":
		q := callInventoryQuery{
			Language:     stringArg(call.Arguments, "language"),
			NameContains: stringArg(call.Arguments, "name_contains"),
			PathContains: stringArg(call.Arguments, "path_contains"),
			Max:          intArg(call.Arguments, "max", 160),
		}
		calls, err := callInventory(profile, q)
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "calls": calls}
	case "assignment_inventory":
		q := assignmentInventoryQuery{
			Language:      stringArg(call.Arguments, "language"),
			NameContains:  stringArg(call.Arguments, "name_contains"),
			ValueContains: stringArg(call.Arguments, "value_contains"),
			PathContains:  stringArg(call.Arguments, "path_contains"),
			Max:           intArg(call.Arguments, "max", 160),
		}
		assignments, err := assignmentInventory(profile, q)
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "assignments": assignments}
	case "search_text":
		pattern, _ := call.Arguments["pattern"].(string)
		matches, err := searchProfileText(profile, pattern, boolArg(call.Arguments, "regex"), boolArg(call.Arguments, "ignoreCase"), intArg(call.Arguments, "max", 80))
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "matches": matches}
	case "search_context":
		pattern, _ := call.Arguments["pattern"].(string)
		matches, err := searchProfileContext(profile, pattern, boolArg(call.Arguments, "regex"), boolArg(call.Arguments, "ignoreCase"), intArg(call.Arguments, "before", 2), intArg(call.Arguments, "after", 2), intArg(call.Arguments, "max", 30))
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "matches": matches}
	case "read_file":
		path, _ := call.Arguments["path"].(string)
		limit := intArg(call.Arguments, "max_bytes", 12000)
		if limit <= 0 || limit > 20000 {
			limit = 12000
		}
		content, ok, err := readProfileFile(profile, path, intArg(call.Arguments, "offset", 0), limit)
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": ok, "path": path, "content": content, "truncated": len(content) >= limit}
	case "read_files":
		paths := stringSliceArg(call.Arguments, "paths")
		files, err := readProfileFiles(profile, paths, intArg(call.Arguments, "max_bytes", 8000))
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "files": files}
	case "function_context":
		path, _ := call.Arguments["path"].(string)
		name, _ := call.Arguments["name"].(string)
		contains, _ := call.Arguments["contains"].(string)
		contexts, err := functionContexts(profile, path, name, contains, intArg(call.Arguments, "max", 8))
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "contexts": contexts}
	case "class_context":
		path, _ := call.Arguments["path"].(string)
		name, _ := call.Arguments["name"].(string)
		contains, _ := call.Arguments["contains"].(string)
		contexts, err := classContexts(profile, path, name, contains, intArg(call.Arguments, "max", 8))
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "contexts": contexts}
	case "module_context":
		path, _ := call.Arguments["path"].(string)
		contains, _ := call.Arguments["contains"].(string)
		contexts, err := moduleContexts(profile, path, contains, intArg(call.Arguments, "max", 8))
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "contexts": contexts}
	case "validate_overlay":
		proposal, warn := proposalFromToolArgs(call.Arguments)
		if warn != "" {
			return map[string]any{"ok": false, "error": warn}
		}
		filtered, warnings := FilterValidProposal(profile, proposal, Config{})
		hints := overlayHints(profile, proposal)
		return map[string]any{"ok": len(warnings) == 0, "valid_adapter_count": len(filtered.AdapterFiles), "warnings": warnings, "hints": hints}
	default:
		return map[string]any{"ok": false, "error": "unknown tool"}
	}
}

func finishOverlayParameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"adapter_files": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"language": map[string]any{"type": "string"},
						"filename": map[string]any{"type": "string"},
						"source":   map[string]any{"type": "string"},
						"evidence": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					},
					"required": []string{"language", "source", "evidence"},
				},
			},
			"notes": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		},
		"required": []string{"adapter_files"},
	}
}

func adapterReferenceText() string {
	return strings.TrimSpace(`
Adapter shape:
adapter <language> {
  package "package-or-project-name" {
    source param -> code.ExternalEntryInput
    source "call_or_value" -> code.HttpInput
    sink path "call.name" -> code.FilePathAccess
    sink path "call.name" arg 1 -> code.SqlExecution
    sink path "call.name" arg all -> code.CommandExecution
    mark "call_or_context" val "required-substring" nval "missing-hardening" -> code.SomeReviewConcept
    mark exact "analysis.function.context" val "name=handler" val "dangerous call" nval "patched guard" -> code.ProtocolStateReview
    mark exact "analysis.module.context" val "var_name:PermissionsByRole" val "RoleNetworkManager" val "PermBackup" nval "RoleAdmin:{PermBackup" -> code.OverbroadRolePermissionGrant
  }
}

When package_reference returns third-party packages, wrap generated API source,
sink, and control mappings in package blocks.
Do not package-wrap exact analysis.*.context marks.
Do not package-wrap first-party workspace package names from local manifests.
Use path/method/receiver only before the quoted pattern. Put arg after the pattern.
Use source param only when the same overlay also adds a concrete sink, mark, or
control for the package. Do not emit source-only source param overlays.
Use mark exact analysis.function.context for narrow local patterns already visible in the scanned function.
Use mark exact analysis.module.context for top-level role, route, permission, ACL, or policy maps.
Use mark exact analysis.class.context for class-level evidence that spans multiple methods.
Call function_context before exact marks and copy short returned substrings from one context only.
Call class_context before analysis.class.context marks and copy structured tokens from one context only.
Call module_context before analysis.module.context marks and copy short returned substrings from one context only.
For exact context marks, each val must be present in the compact context returned
by function_context, class_context, or module_context, and each nval must be absent.
Use existing code.* concepts only. Common target concepts include:
code.CommandExecution, code.CodeEval, code.FilePathAccess, code.SqlExecution,
code.HtmlRender, code.UrlFetch, code.Deserialization, code.RedirectTarget,
code.ResponseHeaderWrite, code.LogOutput, code.RegexCompile, code.XmlParse,
code.DynamicCodeLoad, code.UnsafeUpload, code.ArchiveEntryWrite,
code.CatastrophicRegex,
code.UnboundedCopy, code.RawMemoryCopySize, code.SizeComputation,
code.UnparameterizedSqlQueryParser, code.ProtocolStateReview,
code.MethodGatedRedirectValidationBypass, code.SessionStoredRedirectTarget,
code.AbsolutePathDisclosure, code.SensitiveModelJsonSerializationExposure,
code.OverbroadRolePermissionGrant, code.FilesystemImageDirentTraversal,
code.CommandStringWrapperExecution, code.McpToolCommandTemplateExecution,
	code.JenkinsCredentialsStartupLoadContextExposure,
	code.JenkinsRemoteValidationMissingPostPermission,
	code.JobOutputEventUpdateAuthorizationBypass,
	code.DefaultExternalRelaySecretExposure,
	code.CryptoImproperBlinding.
	`)
}

func conceptReference(topic string) []map[string]string {
	topic = strings.ToLower(topic)
	all := []map[string]string{
		{"concept": "code.SqlExecution", "surface": "scan", "use": "taint sink for SQL execution APIs where caller-controlled data reaches executable query text"},
		{"concept": "code.UnparameterizedSqlQueryParser", "surface": "scan", "use": "mark for query builders/parsers assembling SQL fragments such as order by, direction, filters, raw clauses, or identifiers without allowlists"},
		{"concept": "core.SqlParameterization", "surface": "control", "use": "control concept for parameterization or escaping that neutralizes SQL taint"},
		{"concept": "code.ProtocolStateReview", "surface": "review_only", "use": "review mark for OAuth, protocol, auth, callback, or message state transitions missing required state/cookie/session/order validation"},
		{"concept": "code.ThreadLocalScopeOverwriteWithoutCleanup", "surface": "scan", "use": "mark for request/session/scope lifecycle methods that overwrite ThreadLocal state or per-thread caches without ending/removing the previous scope first"},
		{"concept": "code.DisabledRelationshipMetadataExposure", "surface": "scan", "use": "mark for public relationship/resource metadata helpers that return relationship targets for disabled fields or invisible resources without checking enabled/access/visibility"},
		{"concept": "code.OverbroadRolePermissionGrant", "surface": "scan", "use": "mark for static role/group/permission tables that assign backup, restore, admin, or similarly privileged operations to non-admin roles"},
		{"concept": "code.ParsedUserIdDefaultRootPrivilegeEscalation", "surface": "scan", "use": "mark for UID/GID/user/group parsers that allocate a zeroed process or security identity struct and can return on a bare parsed value before assigning the parsed UID/GID/role into that struct"},
		{"concept": "code.JobOutputEventUpdateAuthorizationBypass", "surface": "scan", "use": "mark for scheduler/plugin child-output handlers that copy update_event from child JSON into job state and later persist it to schedule/event configuration without a config or authorization gate; include nval allow_event_updates_from_jobs or delete data.update_event"},
		{"concept": "code.DefaultExternalRelaySecretExposure", "surface": "scan", "use": "mark for relay/proxy/websocket URL builders that select a hardcoded fallback host while embedding tokens, credentials, connection metadata, or encoded upstream URLs"},
		{"concept": "code.MethodGatedRedirectValidationBypass", "surface": "scan", "use": "mark for URL validation skipped for some HTTP methods before redirect/callback handling"},
		{"concept": "code.SessionStoredRedirectTarget", "surface": "scan", "use": "mark for redirects using session-stored or request-influenced targets without relative/same-origin validation"},
		{"concept": "code.RedirectTarget", "surface": "scan", "use": "taint sink for redirect APIs or methods returning redirect destinations"},
		{"concept": "core.RedirectAllowlist", "surface": "control", "use": "control concept for same-origin, relative URL, or allowlist redirect validation"},
		{"concept": "code.Deserialization", "surface": "scan", "use": "taint sink for unsafe object deserialization such as yaml.load, pickle, unserialize"},
		{"concept": "core.SafeDeserialization", "surface": "control", "use": "control concept for safe deserialization APIs such as safe_load or explicit safe loaders"},
		{"concept": "code.ExpressionEval", "surface": "scan", "use": "taint sink for expression-language or template-message evaluation such as SpEL, MVEL, OGNL, XPath, and Bean Validation buildConstraintViolationWithTemplate"},
		{"concept": "code.HtmlRender", "surface": "scan", "use": "taint sink for raw HTML/template rendering or unescaped response content"},
		{"concept": "code.UnsanitizedSvgUpload", "surface": "scan", "use": "mark for upload services that accept/store SVG files without sanitizing SVG XML/script content before saving"},
		{"concept": "code.LengthDerivedAllocation", "surface": "scan", "use": "mark for resource DoS patterns where request/protocol/body length fields drive allocation or full buffering before an explicit max-size or available-data bound"},
		{"concept": "code.InsecureCookie", "surface": "scan", "use": "mark for session, token, CSRF, auth, or credential cookies set with Secure:false or framework SetCookie wrappers that pass a literal false secure flag instead of the configured secure option"},
		{"concept": "code.SecretComparisonReview", "surface": "scan", "use": "mark for validation functions comparing attacker-supplied CSRF tokens, API keys, webhook secrets, BasicAuth credentials, signatures, or passwords with ordinary equality instead of constant-time comparison; include nvals for scmp, timingSafeEqual, ConstantTimeCompare, MessageDigest.isEqual, or compare_digest"},
		{"concept": "code.CatastrophicRegex", "surface": "scan", "use": "mark for static regular expressions with nested or ambiguous quantified branches used by parser/tokenizer/sanitizer match, replace, exec, or compile paths; include nvals for bounded, possessive, atomic, or linear fixed forms"},
		{"concept": "core.HtmlEscape", "surface": "control", "use": "control concept for HTML escaping or safe text-node wrapping"},
		{"concept": "code.AbsolutePathDisclosure", "surface": "scan", "use": "mark for filesystem, path resolution, error, or warning flows that can expose absolute local paths"},
		{"concept": "code.SensitiveModelJsonSerializationExposure", "surface": "scan", "use": "mark for JSON/API response helpers that serialize a full user, account, settings, credential, or model object instead of explicit safe fields"},
		{"concept": "code.JenkinsCredentialsStartupLoadContextExposure", "surface": "scan", "use": "mark for Jenkins SystemCredentialsProvider-style classes that unmarshal or migrate persisted credentials without an @Initializer after InitMilestone.JOB_LOADED force-loading getInstance during startup"},
		{"concept": "code.JenkinsRemoteValidationMissingPostPermission", "surface": "scan", "use": "mark for Jenkins descriptor doTest/doCheck/doFill form-validation methods that accept @QueryParameter URL or credential values and perform outbound test/connect calls without @POST and checkPermission/hasPermission guards"},
		{"concept": "code.FilesystemImageDirentTraversal", "surface": "scan", "use": "mark for archive or filesystem-image extraction functions that copy image-supplied directory entry names into path buffers before recursive extraction without rejecting '.', '..', separators, or traversal components"},
		{"concept": "code.AssemblyLoadPathTraversal", "surface": "scan", "use": "mark for C#/.NET dynamic assembly loading paths built from caller-controlled type or assembly-name components plus AppContext.BaseDirectory without rejecting traversal or drive-qualified path components"},
		{"concept": "code.CommandStringWrapperExecution", "surface": "scan", "use": "mark for command wrappers that receive one formatted command string containing request-controlled headers, args, paths, or options instead of an argv array or process builder"},
		{"concept": "code.CommandOptionInjection", "surface": "scan", "use": "mark for command builders that pass escaped user-controlled positional arguments to option-taking CLIs without inserting an end-of-options delimiter such as -- or enforcing an option allowlist"},
		{"concept": "code.McpToolCommandTemplateExecution", "surface": "scan", "use": "mark for MCP server.tool handlers whose externally supplied tool callback parameters are interpolated into child_process.exec shell command templates instead of execFile argv arrays; include command-template vals and nval execFile/spawn hardening; use analysis.module.context when the server.tool registration wraps the handler body"},
		{"concept": "code.CryptoImproperBlinding", "surface": "scan", "use": "mark for private-key crypto operations where a randomized blinding factor is inverted or used for unblinding before required subgroup, Jacobi, or square hardening; include Randomize, MultiplicativeInverse, Jacobi/Square evidence and nval the fixed hardening"},
		{"concept": "code.FilePathAccess", "surface": "scan", "use": "taint sink for filesystem path access"},
		{"concept": "core.PathAccessCheck", "surface": "control", "use": "control concept for containment, normalization, allowlist, or traversal guard"},
	}
	if topic == "" {
		return all
	}
	var out []map[string]string
	for _, row := range all {
		hay := strings.ToLower(row["concept"] + " " + row["use"])
		if strings.Contains(hay, topic) {
			out = append(out, row)
		}
	}
	if len(out) == 0 {
		return all
	}
	return out
}

func trustModelSummary(profile Profile) map[string]any {
	cfg := detectScanConfig(profile.Roots)
	out := map[string]any{
		"scan_config":    cfg,
		"languages":      profile.Languages,
		"packages":       cappedStrings(profile.Packages, 80),
		"local_packages": cappedStrings(profile.LocalPkgs, 40),
		"instructions": []string{
			"Use this deterministic profile/trust-boundary setup as repo configuration.",
			"Do not encode profile selection as adapter source mappings.",
			"Only generate adapters for concrete framework/package APIs not already modeled.",
		},
	}
	if len(profile.Manifests) > 0 {
		manifests := profile.Manifests
		if len(manifests) > 20 {
			manifests = manifests[:20]
		}
		out["manifests"] = manifests
	}
	return out
}

type entrypointCandidate struct {
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Language string `json:"language,omitempty"`
	Kind     string `json:"kind"`
	Snippet  string `json:"snippet"`
}

func entrypointInventory(profile Profile, lang string, max int) ([]entrypointCandidate, error) {
	if max <= 0 || max > 200 {
		max = 60
	}
	lang = strings.TrimSpace(lang)
	var out []entrypointCandidate
	err := walkProfileFiles(profile, func(path string) bool {
		fileLang := languageFor(path)
		if lang != "" && fileLang != lang {
			return true
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return true
		}
		if len(data) > 192<<10 {
			data = data[:192<<10]
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if kind := entrypointKind(fileLang, line); kind != "" {
				out = append(out, entrypointCandidate{
					Path:     displayPath(profile, path),
					Line:     i + 1,
					Language: fileLang,
					Kind:     kind,
					Snippet:  compactSnippet(line, 260),
				})
				if len(out) >= max {
					return false
				}
			}
		}
		return true
	})
	return out, err
}

type symbolInventoryQuery struct {
	Language     string
	Kind         string
	NameContains string
	PathContains string
	Max          int
}

type symbolEntry struct {
	Path      string `json:"path"`
	Line      int    `json:"line"`
	Language  string `json:"language"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Signature string `json:"signature"`
	Receiver  string `json:"receiver,omitempty"`
	Container string `json:"container,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
	Score     int    `json:"score,omitempty"`
}

type symbolPattern struct {
	Kind      string
	Expr      *regexp.Regexp
	NameGroup int
}

func symbolInventory(profile Profile, q symbolInventoryQuery) ([]symbolEntry, error) {
	if q.Max <= 0 || q.Max > 500 {
		q.Max = 120
	}
	langFilter := strings.TrimSpace(strings.ToLower(q.Language))
	kindFilter := strings.TrimSpace(strings.ToLower(q.Kind))
	nameFilter := strings.TrimSpace(strings.ToLower(q.NameContains))
	pathFilter := strings.TrimSpace(strings.ToLower(filepath.ToSlash(q.PathContains)))
	seen := map[string]bool{}
	var out []symbolEntry
	err := walkProfileFiles(profile, func(path string) bool {
		fileLang := languageFor(path)
		if langFilter != "" && fileLang != langFilter {
			return true
		}
		display := displayPath(profile, path)
		if pathFilter != "" && !strings.Contains(strings.ToLower(filepath.ToSlash(display)), pathFilter) {
			return true
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return true
		}
		if len(data) > 256<<10 {
			data = data[:256<<10]
		}
		for _, sym := range extractSymbols(fileLang, string(data)) {
			if kindFilter != "" && sym.Kind != kindFilter {
				continue
			}
			if nameFilter != "" && !strings.Contains(strings.ToLower(sym.Name), nameFilter) {
				continue
			}
			sym.Path = display
			sym.Language = fileLang
			sym.Score = securityRelevanceScore(display, sym.Signature+"\n"+sym.Snippet)
			key := fmt.Sprintf("%s:%d:%s:%s", sym.Path, sym.Line, sym.Kind, sym.Name)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, sym)
			if len(out) >= q.Max {
				return false
			}
		}
		return true
	})
	return out, err
}

type callInventoryQuery struct {
	Language     string
	NameContains string
	PathContains string
	Max          int
}

type callEntry struct {
	Path      string `json:"path"`
	Line      int    `json:"line"`
	Language  string `json:"language"`
	Callee    string `json:"callee"`
	Name      string `json:"name"`
	Receiver  string `json:"receiver,omitempty"`
	Enclosing string `json:"enclosing,omitempty"`
	Snippet   string `json:"snippet"`
	Score     int    `json:"score,omitempty"`
}

func callInventory(profile Profile, q callInventoryQuery) ([]callEntry, error) {
	if q.Max <= 0 || q.Max > 500 {
		q.Max = 160
	}
	langFilter := strings.TrimSpace(strings.ToLower(q.Language))
	nameFilter := strings.TrimSpace(strings.ToLower(q.NameContains))
	pathFilter := strings.TrimSpace(strings.ToLower(filepath.ToSlash(q.PathContains)))
	seen := map[string]bool{}
	var out []callEntry
	collectLimit := q.Max * 20
	if collectLimit < 1000 {
		collectLimit = 1000
	}
	err := walkProfileFiles(profile, func(path string) bool {
		fileLang := languageFor(path)
		if langFilter != "" && fileLang != langFilter {
			return true
		}
		display := displayPath(profile, path)
		if pathFilter != "" && !strings.Contains(strings.ToLower(filepath.ToSlash(display)), pathFilter) {
			return true
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return true
		}
		if len(data) > 256<<10 {
			data = data[:256<<10]
		}
		text := string(data)
		symbols := extractSymbols(fileLang, text)
		for _, call := range extractCalls(fileLang, text, symbols) {
			if nameFilter != "" && !strings.Contains(strings.ToLower(call.Callee+" "+call.Name+" "+call.Receiver+" "+call.Enclosing), nameFilter) {
				continue
			}
			call.Path = display
			call.Language = fileLang
			call.Score = securityRelevanceScore(display, call.Snippet)
			key := fmt.Sprintf("%s:%d:%s", call.Path, call.Line, call.Callee)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, call)
			if len(out) >= collectLimit {
				return false
			}
		}
		return true
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Line < out[j].Line
	})
	if len(out) > q.Max {
		out = out[:q.Max]
	}
	return out, err
}

type assignmentInventoryQuery struct {
	Language      string
	NameContains  string
	ValueContains string
	PathContains  string
	Max           int
}

type assignmentEntry struct {
	Path      string   `json:"path"`
	Line      int      `json:"line"`
	Language  string   `json:"language"`
	Target    string   `json:"target"`
	Operator  string   `json:"operator"`
	Value     string   `json:"value"`
	Enclosing string   `json:"enclosing,omitempty"`
	RHSCalls  []string `json:"rhs_calls,omitempty"`
	Snippet   string   `json:"snippet"`
	Score     int      `json:"score,omitempty"`
}

func assignmentInventory(profile Profile, q assignmentInventoryQuery) ([]assignmentEntry, error) {
	if q.Max <= 0 || q.Max > 500 {
		q.Max = 160
	}
	langFilter := strings.TrimSpace(strings.ToLower(q.Language))
	nameFilter := strings.TrimSpace(strings.ToLower(q.NameContains))
	valueFilter := strings.TrimSpace(strings.ToLower(q.ValueContains))
	pathFilter := strings.TrimSpace(strings.ToLower(filepath.ToSlash(q.PathContains)))
	seen := map[string]bool{}
	var out []assignmentEntry
	collectLimit := q.Max * 20
	if collectLimit < 1000 {
		collectLimit = 1000
	}
	err := walkProfileFiles(profile, func(path string) bool {
		fileLang := languageFor(path)
		if langFilter != "" && fileLang != langFilter {
			return true
		}
		display := displayPath(profile, path)
		if pathFilter != "" && !strings.Contains(strings.ToLower(filepath.ToSlash(display)), pathFilter) {
			return true
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return true
		}
		if len(data) > 256<<10 {
			data = data[:256<<10]
		}
		text := string(data)
		symbols := extractSymbols(fileLang, text)
		for _, assignment := range extractAssignments(fileLang, text, symbols) {
			hayName := strings.ToLower(assignment.Target + " " + assignment.Enclosing + " " + strings.Join(assignment.RHSCalls, " ") + " " + assignment.Snippet)
			hayValue := strings.ToLower(assignment.Value + " " + strings.Join(assignment.RHSCalls, " ") + " " + assignment.Snippet)
			if nameFilter != "" && !strings.Contains(hayName, nameFilter) {
				continue
			}
			if valueFilter != "" && !strings.Contains(hayValue, valueFilter) {
				continue
			}
			assignment.Path = display
			assignment.Language = fileLang
			assignment.Score = securityRelevanceScore(display, assignment.Target+"\n"+assignment.Value+"\n"+assignment.Snippet) + assignmentRiskScore(assignment)
			key := fmt.Sprintf("%s:%d:%s:%s", assignment.Path, assignment.Line, assignment.Target, assignment.Value)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, assignment)
			if len(out) >= collectLimit {
				return false
			}
		}
		return true
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Line < out[j].Line
	})
	if len(out) > q.Max {
		out = out[:q.Max]
	}
	return out, err
}

func extractCalls(lang, text string, symbols []symbolEntry) []callEntry {
	re := callPattern(lang)
	if re == nil {
		return nil
	}
	var out []callEntry
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		clean := strings.TrimSpace(line)
		if clean == "" || strings.HasPrefix(clean, "//") || strings.HasPrefix(clean, "#") || isSymbolDeclarationLine(lang, clean) {
			continue
		}
		matches := re.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			callee := normalizeCallee(m[1])
			name := calleeName(callee)
			if callee == "" || name == "" || isControlSymbolName(name) {
				continue
			}
			out = append(out, callEntry{
				Line:      i + 1,
				Callee:    callee,
				Name:      name,
				Receiver:  calleeReceiver(callee),
				Enclosing: enclosingDeclaration(symbols, i+1),
				Snippet:   nearbySnippet(lines, i, 1, 1, 360),
			})
		}
	}
	return out
}

func extractAssignments(lang, text string, symbols []symbolEntry) []assignmentEntry {
	re := assignmentPattern(lang)
	if re == nil {
		return nil
	}
	var out []assignmentEntry
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		clean := strings.TrimSpace(line)
		if clean == "" || strings.HasPrefix(clean, "//") || strings.HasPrefix(clean, "#") || strings.HasPrefix(clean, "*") || isSymbolDeclarationLine(lang, clean) {
			continue
		}
		m := re.FindStringSubmatch(clean)
		if len(m) < 4 {
			continue
		}
		target := normalizeAssignmentSide(m[1])
		operator := strings.TrimSpace(m[2])
		value := normalizeAssignmentValue(m[3])
		if !validAssignmentTarget(target) || value == "" {
			continue
		}
		out = append(out, assignmentEntry{
			Line:      i + 1,
			Target:    target,
			Operator:  operator,
			Value:     compactSnippet(value, 260),
			Enclosing: enclosingDeclaration(symbols, i+1),
			RHSCalls:  callsInExpression(lang, value),
			Snippet:   nearbySnippet(lines, i, 1, 1, 420),
		})
	}
	return out
}

func assignmentPattern(lang string) *regexp.Regexp {
	switch lang {
	case "php":
		return regexp.MustCompile(`^(.+?)\s*(=|\.=|\+=|-=)\s*(.+?);?\s*(?://.*)?$`)
	case "python":
		return regexp.MustCompile(`^(.+?)\s*(=|\+=|-=|\*=|/=)\s*(.+?)\s*(?:#.*)?$`)
	case "go", "javascript", "typescript", "java", "kotlin", "scala", "c", "cpp", "csharp", "rust", "ruby", "bash":
		return regexp.MustCompile(`^(.+?)\s*(:=|=|\+=|-=|\*=|/=|\|\|=|&&=|\?\?=)\s*(.+?);?\s*(?://.*|#.*)?$`)
	default:
		return nil
	}
}

func normalizeAssignmentSide(side string) string {
	side = strings.TrimSpace(side)
	side = strings.TrimPrefix(side, "let ")
	side = strings.TrimPrefix(side, "const ")
	side = strings.TrimPrefix(side, "var ")
	return strings.Join(strings.Fields(side), "")
}

func normalizeAssignmentValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, ";")
	if strings.HasPrefix(strings.TrimSpace(value), ">") {
		return ""
	}
	return strings.TrimSpace(value)
}

func validAssignmentTarget(target string) bool {
	if target == "" || len(target) > 180 {
		return false
	}
	lower := strings.ToLower(target)
	for _, bad := range []string{"if(", "while(", "for(", "switch(", "return", "=>", "==", "!=", "<=", ">="} {
		if strings.Contains(lower, bad) {
			return false
		}
	}
	return regexp.MustCompile(`[\w$\]\)]`).MatchString(target)
}

func callsInExpression(lang string, expr string) []string {
	re := callPattern(lang)
	if re == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range re.FindAllStringSubmatch(expr, -1) {
		if len(m) < 2 {
			continue
		}
		callee := normalizeCallee(m[1])
		name := calleeName(callee)
		if callee == "" || name == "" || isControlSymbolName(name) || seen[callee] {
			continue
		}
		seen[callee] = true
		out = append(out, callee)
		if len(out) >= 8 {
			break
		}
	}
	return out
}

func assignmentRiskScore(entry assignmentEntry) int {
	hay := strings.ToLower(entry.Target + " " + entry.Value + " " + entry.Snippet + " " + strings.Join(entry.RHSCalls, " "))
	score := 0
	for token, weight := range map[string]int{
		"title": 14, "name": 8, "label": 8, "html": 12, "body": 8, "content": 8,
		"snapshot": 16, "audit": 12, "model": 8, "entity": 6, "user": 8,
		"username": 14, "render": 10, "template": 10, "escape": 10, "encode": 10,
		"sanitize": 12, "htmlspecialchars": 18, "html::encode": 18,
		"cmdexecuteservice": 42, "$cmd_string": 36, "x-islandora-args": 30,
		"generatederivativeresponse": 28, "$this->cmd->execute": 32,
		"command string": 22, "array_merge": 12, "headerbag": 12,
		"gnupg": 34, "gpg": 20, "escapeshellarg": 24, "$operation": 24,
		"setoperation": 26, "--list-secret-keys": 30, "--list-public-keys": 30,
		"--list-keys": 26, "--delete-key": 30, "--delete-secret-key": 30,
		"--export": 20, "end-of-options": 32,
		"do_directory": 28, "expand_fs": 34, "romfs_read": 22, "namelen": 16,
		"dirent": 16, "bad filename": 18, "strchr(name": 24, "strcmp(name": 20,
		"pollinghost": 30, "connectionmetadata": 26, "gurl": 20,
		"encodeuricomponent": 18, "herokuapp.com": 26, "wsv2": 18,
		"absoluteurlwithprotocol": 30, "safecanonicalurl": 26, "canonicalurl": 18,
		"getpathinfo": 16, "sanitizeurl": 20, "sanitizeuserinput": 18,
		"x-forwarded-host": 24, "twig": 18, "ssti": 24, "host": 8,
		"asmodelsuccess": 30, "modelname": 18, "getacceptsjson": 14,
		"toarray": 14, "extrafields": 14, "serialize": 12, "json": 8,
		"uid": 16, "gid": 16, "userspec": 28, "endptr": 18, "strtoll": 18,
		"process->user": 22,
		"permission":    12, "role": 10, "admin": 8, "policy": 8, "session": 8,
		"path": 8, "filename": 10, "url": 8, "redirect": 12, "origin": 10,
		"token": 8, "secret": 12, "password": 12, "key": 6,
	} {
		if strings.Contains(hay, token) {
			score += weight
		}
	}
	return score
}

func callPattern(lang string) *regexp.Regexp {
	switch lang {
	case "php":
		return regexp.MustCompile(`((?:\$?[A-Za-z_]\w*|[A-Za-z_]\w*)\s*(?:->|::)\s*[A-Za-z_]\w*|[A-Za-z_]\w*)\s*\(`)
	case "ruby":
		return regexp.MustCompile(`([A-Za-z_]\w*(?:\.[A-Za-z_]\w*[!?=]?|::[A-Za-z_]\w*)?|[A-Za-z_]\w*[!?=]?)\s*\(`)
	case "python", "go", "javascript", "typescript", "java", "kotlin", "scala", "c", "cpp", "csharp", "rust", "bash":
		return regexp.MustCompile(`([A-Za-z_$][\w$]*(?:(?:\.|::|->)[A-Za-z_$][\w$]*)*)\s*\(`)
	default:
		return nil
	}
}

func normalizeCallee(callee string) string {
	callee = strings.Join(strings.Fields(callee), "")
	callee = strings.Trim(callee, ".")
	return callee
}

func calleeName(callee string) string {
	callee = strings.TrimSpace(callee)
	for _, sep := range []string{"->", "::", "."} {
		if idx := strings.LastIndex(callee, sep); idx >= 0 {
			return strings.TrimSpace(callee[idx+len(sep):])
		}
	}
	return callee
}

func calleeReceiver(callee string) string {
	callee = strings.TrimSpace(callee)
	for _, sep := range []string{"->", "::", "."} {
		if idx := strings.LastIndex(callee, sep); idx >= 0 {
			return strings.TrimSpace(callee[:idx])
		}
	}
	return ""
}

func enclosingDeclaration(symbols []symbolEntry, line int) string {
	var best symbolEntry
	for _, sym := range symbols {
		if sym.Line > line {
			continue
		}
		if sym.Kind != "function" && sym.Kind != "method" {
			continue
		}
		if best.Line == 0 || sym.Line > best.Line {
			best = sym
		}
	}
	if best.Name == "" {
		return ""
	}
	if best.Container != "" {
		return best.Container + "." + best.Name
	}
	return best.Name
}

func isSymbolDeclarationLine(lang string, line string) bool {
	for _, pat := range symbolPatterns(lang) {
		if pat.Expr.MatchString(line) {
			return true
		}
	}
	return false
}

func extractSymbols(lang, text string) []symbolEntry {
	patterns := symbolPatterns(lang)
	if len(patterns) == 0 {
		return nil
	}
	var out []symbolEntry
	lines := strings.Split(text, "\n")
	container := ""
	for i, line := range lines {
		clean := strings.TrimSpace(line)
		if clean == "" || strings.HasPrefix(clean, "//") || strings.HasPrefix(clean, "#") || strings.HasPrefix(clean, "*") {
			continue
		}
		for _, pat := range patterns {
			m := pat.Expr.FindStringSubmatch(line)
			if len(m) <= pat.NameGroup {
				continue
			}
			name := strings.TrimSpace(m[pat.NameGroup])
			if name == "" || isControlSymbolName(name) {
				continue
			}
			receiver := ""
			if lang == "go" && pat.Kind == "method" {
				receiver = goReceiverName(clean)
				if receiver != "" {
					container = receiver
				}
			}
			entryContainer := ""
			if pat.Kind == "method" || pat.Kind == "function" {
				entryContainer = container
			}
			out = append(out, symbolEntry{
				Line:      i + 1,
				Kind:      pat.Kind,
				Name:      name,
				Signature: compactSnippet(clean, 240),
				Receiver:  receiver,
				Container: entryContainer,
				Snippet:   nearbySnippet(lines, i, 1, 2, 420),
			})
			if isContainerKind(pat.Kind) {
				container = name
			}
			break
		}
	}
	return out
}

func isContainerKind(kind string) bool {
	switch kind {
	case "class", "interface", "trait", "module", "impl", "struct":
		return true
	default:
		return false
	}
}

func goReceiverName(signature string) string {
	m := regexp.MustCompile(`^\s*func\s+\(\s*(?:[A-Za-z_]\w*\s+)?\*?([A-Za-z_]\w*)`).FindStringSubmatch(signature)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func nearbySnippet(lines []string, idx int, before int, after int, max int) string {
	if idx < 0 || idx >= len(lines) {
		return ""
	}
	start := idx - before
	if start < 0 {
		start = 0
	}
	end := idx + after + 1
	if end > len(lines) {
		end = len(lines)
	}
	var parts []string
	for _, line := range lines[start:end] {
		clean := strings.TrimSpace(line)
		if clean != "" {
			parts = append(parts, clean)
		}
	}
	return compactSnippet(strings.Join(parts, " "), max)
}

func symbolPatterns(lang string) []symbolPattern {
	pat := func(kind, expr string, nameGroup int) symbolPattern {
		return symbolPattern{Kind: kind, Expr: regexp.MustCompile(expr), NameGroup: nameGroup}
	}
	switch lang {
	case "go":
		return []symbolPattern{
			pat("method", `^\s*func\s+\([^)]*\)\s*([A-Za-z_]\w*)\s*\(`, 1),
			pat("function", `^\s*func\s+([A-Za-z_]\w*)\s*\(`, 1),
			pat("class", `^\s*type\s+([A-Za-z_]\w*)\s+struct\b`, 1),
			pat("interface", `^\s*type\s+([A-Za-z_]\w*)\s+interface\b`, 1),
			pat("type", `^\s*type\s+([A-Za-z_]\w*)\b`, 1),
		}
	case "python":
		return []symbolPattern{
			pat("class", `^\s*class\s+([A-Za-z_]\w*)\b`, 1),
			pat("function", `^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`, 1),
		}
	case "php":
		return []symbolPattern{
			pat("class", `^\s*(?:abstract\s+|final\s+)?class\s+([A-Za-z_]\w*)\b`, 1),
			pat("interface", `^\s*interface\s+([A-Za-z_]\w*)\b`, 1),
			pat("trait", `^\s*trait\s+([A-Za-z_]\w*)\b`, 1),
			pat("function", `^\s*(?:(?:public|protected|private|static|final|abstract)\s+)*function\s+&?\s*([A-Za-z_]\w*)\s*\(`, 1),
		}
	case "javascript":
		return []symbolPattern{
			pat("class", `^\s*(?:export\s+default\s+|export\s+)?class\s+([A-Za-z_$][\w$]*)\b`, 1),
			pat("function", `^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(`, 1),
			pat("function", `^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>`, 1),
			pat("method", `^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{?\s*$`, 1),
		}
	case "java", "scala":
		return []symbolPattern{
			pat("class", `^\s*(?:(?:public|protected|private|abstract|final|sealed|static)\s+)*(?:class|record)\s+([A-Za-z_]\w*)\b`, 1),
			pat("interface", `^\s*(?:(?:public|protected|private|abstract|static)\s+)*interface\s+([A-Za-z_]\w*)\b`, 1),
			pat("enum", `^\s*(?:(?:public|protected|private|static)\s+)*enum\s+([A-Za-z_]\w*)\b`, 1),
			pat("method", `^\s*(?:(?:public|protected|private|static|final|abstract|synchronized|native|override)\s+)*[A-Za-z_$][\w$<>\[\].?,\s]*\s+([A-Za-z_$]\w*)\s*\([^;]*\)\s*(?:throws\b.*)?\{?\s*$`, 1),
		}
	case "kotlin":
		return []symbolPattern{
			pat("class", `^\s*(?:(?:data|sealed|open|abstract|public|private|internal)\s+)*class\s+([A-Za-z_]\w*)\b`, 1),
			pat("interface", `^\s*(?:(?:public|private|internal)\s+)*interface\s+([A-Za-z_]\w*)\b`, 1),
			pat("function", `^\s*(?:(?:public|private|protected|internal|override|suspend|inline|operator)\s+)*fun\s+(?:<[^>]+>\s*)?([A-Za-z_]\w*)\s*\(`, 1),
		}
	case "c", "cpp":
		return []symbolPattern{
			pat("class", `^\s*(?:class|struct)\s+([A-Za-z_]\w*)\b`, 1),
			pat("enum", `^\s*(?:typedef\s+)?enum\s+([A-Za-z_]\w*)\b`, 1),
			pat("function", `^\s*(?:(?:static|extern|inline|const|volatile|unsigned|signed|long|short|struct\s+\w+|enum\s+\w+|[A-Za-z_]\w*|\*)\s+)+\*?([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:\{|$)`, 1),
		}
	case "csharp":
		return []symbolPattern{
			pat("class", `^\s*(?:(?:public|protected|private|internal|abstract|sealed|static|partial)\s+)*class\s+([A-Za-z_]\w*)\b`, 1),
			pat("interface", `^\s*(?:(?:public|protected|private|internal|partial)\s+)*interface\s+([A-Za-z_]\w*)\b`, 1),
			pat("method", `^\s*(?:(?:public|protected|private|internal|static|virtual|override|async|sealed|partial)\s+)*[A-Za-z_][\w<>\[\].?,\s]*\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{?\s*$`, 1),
		}
	case "rust":
		return []symbolPattern{
			pat("function", `^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*(?:<[^>]+>)?\s*\(`, 1),
			pat("class", `^\s*(?:pub\s+)?struct\s+([A-Za-z_]\w*)\b`, 1),
			pat("enum", `^\s*(?:pub\s+)?enum\s+([A-Za-z_]\w*)\b`, 1),
			pat("trait", `^\s*(?:pub\s+)?trait\s+([A-Za-z_]\w*)\b`, 1),
			pat("impl", `^\s*impl(?:<[^>]+>)?\s+([A-Za-z_]\w*)\b`, 1),
		}
	case "ruby":
		return []symbolPattern{
			pat("class", `^\s*class\s+([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\b`, 1),
			pat("module", `^\s*module\s+([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\b`, 1),
			pat("function", `^\s*def\s+(?:self\.)?([A-Za-z_]\w*[!?=]?)\b`, 1),
		}
	case "bash":
		return []symbolPattern{
			pat("function", `^\s*(?:function\s+)?([A-Za-z_][\w.-]*)\s*(?:\(\))?\s*\{`, 1),
		}
	default:
		return nil
	}
}

func isControlSymbolName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "if", "for", "while", "switch", "catch", "else", "do", "return", "sizeof", "typeof", "with", "function", "class":
		return true
	default:
		return false
	}
}

func entrypointKind(lang, line string) string {
	lower := strings.ToLower(line)
	switch lang {
	case "go":
		switch {
		case strings.Contains(line, "http.HandleFunc") || strings.Contains(line, ".HandleFunc(") || strings.Contains(line, ".Handle("):
			return "http_route"
		case strings.Contains(line, "ServeHTTP("):
			return "http_handler"
		case strings.Contains(line, "grpc.NewServer") || strings.Contains(line, "Register") && strings.Contains(line, "Server"):
			return "grpc_server"
		case strings.Contains(line, "cobra.Command") || strings.Contains(line, "Use:"):
			return "cli_command"
		}
	case "javascript", "typescript":
		switch {
		case regexp.MustCompile(`\b(app|router)\.(get|post|put|patch|delete|use)\s*\(`).MatchString(line):
			return "http_route"
		case strings.Contains(lower, "createhandler") || strings.Contains(lower, "create server"):
			return "http_handler"
		case strings.Contains(lower, "commander") || strings.Contains(lower, ".command("):
			return "cli_command"
		}
	case "python":
		switch {
		case strings.Contains(line, "@app.route") || strings.Contains(line, "@router.") || strings.Contains(line, "add_url_rule"):
			return "http_route"
		case strings.Contains(line, "FastAPI(") || strings.Contains(line, "APIRouter("):
			return "http_framework"
		case strings.Contains(line, "argparse.") || strings.Contains(line, "click.command"):
			return "cli_command"
		}
	case "java", "kotlin", "scala":
		switch {
		case strings.Contains(line, "@RequestMapping") || strings.Contains(line, "@GetMapping") || strings.Contains(line, "@PostMapping"):
			return "http_route"
		case strings.Contains(line, "extends HttpServlet") || strings.Contains(line, "doGet(") || strings.Contains(line, "doPost("):
			return "http_handler"
		}
	case "php":
		switch {
		case strings.Contains(lower, "$_get") || strings.Contains(lower, "$_post") || strings.Contains(lower, "$_request"):
			return "http_global"
		case strings.Contains(lower, "route::") || strings.Contains(lower, "->get(") || strings.Contains(lower, "->post("):
			return "http_route"
		}
	case "ruby":
		switch {
		case regexp.MustCompile(`^\s*(get|post|put|patch|delete)\s+['"]`).MatchString(line):
			return "http_route"
		case strings.Contains(line, "Rails.application.routes.draw"):
			return "http_routes"
		}
	}
	switch {
	case strings.Contains(lower, "openapi") || strings.Contains(lower, "swagger"):
		return "api_spec"
	case strings.Contains(lower, "webhook"):
		return "webhook"
	case strings.Contains(lower, "config") && (strings.Contains(lower, "load") || strings.Contains(lower, "parse")):
		return "config_load"
	default:
		return ""
	}
}

func adapterCoverage(profile Profile, lang string, max int) map[string]any {
	if max <= 0 || max > 200 {
		max = 80
	}
	gaps := filteredDependencyGaps(profile, lang, max)
	covered := packageReference(profile, lang)
	if len(covered) > max {
		covered = covered[:max]
	}
	out := map[string]any{
		"covered_or_observed_packages": covered,
		"uncovered_gaps":               gaps,
		"gap_count":                    len(gaps),
	}
	if len(gaps) > 0 {
		out["recommended_probe"] = map[string]any{"language": gaps[0].Language, "package": gaps[0].Package}
		out["instruction"] = "Probe high-scoring uncovered dependencies, but only emit adapters for concrete security APIs with sources plus sinks/marks/controls."
	}
	return out
}

func cappedStrings(vals []string, max int) []string {
	out := append([]string(nil), vals...)
	sort.Strings(out)
	if max > 0 && len(out) > max {
		return out[:max]
	}
	return out
}

func packageReference(profile Profile, lang string) []map[string]any {
	lang = strings.TrimSpace(lang)
	seen := map[string]string{}
	add := func(pkg, source string) {
		pkg = strings.TrimSpace(pkg)
		if pkg == "" {
			return
		}
		if _, ok := seen[pkg]; !ok {
			seen[pkg] = source
		}
	}
	for _, man := range profile.Manifests {
		for _, pkg := range man.Packages {
			add(pkg, man.Kind+":"+man.Path)
		}
	}
	if lang != "" {
		for _, imp := range profile.Imports[lang] {
			add(imp, "import:"+lang)
			if i := strings.IndexAny(imp, "./:"); i > 0 {
				add(imp[:i], "import-root:"+lang)
			}
		}
	} else {
		for l, imports := range profile.Imports {
			for _, imp := range imports {
				add(imp, "import:"+l)
				if i := strings.IndexAny(imp, "./:"); i > 0 {
					add(imp[:i], "import-root:"+l)
				}
			}
		}
	}
	for _, pkg := range profile.Packages {
		add(pkg, "profile")
	}
	var pkgs []string
	for pkg := range seen {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)
	out := make([]map[string]any, 0, len(pkgs))
	for _, pkg := range pkgs {
		out = append(out, map[string]any{"package": pkg, "source": seen[pkg]})
	}
	if len(out) > 80 {
		return out[:80]
	}
	return out
}

func filteredDependencyGaps(profile Profile, lang string, max int) []DependencyGap {
	if max <= 0 || max > 200 {
		max = 80
	}
	lang = strings.TrimSpace(lang)
	var out []DependencyGap
	for _, gap := range profile.DepGaps {
		if lang != "" && gap.Language != lang {
			continue
		}
		out = append(out, gap)
		if len(out) >= max {
			break
		}
	}
	return out
}

type dependencyProbe struct {
	Gap     DependencyGap `json:"gap"`
	Terms   []string      `json:"terms"`
	Files   []rankedFile  `json:"files,omitempty"`
	Matches []textMatch   `json:"matches,omitempty"`
}

func probeDependency(profile Profile, lang string, pkg string, max int) (dependencyProbe, error) {
	if max <= 0 || max > 100 {
		max = 40
	}
	lang = strings.TrimSpace(lang)
	pkg = strings.TrimSpace(pkg)
	var gap DependencyGap
	for _, g := range profile.DepGaps {
		if lang != "" && g.Language != lang {
			continue
		}
		if sca.PackageMatches(pkg, g.Package) || sca.PackageMatches(g.Package, pkg) {
			gap = g
			break
		}
		for _, imp := range g.Imports {
			if sca.PackageMatches(pkg, imp) || strings.EqualFold(pkg, imp) {
				gap = g
				break
			}
		}
		if gap.Package != "" {
			break
		}
	}
	if gap.Package == "" {
		gap = DependencyGap{Language: lang, Package: pkg, Source: "argument"}
	}
	terms := dependencyProbeTerms(gap)
	termSet := map[string]bool{}
	for _, term := range terms {
		termSet[strings.ToLower(term)] = true
	}
	var matches []textMatch
	fileScores := map[string]*rankedFile{}
	err := walkProfileFiles(profile, func(path string) bool {
		fileLang := languageFor(path)
		if gap.Language != "" && fileLang != gap.Language {
			return true
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return true
		}
		if len(data) > 256<<10 {
			data = data[:256<<10]
		}
		text := string(data)
		lowerText := strings.ToLower(text)
		hit := false
		for term := range termSet {
			if term != "" && strings.Contains(lowerText, term) {
				hit = true
				break
			}
		}
		if !hit {
			return true
		}
		score := securityRelevanceScore(path, text)
		rf := &rankedFile{Path: path, Language: fileLang, Score: score, Snippet: securitySnippet(text)}
		fileScores[path] = rf
		for i, line := range strings.Split(text, "\n") {
			lowerLine := strings.ToLower(line)
			for _, term := range terms {
				if term != "" && strings.Contains(lowerLine, strings.ToLower(term)) {
					matches = append(matches, textMatch{Path: path, Line: i + 1, Snippet: compactSnippet(line, 240)})
					break
				}
			}
			if len(matches) >= max {
				return false
			}
		}
		return true
	})
	files := make([]rankedFile, 0, len(fileScores))
	for _, rf := range fileScores {
		files = append(files, *rf)
	}
	sort.SliceStable(files, func(i, j int) bool {
		if files[i].Score != files[j].Score {
			return files[i].Score > files[j].Score
		}
		return files[i].Path < files[j].Path
	})
	if len(files) > 12 {
		files = files[:12]
	}
	return dependencyProbe{Gap: gap, Terms: terms, Files: files, Matches: matches}, err
}

func dependencyProbeTerms(gap DependencyGap) []string {
	set := map[string]bool{}
	add := func(term string) {
		term = strings.TrimSpace(strings.Trim(term, `"'`))
		if term == "" || len(term) < 2 {
			return
		}
		set[term] = true
	}
	add(gap.Package)
	add(sca.PackageRoot(gap.Package))
	for _, sep := range []string{"/", ".", "-", "_", ":"} {
		parts := strings.Split(gap.Package, sep)
		if len(parts) > 0 {
			add(parts[len(parts)-1])
		}
	}
	for _, imp := range gap.Imports {
		add(imp)
		for _, sep := range []string{".", "/", "\\", ":"} {
			parts := strings.Split(imp, sep)
			if len(parts) > 0 {
				add(parts[len(parts)-1])
			}
		}
	}
	out := make([]string, 0, len(set))
	for term := range set {
		out = append(out, term)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	if len(out) > 16 {
		out = out[:16]
	}
	return out
}

func overlayHints(profile Profile, proposal Proposal) []string {
	var hints []string
	firstPartyPackages := firstPartyManifestPackages(profile)
	for _, f := range proposal.AdapterFiles {
		src := f.Source
		if strings.Contains(src, "SqlExecution") && !strings.Contains(src, "source ") && !strings.Contains(src, "UnparameterizedSqlQueryParser") {
			hints = append(hints, "SQL sinks need a source/control flow to fire; for library public APIs consider source param -> code.ExternalEntryInput, or use a narrow code.UnparameterizedSqlQueryParser mark for local query-fragment assembly.")
		}
		if strings.Contains(src, "RedirectTarget") && !strings.Contains(src, "source ") && !strings.Contains(src, "ProtocolStateReview") && !strings.Contains(src, "SessionStoredRedirectTarget") {
			hints = append(hints, "Redirect sinks need a source/control flow to fire; for missing OAuth/state/callback validation consider a narrow code.ProtocolStateReview mark.")
		}
		if strings.Contains(src, "ProtocolStateReview") {
			hints = append(hints, "code.ProtocolStateReview is review_only in the current rule packs; it can support review/ATTENTION but will not improve vyql scan caught rate by itself.")
		}
		if strings.Contains(src, "source param") && !strings.Contains(src, "sink ") && !strings.Contains(src, "mark ") && !strings.Contains(src, "control ") {
			hints = append(hints, "source param without a concrete sink, mark, or control is broad source-only expansion; return an empty overlay instead of widening public parameters.")
		}
		if !strings.Contains(src, "package \"") {
			hints = append(hints, "When package_reference returns third-party candidates, wrap generated API source/sink/control mappings in package \"name\" { ... }; keep exact analysis.*.context marks unscoped.")
		}
		for pkg := range firstPartyPackages {
			if strings.Contains(src, `package "`+pkg+`"`) {
				hints = append(hints, "Do not package-gate first-party workspace package "+pkg+"; use a generalized API mapping, exact context mark, or empty overlay.")
				break
			}
		}
		if strings.Contains(src, "mark exact") && !strings.Contains(src, "analysis.function.context") {
			hints = append(hints, "Prefer mark exact \"analysis.function.context\" for function-local anti-patterns so frontend context matching can apply.")
		}
	}
	return hints
}

type dirSummary struct {
	Path      string         `json:"path"`
	Files     int            `json:"files"`
	Score     int            `json:"score,omitempty"`
	Languages map[string]int `json:"languages,omitempty"`
	Examples  []string       `json:"examples,omitempty"`
}

func repoStructure(profile Profile, max int) ([]dirSummary, error) {
	if max <= 0 || max > 100 {
		max = 40
	}
	byDir := map[string]*dirSummary{}
	err := walkProfileFiles(profile, func(path string) bool {
		rel := displayPath(profile, path)
		dir := filepath.ToSlash(filepath.Dir(rel))
		if dir == "." {
			dir = ""
		}
		lang := languageFor(path)
		data, _ := os.ReadFile(path)
		if len(data) > 64<<10 {
			data = data[:64<<10]
		}
		sum := byDir[dir]
		if sum == nil {
			sum = &dirSummary{Path: dir, Languages: map[string]int{}}
			byDir[dir] = sum
		}
		sum.Files++
		if lang != "" {
			sum.Languages[lang]++
		}
		sum.Score += securityRelevanceScore(path, string(data))
		if len(sum.Examples) < 4 {
			sum.Examples = append(sum.Examples, rel)
		}
		return true
	})
	out := make([]dirSummary, 0, len(byDir))
	for _, sum := range byDir {
		out = append(out, *sum)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].Files != out[j].Files {
			return out[i].Files > out[j].Files
		}
		return out[i].Path < out[j].Path
	})
	if len(out) > max {
		out = out[:max]
	}
	return out, err
}

type textContextMatch struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
	Context string `json:"context"`
}

func searchProfileContext(profile Profile, pattern string, useRegex bool, ignoreCase bool, before int, after int, max int) ([]textContextMatch, error) {
	if max <= 0 || max > 100 {
		max = 30
	}
	if before < 0 || before > 8 {
		before = 2
	}
	if after < 0 || after > 8 {
		after = 2
	}
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, nil
	}
	var re *regexp.Regexp
	var err error
	needle := pattern
	if ignoreCase {
		needle = strings.ToLower(needle)
	}
	if useRegex {
		expr := pattern
		if ignoreCase {
			expr = "(?i)" + expr
		}
		re, err = regexp.Compile(expr)
		if err != nil {
			return nil, err
		}
	}
	var matches []textContextMatch
	err = walkProfileFiles(profile, func(path string) bool {
		data, err := os.ReadFile(path)
		if err != nil {
			return true
		}
		if len(data) > 256<<10 {
			data = data[:256<<10]
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			hay := line
			if ignoreCase {
				hay = strings.ToLower(hay)
			}
			ok := false
			if re != nil {
				ok = re.MatchString(line)
			} else {
				ok = strings.Contains(hay, needle)
			}
			if !ok {
				continue
			}
			start := i - before
			if start < 0 {
				start = 0
			}
			end := i + after + 1
			if end > len(lines) {
				end = len(lines)
			}
			var ctx []string
			for n := start; n < end; n++ {
				ctx = append(ctx, fmt.Sprintf("%d: %s", n+1, compactSnippet(lines[n], 280)))
			}
			matches = append(matches, textContextMatch{
				Path:    displayPath(profile, path),
				Line:    i + 1,
				Snippet: compactSnippet(line, 240),
				Context: compactSnippet(strings.Join(ctx, "\n"), 1600),
			})
			if len(matches) >= max {
				return false
			}
		}
		return true
	})
	return matches, err
}

type fileRead struct {
	Path      string `json:"path"`
	Content   string `json:"content,omitempty"`
	OK        bool   `json:"ok"`
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

func readProfileFiles(profile Profile, paths []string, limit int) ([]fileRead, error) {
	if limit <= 0 || limit > 20000 {
		limit = 8000
	}
	if len(paths) > 8 {
		paths = paths[:8]
	}
	var out []fileRead
	total := 0
	for _, path := range paths {
		if total >= 48000 {
			break
		}
		remaining := 48000 - total
		oneLimit := limit
		if oneLimit > remaining {
			oneLimit = remaining
		}
		content, ok, err := readProfileFile(profile, path, 0, oneLimit)
		row := fileRead{Path: path, OK: ok, Truncated: len(content) >= oneLimit}
		if err != nil {
			row.Error = err.Error()
		} else {
			row.Content = content
		}
		total += len(content)
		out = append(out, row)
	}
	return out, nil
}

func displayPath(profile Profile, path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	for _, root := range profile.Roots {
		rabs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		if rel, err := filepath.Rel(rabs, abs); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(path)
}

func readProfileFile(profile Profile, path string, offset int, limit int) (string, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", false, nil
	}
	if offset < 0 {
		offset = 0
	}
	candidates := []string{path}
	if !filepath.IsAbs(path) {
		for _, root := range profile.Roots {
			candidates = append(candidates, filepath.Join(root, path))
		}
		for _, sample := range profile.Samples {
			if sample.Path == path || strings.HasSuffix(sample.Path, string(os.PathSeparator)+path) || filepath.Base(sample.Path) == path {
				candidates = append(candidates, sample.Path)
			}
		}
	}
	var lastErr error
	for _, candidate := range candidates {
		abs, err := filepath.Abs(candidate)
		if err != nil {
			lastErr = err
			continue
		}
		allowed := false
		for _, root := range profile.Roots {
			rabs, err := filepath.Abs(root)
			if err != nil {
				continue
			}
			if abs == rabs || strings.HasPrefix(abs, rabs+string(os.PathSeparator)) {
				allowed = true
				break
			}
		}
		if !allowed {
			lastErr = fmt.Errorf("path is outside scan roots")
			continue
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			lastErr = err
			continue
		}
		if offset > len(data) {
			return "", true, nil
		}
		data = data[offset:]
		if len(data) > limit {
			data = data[:limit]
		}
		return string(data), true, nil
	}
	if lastErr != nil {
		return "", false, lastErr
	}
	return "", false, nil
}

type functionContextPreview struct {
	Path           string   `json:"path"`
	Name           string   `json:"name"`
	Line           int      `json:"line"`
	Prefix         string   `json:"prefix"`
	CompactPreview string   `json:"compact_preview"`
	SuggestedVals  []string `json:"suggested_vals,omitempty"`
}

type classContextPreview struct {
	Path           string   `json:"path"`
	Name           string   `json:"name"`
	Line           int      `json:"line"`
	Prefix         string   `json:"prefix"`
	CompactPreview string   `json:"compact_preview"`
	SuggestedVals  []string `json:"suggested_vals,omitempty"`
}

type moduleContextPreview struct {
	Path           string   `json:"path"`
	Name           string   `json:"name"`
	Line           int      `json:"line"`
	Prefix         string   `json:"prefix"`
	CompactPreview string   `json:"compact_preview"`
	SuggestedVals  []string `json:"suggested_vals,omitempty"`
}

func functionContexts(profile Profile, path string, name string, contains string, max int) ([]functionContextPreview, error) {
	if max <= 0 || max > 20 {
		max = 8
	}
	content, ok, err := readProfileFile(profile, path, 0, 256<<10)
	if err != nil || !ok {
		return nil, err
	}
	abs := path
	if !filepath.IsAbs(abs) {
		for _, root := range profile.Roots {
			candidate := filepath.Join(root, path)
			if _, err := os.Stat(candidate); err == nil {
				abs = candidate
				break
			}
		}
	}
	lang := languageFor(abs)
	var contexts []functionContextPreview
	switch lang {
	case "python":
		contexts = pythonFunctionContexts(abs, content, name, contains, max)
	default:
		contexts = braceFunctionContexts(abs, content, lang, name, contains, max)
	}
	return contexts, nil
}

func classContexts(profile Profile, path string, name string, contains string, max int) ([]classContextPreview, error) {
	if max <= 0 || max > 20 {
		max = 8
	}
	content, ok, err := readProfileFile(profile, path, 0, 256<<10)
	if err != nil || !ok {
		return nil, err
	}
	lang := languageFor(path)
	switch lang {
	case "python":
		return pythonClassContexts(path, content, name, contains, max), nil
	default:
		return braceClassContexts(path, content, lang, name, contains, max), nil
	}
}

func moduleContexts(profile Profile, path string, contains string, max int) ([]moduleContextPreview, error) {
	if max <= 0 || max > 20 {
		max = 8
	}
	content, ok, err := readProfileFile(profile, path, 0, 256<<10)
	if err != nil || !ok {
		return nil, err
	}
	contains = strings.TrimSpace(contains)
	lang := languageFor(path)
	var out []moduleContextPreview
	switch lang {
	case "go":
		out = goModuleContexts(path, content, contains, max)
	default:
		out = braceModuleContexts(path, content, lang, contains, max)
	}
	return out, nil
}

func goModuleContexts(path string, content string, contains string, max int) []moduleContextPreview {
	re := regexp.MustCompile(`(?ms)\bvar\s+(?:\(\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:=[^{}\n]*|[^=\n]*=\s*)`)
	matches := re.FindAllStringSubmatchIndex(content, -1)
	var out []moduleContextPreview
	for _, m := range matches {
		name := content[m[2]:m[3]]
		start := m[0]
		end := endOfTopLevelDecl(content, m[1])
		if end <= start {
			continue
		}
		body := content[start:end]
		if contains != "" && !strings.Contains(body, contains) && !strings.Contains(compactSourceText(body), compactSourceText(contains)) {
			continue
		}
		compact := compactSourceText(body)
		out = append(out, moduleContextPreview{
			Path:           path,
			Name:           name,
			Line:           1 + strings.Count(content[:start], "\n"),
			Prefix:         "lang=go\x00var_name=" + name,
			CompactPreview: compactSnippet(compact, 1800),
			SuggestedVals:  suggestContextVals(name, compact),
		})
		if len(out) >= max {
			break
		}
	}
	return out
}

func braceModuleContexts(path string, content string, lang string, contains string, max int) []moduleContextPreview {
	contains = strings.TrimSpace(contains)
	var out []moduleContextPreview
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "=") && !strings.Contains(trimmed, ":") {
			continue
		}
		if contains != "" && !strings.Contains(trimmed, contains) {
			continue
		}
		compact := compactSourceText(trimmed)
		out = append(out, moduleContextPreview{
			Path:           path,
			Name:           "",
			Line:           i + 1,
			Prefix:         "lang=" + lang,
			CompactPreview: compactSnippet(compact, 1000),
			SuggestedVals:  suggestContextVals("", compact),
		})
		if len(out) >= max {
			break
		}
	}
	return out
}

func endOfTopLevelDecl(content string, start int) int {
	depth := 0
	seenBrace := false
	for i := start; i < len(content); i++ {
		switch content[i] {
		case '{', '(':
			depth++
			seenBrace = true
		case '}', ')':
			if depth > 0 {
				depth--
			}
			if seenBrace && depth == 0 {
				j := i + 1
				for j < len(content) && (content[j] == ',' || content[j] == ' ' || content[j] == '\t' || content[j] == '\r') {
					j++
				}
				return j
			}
		case '\n':
			if !seenBrace && depth == 0 {
				return i
			}
		}
	}
	return len(content)
}

func braceFunctionContexts(path string, content string, lang string, name string, contains string, max int) []functionContextPreview {
	name = strings.TrimSpace(name)
	contains = strings.TrimSpace(contains)
	type fnMatch struct {
		start     int
		headerEnd int
		nameStart int
		nameEnd   int
	}
	var matches []fnMatch
	if lang == "go" {
		re := regexp.MustCompile(`(?m)^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
		for _, m := range re.FindAllStringSubmatchIndex(content, -1) {
			if len(m) >= 4 && m[2] >= 0 {
				matches = append(matches, fnMatch{start: m[0], headerEnd: m[1], nameStart: m[2], nameEnd: m[3]})
			}
		}
	} else if lang == "javascript" || lang == "typescript" {
		re := regexp.MustCompile(`(?m)([A-Za-z_$][A-Za-z0-9_$.]*)\s*=\s*function\s*\(`)
		for _, m := range re.FindAllStringSubmatchIndex(content, -1) {
			if len(m) >= 4 && m[2] >= 0 {
				matches = append(matches, fnMatch{start: m[0], headerEnd: m[1], nameStart: m[2], nameEnd: m[3]})
			}
		}
		namedRe := regexp.MustCompile(`(?m)function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(`)
		for _, m := range namedRe.FindAllStringSubmatchIndex(content, -1) {
			if len(m) >= 4 && m[2] >= 0 {
				matches = append(matches, fnMatch{start: m[0], headerEnd: m[1], nameStart: m[2], nameEnd: m[3]})
			}
		}
	} else {
		re := regexp.MustCompile(`(?m)(?:public|private|protected|static|async|final|function|\s|[\w\\:&*\[\]<>])+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(|(?:public|private|protected|static|final|\s)+[A-Za-z_][A-Za-z0-9_:\<\>\\&*\[\]]*\s+((?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Za-z_][A-Za-z0-9_]*)\s*\(`)
		for _, m := range re.FindAllStringSubmatchIndex(content, -1) {
			if len(m) >= 4 && m[2] >= 0 {
				matches = append(matches, fnMatch{start: m[0], headerEnd: m[1], nameStart: m[2], nameEnd: m[3]})
			} else if len(m) >= 6 && m[4] >= 0 {
				matches = append(matches, fnMatch{start: m[0], headerEnd: m[1], nameStart: m[4], nameEnd: m[5]})
			}
		}
	}
	var out []functionContextPreview
	for _, m := range matches {
		fnName := content[m.nameStart:m.nameEnd]
		if name != "" && !functionNameMatches(fnName, name) {
			continue
		}
		open := strings.Index(content[m.headerEnd:], "{")
		if open < 0 {
			continue
		}
		start := m.start
		bodyStart := m.headerEnd + open
		end := findMatchingBrace(content, bodyStart)
		if end < 0 {
			continue
		}
		body := content[bodyStart : end+1]
		if contains != "" && !strings.Contains(body, contains) && !strings.Contains(compactSourceText(body), compactSourceText(contains)) {
			continue
		}
		compact := compactSourceText(body)
		prefix := "lang=" + lang + "\x00name=" + fnName
		suggested := suggestContextVals(fnName, compact)
		if lang == "go" {
			prefix = "lang=go\x00function_name:" + fnName
			if len(suggested) == 0 {
				suggested = []string{"function_name:" + fnName}
			} else {
				suggested[0] = "function_name:" + fnName
			}
		}
		line := 1 + strings.Count(content[:start], "\n")
		out = append(out, functionContextPreview{
			Path:           path,
			Name:           fnName,
			Line:           line,
			Prefix:         prefix,
			CompactPreview: compactSnippet(compact, 1600),
			SuggestedVals:  suggested,
		})
		if len(out) >= max {
			break
		}
	}
	return out
}

func functionNameMatches(found string, want string) bool {
	found = strings.TrimSpace(found)
	want = strings.TrimSpace(want)
	if found == "" || want == "" {
		return found == want
	}
	if found == want {
		return true
	}
	foundLast := lastIdentifierSegment(found)
	wantLast := lastIdentifierSegment(want)
	return foundLast != "" && foundLast == wantLast
}

func pythonFunctionContexts(path string, content string, name string, contains string, max int) []functionContextPreview {
	name = strings.TrimSpace(name)
	contains = strings.TrimSpace(contains)
	lines := strings.Split(content, "\n")
	var out []functionContextPreview
	defRe := regexp.MustCompile(`^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	for i := 0; i < len(lines); i++ {
		m := defRe.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		fnName := m[1]
		if name != "" && fnName != name {
			continue
		}
		indent := leadingSpaces(lines[i])
		j := i + 1
		for ; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == "" {
				continue
			}
			if leadingSpaces(lines[j]) <= indent && defRe.MatchString(lines[j]) {
				break
			}
			if leadingSpaces(lines[j]) <= indent && !strings.HasPrefix(strings.TrimSpace(lines[j]), "#") {
				break
			}
		}
		body := strings.Join(lines[i:j], "\n")
		if contains != "" && !strings.Contains(body, contains) && !strings.Contains(compactSourceText(body), compactSourceText(contains)) {
			continue
		}
		compact := compactSourceText(body)
		out = append(out, functionContextPreview{
			Path:           path,
			Name:           fnName,
			Line:           i + 1,
			Prefix:         "lang=python\x00name=" + fnName,
			CompactPreview: compactSnippet(compact, 1600),
			SuggestedVals:  suggestContextVals(fnName, compact),
		})
		if len(out) >= max {
			break
		}
	}
	return out
}

func braceClassContexts(path string, content string, lang string, name string, contains string, max int) []classContextPreview {
	name = strings.TrimSpace(name)
	contains = strings.TrimSpace(contains)
	symbols := extractSymbols(lang, content)
	var out []classContextPreview
	for _, sym := range symbols {
		if sym.Kind != "class" && sym.Kind != "interface" && sym.Kind != "record" && sym.Kind != "struct" {
			continue
		}
		if name != "" && sym.Name != name {
			continue
		}
		start := offsetForLine(content, sym.Line)
		if start < 0 {
			continue
		}
		openRel := strings.Index(content[start:], "{")
		if openRel < 0 {
			continue
		}
		open := start + openRel
		end := findMatchingBrace(content, open)
		if end < 0 {
			continue
		}
		body := content[start : end+1]
		compactBody := compactSourceText(body)
		if contains != "" && !strings.Contains(body, contains) && !strings.Contains(compactBody, compactSourceText(contains)) {
			continue
		}
		tokens := classContextTokens(lang, sym.Name, body)
		compact := strings.Join(tokens, "\x00")
		out = append(out, classContextPreview{
			Path:           path,
			Name:           sym.Name,
			Line:           sym.Line,
			Prefix:         "lang=" + lang + "\x00class_name:" + sym.Name,
			CompactPreview: compactSnippet(compact, 2400),
			SuggestedVals:  tokens,
		})
		if len(out) >= max {
			break
		}
	}
	return out
}

func pythonClassContexts(path string, content string, name string, contains string, max int) []classContextPreview {
	name = strings.TrimSpace(name)
	contains = strings.TrimSpace(contains)
	lines := strings.Split(content, "\n")
	classRe := regexp.MustCompile(`^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b`)
	var out []classContextPreview
	for i := 0; i < len(lines); i++ {
		m := classRe.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		className := m[1]
		if name != "" && className != name {
			continue
		}
		indent := leadingSpaces(lines[i])
		j := i + 1
		for ; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == "" {
				continue
			}
			if leadingSpaces(lines[j]) <= indent && !strings.HasPrefix(strings.TrimSpace(lines[j]), "#") {
				break
			}
		}
		body := strings.Join(lines[i:j], "\n")
		compactBody := compactSourceText(body)
		if contains != "" && !strings.Contains(body, contains) && !strings.Contains(compactBody, compactSourceText(contains)) {
			continue
		}
		tokens := classContextTokens("python", className, body)
		compact := strings.Join(tokens, "\x00")
		out = append(out, classContextPreview{
			Path:           path,
			Name:           className,
			Line:           i + 1,
			Prefix:         "lang=python\x00class_name:" + className,
			CompactPreview: compactSnippet(compact, 2400),
			SuggestedVals:  tokens,
		})
		if len(out) >= max {
			break
		}
	}
	return out
}

func classContextTokens(lang string, className string, body string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(tok string) {
		tok = strings.TrimSpace(tok)
		if tok == "" || seen[tok] || len(out) >= 120 {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	if lang == "php" || lang == "ruby" {
		add("lang=" + lang)
	}
	if className != "" {
		add("class_name:" + className)
	}
	header := body
	if i := strings.IndexByte(body, '{'); i >= 0 {
		header = body[:i]
	}
	if m := regexp.MustCompile(`\bextends\s+([A-Za-z_][A-Za-z0-9_.$]*)`).FindStringSubmatch(header); len(m) == 2 {
		add("class_base:" + lastIdentifierSegment(m[1]))
	}
	if m := regexp.MustCompile(`\bimplements\s+([A-Za-z0-9_.$,\s]+)`).FindStringSubmatch(header); len(m) == 2 {
		for _, base := range strings.Split(m[1], ",") {
			add("class_base:" + lastIdentifierSegment(base))
		}
	}
	for _, m := range regexp.MustCompile(`@([A-Za-z_][A-Za-z0-9_.]*)`).FindAllStringSubmatch(body, -1) {
		add("annotation:" + m[1])
		add("annotation:" + lastIdentifierSegment(m[1]))
	}
	symbols := extractSymbols(lang, body)
	for _, sym := range symbols {
		switch sym.Kind {
		case "function", "method":
			add("function_name:" + sym.Name)
		}
	}
	for _, call := range extractCalls(lang, body, symbols) {
		if call.Callee != "" && strings.Contains(call.Callee, ".") {
			add("call_path:" + call.Callee)
		}
		if call.Receiver != "" && call.Name != "" {
			add("call_path:" + call.Receiver + "." + call.Name)
		}
		if call.Name != "" {
			add("call:" + call.Name)
		}
	}
	for _, assignment := range extractAssignments(lang, body, symbols) {
		if assignment.Target != "" {
			add("assign:" + compactSourceText(assignment.Target+"="+assignment.Value))
		}
	}
	return out
}

func lastIdentifierSegment(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "{}()[];")
	if i := strings.LastIndexAny(s, ".$\\"); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSpace(s)
}

func offsetForLine(content string, line int) int {
	if line <= 1 {
		return 0
	}
	current := 1
	for i, r := range content {
		if r == '\n' {
			current++
			if current == line {
				return i + 1
			}
		}
	}
	return -1
}

func findMatchingBrace(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func leadingSpaces(s string) int {
	n := 0
	for _, r := range s {
		if r == ' ' {
			n++
			continue
		}
		if r == '\t' {
			n += 4
			continue
		}
		break
	}
	return n
}

func suggestContextVals(name string, compact string) []string {
	vals := []string{"name=" + name}
	for _, token := range []string{
		"orderBy", "direction", "QUERY_ORDER_DESC", "QUERY_ORDER_ASC", "request.query_params.get(\"state\")",
		"request.cookies.get(\"sso_state\")", "safe_load", "yaml.load", "redirect", "Location", "htmlspecialchars",
		"Html::encode", "$model->title", "$snapshot['title']", "$snapshot[\"title\"]", "$element->username",
		"$element->title", "snapshot", "title", "username",
		"asModelSuccess", "modelName: 'user'", "modelName:\"user\"",
		"$this->request->getAcceptsJson()", "return$this->asModelSuccess($user,modelName:'user',data:$return)",
		"return$this->asSuccess(data:$return)", "$response->data", "toArray", "fields", "extraFields",
		"testConnection", "doTestConnection", "CrowdConfigurationService",
		"Jenkins.ADMINISTER", "checkPermission", "FormValidation", "QueryParameter",
		"hasPermission", "@POST",
		"CmdExecuteService", "$cmd_string", "X-Islandora-Args",
		"generateDerivativeResponse", "$this->cmd->execute",
		"Process::fromShellCommandline", "array_merge", "HeaderBag",
		"fmt.Sprintf", "RunPowershellCmd", "utils.RunPowershellCmd",
		"Get-Volume", "Get-Item", "Format-Volume",
		"Add-PartitionAccessPath", "Remove-PartitionAccessPath",
		"Resize-Partition", "$Env:", "cmdEnv",
		"do_directory", "expand_fs", "romfs_read", "child->namelen",
		"memcpy(newpath+pathlen,romfs_read(offset),newlen)",
		"strchr(name,'/')", "strcmp(name,\"..\")",
		"strtoll(userspec,&endptr,10)", "if(*endptr=='\\0')returnu",
		"u->uid=(int)l", "u->gid=(int)l",
		"safeCanonicalUrl", "absoluteUrlWithProtocol", "getPathInfo", "sanitizeUrl",
		"returnUrlHelper::absoluteUrlWithProtocol($url)",
		"returnDynamicMetaHelper::sanitizeUrl(UrlHelper::absoluteUrlWithProtocol($url))",
		"prepare", "execute", "processOrderBy", "$orderBy['direction']", "$orderBy[\"direction\"]",
		"$request->query->get", "addConditionParam", "whereRaw", "havingRaw", "orderByRaw", "selectRaw",
		"AllowOrigins", "AllowOriginFunc", "AllowAllOrigins", "parseWildcardRules", "validateOrigin",
		"Access-Control-Allow-Origin", "HasPrefix", "HasSuffix", "o[:i-1]", "o[:i]",
		"AttestationToPayloadJSON", "PredicateType", "VerifyImageAttestations",
		"VerifyLocalImageAttestations", "PrintVerification", "checked", "verified",
		"CalculateInverse", "Randomize", "MultiplicativeInverse", "Jacobi",
		"ModularSquareRoot", "modn.Square", "r=modn.Square(r);rInv=modn.MultiplicativeInverse(r)",
		"blind", "unblind",
		"malloc", "calloc", "realloc", "PyString_FromStringAndSize", "ALLOCV_N",
		"memcpy", "memmove", "strcpy", "size", "len", "length", "capacity",
		"offset", "count", "ch>=0x10000", "10*size", "6*size",
	} {
		c := compactSourceText(token)
		if strings.Contains(compact, c) {
			vals = append(vals, c)
		}
	}
	if len(vals) > 10 {
		return vals[:10]
	}
	return vals
}

func listProfileFiles(profile Profile, contains string, ext string, max int) ([]string, error) {
	if max <= 0 || max > 200 {
		max = 80
	}
	contains = strings.ToLower(strings.TrimSpace(contains))
	ext = strings.TrimSpace(ext)
	if ext != "" && !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	var files []string
	err := walkProfileFiles(profile, func(path string) bool {
		base := strings.ToLower(path)
		if contains != "" && !strings.Contains(base, contains) {
			return true
		}
		if ext != "" && filepath.Ext(path) != ext {
			return true
		}
		files = append(files, path)
		return len(files) < max
	})
	sort.Strings(files)
	return files, err
}

type textMatch struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

type rankedFile struct {
	Path     string `json:"path"`
	Language string `json:"language,omitempty"`
	Score    int    `json:"score"`
	Snippet  string `json:"snippet,omitempty"`
}

func securityRelevantFiles(profile Profile, lang string, max int) ([]rankedFile, error) {
	if max <= 0 || max > 100 {
		max = 40
	}
	lang = strings.TrimSpace(lang)
	var files []rankedFile
	err := walkProfileFiles(profile, func(path string) bool {
		fileLang := languageFor(path)
		if lang != "" && fileLang != lang {
			return true
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return true
		}
		if len(data) > 256<<10 {
			data = data[:256<<10]
		}
		text := string(data)
		score := securityRelevanceScore(path, text)
		if score <= 0 {
			return true
		}
		files = append(files, rankedFile{
			Path:     path,
			Language: fileLang,
			Score:    score,
			Snippet:  securitySnippet(text),
		})
		return true
	})
	sort.SliceStable(files, func(i, j int) bool {
		if files[i].Score != files[j].Score {
			return files[i].Score > files[j].Score
		}
		return files[i].Path < files[j].Path
	})
	if len(files) > max {
		files = files[:max]
	}
	return files, err
}

func securitySnippet(text string) string {
	for _, token := range []string{
		"exec(", "system(", "shell_exec", "passthru", "proc_open", "popen(",
		"eval(", "unserialize", "yaml.load", "pickle.load", "file_put_contents",
		"buildConstraintViolationWithTemplate", "addConstraintViolation",
		"ConstraintValidator", "ConstraintValidatorContext",
		"IllegalArgumentException", "getMessage()",
		"move_uploaded_file", "rename(", "copy(", "unlink(", "touch(",
		"getAbsolutePath", "absolutePath", "absolute path", "E_WARNING",
		"RuntimeException", "FileOperationErrorException",
		"UploadedFile", "FileUploader", "storeAs(", "getClientOriginalExtension",
		"getClientMimeType", "svg", "getSvgDimensions", "svgSanitize",
		"sanitizeSvg", "Sanitizer",
		"Html::encode", "htmlspecialchars", "escapeHtml", "$model->title",
		"$snapshot['title']", "$snapshot[\"title\"]", "snapshot", "audit", "xss",
		"asModelSuccess", "modelName", "getAcceptsJson", "$response->data",
		"toArray", "extraFields", "serialize",
		"testConnection", "doTestConnection", "CrowdConfigurationService",
		"Jenkins.ADMINISTER", "checkPermission", "FormValidation", "QueryParameter",
		"secret", "token", "credential",
		"CmdExecuteService", "$cmd_string", "X-Islandora-Args",
		"generateDerivativeResponse", "$this->cmd->execute",
		"Process::fromShellCommandline", "command string",
		"escapeshellarg", "$operation", "setOperation", "--list-secret-keys",
		"--list-public-keys", "--list-keys", "--delete-key",
		"--delete-secret-key", "--export", "end-of-options", "GnuPG", "gpg",
		"memcpy(newpath + pathlen", "child->namelen", "do_directory",
		"expand_fs", "romfs_read", "namelen", "dirent",
		"bad filename", "strchr(name", "strcmp(name",
		"userspec", "strtoll", "u->uid", "u->gid", "process->user",
		"make_oci_process_user", "--user",
		"safeCanonicalUrl", "absoluteUrlWithProtocol", "getPathInfo", "sanitizeUrl",
		"sanitizeUserInput", "X-Forwarded-Host", "host header", "Twig", "SSTI",
		"pollingHost", "connectionMetadata", "gurl", "encodeURIComponent",
		"herokuapp.com", "wsv2",
		"redirect", "header(", "$_GET", "$_POST", "$_FILES", "$_REQUEST",
		"Access-Control-Allow-Origin", "AllowOrigins", "AllowOriginFunc",
		"AllowAllOrigins", "validateOrigin", "wildcard", "HasPrefix",
		"AttestationToPayloadJSON", "PredicateType", "VerifyImageAttestations",
		"VerifyLocalImageAttestations", "PrintVerification", "attestation",
		"CalculateInverse", "MultiplicativeInverse", "Randomize", "Jacobi",
		"ModularSquareRoot", "modn.Square", "blind", "unblind", "Rabin",
		"restore", "import", "backup", "archive", "extract", "filename", "rrdtool",
		"ThreadLocal", "beginRequest", "endRequest", "activate(", "deactivate(",
		"associate(", "dissociate(", "RequestScoped",
		"isFieldEnabled", "getRelatableResourceTypes", "ResourceTypeRelationship",
		"PermissionsByRole", "RoleNetworkManager", "PermBackup", "PermRestore",
		"permission", "authorization", "middleware",
	} {
		if idx := strings.Index(strings.ToLower(text), strings.ToLower(token)); idx >= 0 {
			start := idx - 120
			if start < 0 {
				start = 0
			}
			end := idx + 220
			if end > len(text) {
				end = len(text)
			}
			return compactSnippet(text[start:end], 360)
		}
	}
	return compactSnippet(text, 360)
}

func searchProfileText(profile Profile, pattern string, useRegex bool, ignoreCase bool, max int) ([]textMatch, error) {
	if max <= 0 || max > 200 {
		max = 80
	}
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, nil
	}
	var re *regexp.Regexp
	var err error
	needle := pattern
	if ignoreCase {
		needle = strings.ToLower(needle)
	}
	if useRegex {
		expr := pattern
		if ignoreCase {
			expr = "(?i)" + expr
		}
		re, err = regexp.Compile(expr)
		if err != nil {
			return nil, err
		}
	}
	var matches []textMatch
	err = walkProfileFiles(profile, func(path string) bool {
		data, err := os.ReadFile(path)
		if err != nil {
			return true
		}
		if len(data) > 256<<10 {
			data = data[:256<<10]
		}
		for i, line := range strings.Split(string(data), "\n") {
			hay := line
			if ignoreCase {
				hay = strings.ToLower(hay)
			}
			ok := false
			if re != nil {
				ok = re.MatchString(line)
			} else {
				ok = strings.Contains(hay, needle)
			}
			if ok {
				matches = append(matches, textMatch{Path: path, Line: i + 1, Snippet: compactSnippet(line, 220)})
				if len(matches) >= max {
					return false
				}
			}
		}
		return true
	})
	return matches, err
}

func walkProfileFiles(profile Profile, visit func(path string) bool) error {
	for _, root := range profile.Roots {
		if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if skipDir(d.Name()) && path != root {
					return filepath.SkipDir
				}
				return nil
			}
			lang := languageFor(path)
			if lang == "" && !knownConfigOrManifest(path) {
				return nil
			}
			if !visit(path) {
				return filepath.SkipAll
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func knownConfigOrManifest(path string) bool {
	switch strings.ToLower(filepath.Base(path)) {
	case "package.json", "go.mod", "requirements.txt", "pyproject.toml", "composer.json", "pom.xml", "build.gradle", "cargo.toml":
		return true
	default:
		return false
	}
}

func compactSnippet(s string, limit int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > limit {
		return s[:limit]
	}
	return s
}

func intArg(args map[string]any, key string, fallback int) int {
	v, ok := args[key]
	if !ok {
		return fallback
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		i, err := n.Int64()
		if err == nil {
			return int(i)
		}
	}
	return fallback
}

func boolArg(args map[string]any, key string) bool {
	v, _ := args[key].(bool)
	return v
}

func stringArg(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return strings.TrimSpace(v)
}

func stringSliceArg(args map[string]any, key string) []string {
	raw, ok := args[key]
	if !ok {
		return nil
	}
	switch vals := raw.(type) {
	case []string:
		return vals
	case []any:
		out := make([]string, 0, len(vals))
		for _, v := range vals {
			s, _ := v.(string)
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func proposalFromToolArgs(args map[string]any) (Proposal, string) {
	data, err := json.Marshal(args)
	if err != nil {
		return Proposal{}, err.Error()
	}
	var raw struct {
		AdapterFiles []AdapterFile `json:"adapter_files"`
		Notes        []string      `json:"notes"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return Proposal{}, err.Error()
	}
	if len(raw.AdapterFiles) == 0 && len(raw.Notes) == 0 {
		return Proposal{AdapterFiles: raw.AdapterFiles, Notes: raw.Notes}, "empty overlay must include notes explaining core coverage or why no validated adapter target exists"
	}
	return Proposal{AdapterFiles: raw.AdapterFiles, Notes: raw.Notes}, ""
}

func vertexResponseParts(data []byte) (string, []vertexToolCall, []map[string]any, string, error) {
	var raw struct {
		Candidates []struct {
			FinishReason string `json:"finishReason"`
			Content      struct {
				Parts []map[string]any `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return string(data), nil, nil, "", nil
	}
	if len(raw.Candidates) == 0 {
		return string(data), nil, nil, "", nil
	}
	var texts []string
	var calls []vertexToolCall
	for i, part := range raw.Candidates[0].Content.Parts {
		if text, _ := part["text"].(string); text != "" {
			texts = append(texts, text)
		}
		fc, _ := part["functionCall"].(map[string]any)
		name, _ := fc["name"].(string)
		if name != "" {
			args, _ := fc["args"].(map[string]any)
			if args == nil {
				args = map[string]any{}
			}
			calls = append(calls, vertexToolCall{
				ID:        fmt.Sprintf("%s_%d", name, i),
				Name:      name,
				Arguments: args,
			})
		}
	}
	return strings.Join(texts, "\n"), calls, raw.Candidates[0].Content.Parts, raw.Candidates[0].FinishReason, nil
}

func (p *VertexProvider) endpoint() string {
	return fmt.Sprintf("https://%s/v1/projects/%s/locations/%s/publishers/google/models/%s:generateContent",
		p.vertexHost(), p.project, p.location, p.model)
}

func (p *VertexProvider) cachedContentsEndpoint() string {
	return fmt.Sprintf("https://%s/v1/projects/%s/locations/%s/cachedContents",
		p.vertexHost(), p.project, p.location)
}

func (p *VertexProvider) modelResource() string {
	return fmt.Sprintf("projects/%s/locations/%s/publishers/google/models/%s",
		p.project, p.location, p.model)
}

func (p *VertexProvider) vertexHost() string {
	host := "aiplatform.googleapis.com"
	if p.location != "global" {
		host = p.location + "-aiplatform.googleapis.com"
	}
	return host
}
