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
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/oauth2/google"
)

type VertexConfig struct {
	Project         string
	Location        string
	Model           string
	CredentialsFile string
	Temperature     float64
	Timeout         time.Duration
}

type VertexProvider struct {
	project     string
	location    string
	model       string
	temperature float64
	http        *http.Client
	token       func(context.Context) (string, error)
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
		project:     cfg.Project,
		location:    cfg.Location,
		model:       cfg.Model,
		temperature: cfg.Temperature,
		http:        &http.Client{Timeout: cfg.Timeout},
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
	prompt := `You are a repo-local VyQL adapter preparation agent.

Use tools to inspect bounded repo evidence, then call finish_overlay.

Rules:
- Generate only adapter declarations for languages present in the profile.
- Use explicit package-scoped adapter blocks when package/import/manifest
  evidence exists. This is locality for the proposed mapping, not a
  concept-level package gate. The validator rejects package-less mappings in
  that case. Example:
  adapter python {
    package "fastapi-sso" {
      source param -> code.ExternalEntryInput
      sink path "RedirectResponse" arg 0 -> code.RedirectTarget
    }
  }
- Keep mappings conservative and selector-backed.
- Adapter source must be valid VyQL DSL, for example:
  adapter python {
    source "request.args" -> code.HttpInput
    sink path "open" -> code.FilePathAccess
  }
- Valid sink syntax puts arg after the quoted pattern:
  sink path "do_cmd" arg 2 -> code.CommandExecution
  sink path "do_local_cmd" arg 0 -> code.CommandExecution
  sink path "run" arg all -> code.CommandExecution
- For libraries/frameworks, public API parameters can be marked as external
  entry input when the repository code itself is the package being scanned:
  source param -> code.ExternalEntryInput
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
- Before writing mark exact "analysis.function.context", call function_context
  for the target function and choose val/nval substrings from that returned
  single function context. Do not combine vals from different functions.
- For scan catch-rate work, prefer concepts with surface=scan from
  concept_reference. surface=review_only can be useful for review/ATTENTION,
  but it will not make vyql scan emit a finding unless a scan rule matches it.
- Once validate_overlay returns ok=true with at least one valid adapter, call
  finish_overlay immediately unless a specific validation warning requires a
  correction.
- Prefer this workflow:
  1. inspect_profile
  2. adapter_reference, package_reference, and concept_reference
  3. security_relevant_files, then list_files or search_text for exact
     wrappers/routes/config. For PHP and similar ecosystems, include helper
     files such as .inc/.phtml and search command sinks plus restore/import,
     upload, archive, and filename flows. For Java/C#/server frameworks,
     inspect lifecycle/concurrency files containing ThreadLocal, request/session
     context, begin/end, activate/deactivate, associate/dissociate, cache set,
     or cleanup/remove before chasing unrelated example SQL/deserialization code.
     For authz/data-model CVEs, inspect public methods returning relationship,
     resource, field, permission, or metadata lists and look for missing enabled,
     access, ownership, or visibility checks before returns.
  4. read_file on exact evidence
  5. function_context before any exact context mark
  6. validate_overlay if producing any non-empty adapter
  7. finish_overlay only after validation is clean, or empty if no useful
     repo-local adapter can improve scan.

Repo profile:
` + string(payload)
	contents := []map[string]any{{
		"role":  "user",
		"parts": []map[string]any{{"text": prompt}},
	}}
	var log []AgentStep
	var lastValid Proposal
	const maxAgentSteps = 10
agentLoop:
	for step := 1; step <= maxAgentSteps; step++ {
		text, calls, modelParts, finish, err := p.generateAgentStep(ctx, contents)
		if err != nil {
			return Proposal{AgentLog: log}, err
		}
		entry := AgentStep{Index: step, Text: text, Finish: finish}
		for _, call := range calls {
			entry.ToolCalls = append(entry.ToolCalls, AgentToolCall{ID: call.ID, Name: call.Name, Arguments: call.Arguments})
		}
		if len(calls) == 0 {
			proposal := Proposal{AgentLog: append(log, entry)}
			if strings.TrimSpace(text) != "" {
				if err := json.Unmarshal([]byte(text), &proposal); err == nil {
					proposal.AgentLog = append(log, entry)
				} else {
					proposal.Notes = append(proposal.Notes, "agent returned text without finish_overlay tool call")
				}
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
				validationWarnings := []string(nil)
				validAdapterCount := 0
				if warn == "" {
					filtered, warnings := FilterValidProposal(profile, proposal, Config{})
					validationWarnings = warnings
					validAdapterCount = len(filtered.AdapterFiles)
				}
				ok := warn == "" && len(validationWarnings) == 0
				toolResult := map[string]any{
					"ok":                  ok,
					"valid_adapter_count": validAdapterCount,
				}
				if warn != "" {
					toolResult["error"] = warn
				}
				if len(validationWarnings) > 0 {
					toolResult["warnings"] = validationWarnings
					proposal.Notes = append(proposal.Notes, "agent overlay validation warnings: "+strings.Join(validationWarnings, "; "))
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
				return proposal, nil
			}
			result := p.executePrepTool(profile, call)
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
		log = append(log, entry)
	}
	if len(lastValid.AdapterFiles) > 0 {
		lastValid.AgentLog = log
		lastValid.Notes = append(lastValid.Notes, "agent reached max_steps after validating overlay; using last valid proposal")
		return lastValid, nil
	}
	return Proposal{AgentLog: log, Notes: []string{"agent reached max_steps without finish_overlay"}}, nil
}

type vertexToolCall struct {
	ID        string
	Name      string
	Arguments map[string]any
}

func (p *VertexProvider) generateAgentStep(ctx context.Context, contents []map[string]any) (string, []vertexToolCall, []map[string]any, string, error) {
	body := map[string]any{
		"contents": contents,
		"tools": []map[string]any{{"functionDeclarations": []map[string]any{
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
				"name":        "validate_overlay",
				"description": "Validate proposed VyQL adapter overlay JSON before finalizing.",
				"parameters":  finishOverlayParameters(),
			},
			{
				"name":        "finish_overlay",
				"description": "Finish with repo-local VyQL adapter overlay files.",
				"parameters":  finishOverlayParameters(),
			},
		}}},
		"generationConfig": map[string]any{
			"temperature": p.temperature,
		},
	}
	b, _ := json.Marshal(body)
	token, err := p.token(ctx)
	if err != nil {
		return "", nil, nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint(), bytes.NewReader(b))
	if err != nil {
		return "", nil, nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := p.http.Do(req)
	if err != nil {
		return "", nil, nil, "", err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", nil, nil, "", fmt.Errorf("agentic prep: vertex HTTP %d: %s", res.StatusCode, string(data))
	}
	return vertexResponseParts(data)
}

func (p *VertexProvider) executePrepTool(profile Profile, call vertexToolCall) map[string]any {
	switch call.Name {
	case "inspect_profile":
		return map[string]any{"ok": true, "profile": profile}
	case "adapter_reference":
		return map[string]any{"ok": true, "reference": adapterReferenceText()}
	case "concept_reference":
		topic, _ := call.Arguments["topic"].(string)
		return map[string]any{"ok": true, "concepts": conceptReference(topic)}
	case "package_reference":
		lang, _ := call.Arguments["language"].(string)
		return map[string]any{"ok": true, "packages": packageReference(profile, lang), "syntax": `adapter <language> { package "<package>" { ...mappings... } }`}
	case "list_files":
		contains, _ := call.Arguments["contains"].(string)
		ext, _ := call.Arguments["extension"].(string)
		files, err := listProfileFiles(profile, contains, ext, intArg(call.Arguments, "max", 80))
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "files": files}
	case "security_relevant_files":
		lang, _ := call.Arguments["language"].(string)
		files, err := securityRelevantFiles(profile, lang, intArg(call.Arguments, "max", 40))
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true, "files": files}
	case "search_text":
		pattern, _ := call.Arguments["pattern"].(string)
		matches, err := searchProfileText(profile, pattern, boolArg(call.Arguments, "regex"), boolArg(call.Arguments, "ignoreCase"), intArg(call.Arguments, "max", 80))
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
	case "function_context":
		path, _ := call.Arguments["path"].(string)
		name, _ := call.Arguments["name"].(string)
		contains, _ := call.Arguments["contains"].(string)
		contexts, err := functionContexts(profile, path, name, contains, intArg(call.Arguments, "max", 8))
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
		hints := overlayHints(proposal)
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
  }
}

When package_reference returns packages, wrap generated mappings in package blocks.
Use path/method/receiver only before the quoted pattern. Put arg after the pattern.
Use source param for library/package code whose public function parameters are caller-controlled.
Use mark exact analysis.function.context for narrow local patterns already visible in the scanned function.
Call function_context before exact marks and copy short returned substrings from one context only.
For marks, each val must be present in the compact function context and each nval must be absent.
Use existing code.* concepts only. Common target concepts include:
code.CommandExecution, code.CodeEval, code.FilePathAccess, code.SqlExecution,
code.HtmlRender, code.UrlFetch, code.Deserialization, code.RedirectTarget,
code.ResponseHeaderWrite, code.LogOutput, code.RegexCompile, code.XmlParse,
code.DynamicCodeLoad, code.UnsafeUpload, code.ArchiveEntryWrite,
code.UnboundedCopy, code.RawMemoryCopySize, code.SizeComputation,
code.UnparameterizedSqlQueryParser, code.ProtocolStateReview,
code.MethodGatedRedirectValidationBypass, code.SessionStoredRedirectTarget.
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
		{"concept": "code.MethodGatedRedirectValidationBypass", "surface": "scan", "use": "mark for URL validation skipped for some HTTP methods before redirect/callback handling"},
		{"concept": "code.SessionStoredRedirectTarget", "surface": "scan", "use": "mark for redirects using session-stored or request-influenced targets without relative/same-origin validation"},
		{"concept": "code.RedirectTarget", "surface": "scan", "use": "taint sink for redirect APIs or methods returning redirect destinations"},
		{"concept": "core.RedirectAllowlist", "surface": "control", "use": "control concept for same-origin, relative URL, or allowlist redirect validation"},
		{"concept": "code.Deserialization", "surface": "scan", "use": "taint sink for unsafe object deserialization such as yaml.load, pickle, unserialize"},
		{"concept": "core.SafeDeserialization", "surface": "control", "use": "control concept for safe deserialization APIs such as safe_load or explicit safe loaders"},
		{"concept": "code.HtmlRender", "surface": "scan", "use": "taint sink for raw HTML/template rendering or unescaped response content"},
		{"concept": "core.HtmlEscape", "surface": "control", "use": "control concept for HTML escaping or safe text-node wrapping"},
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

func overlayHints(proposal Proposal) []string {
	var hints []string
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
		if !strings.Contains(src, "package \"") {
			hints = append(hints, "When package_reference returns candidates, wrap mappings in package \"name\" { ... } so the overlay is dependency-gated.")
		}
		if strings.Contains(src, "mark exact") && !strings.Contains(src, "analysis.function.context") {
			hints = append(hints, "Prefer mark exact \"analysis.function.context\" for function-local anti-patterns so frontend context matching can apply.")
		}
	}
	return hints
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

func braceFunctionContexts(path string, content string, lang string, name string, contains string, max int) []functionContextPreview {
	name = strings.TrimSpace(name)
	contains = strings.TrimSpace(contains)
	re := regexp.MustCompile(`(?m)(?:public|private|protected|static|async|final|function|\s|[\w\\:&*\[\]<>])+function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(|(?:public|private|protected|static|final|\s)+[A-Za-z_][A-Za-z0-9_:\<\>\\&*\[\]]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	matches := re.FindAllStringSubmatchIndex(content, -1)
	var out []functionContextPreview
	for _, m := range matches {
		fnName := ""
		if m[2] >= 0 {
			fnName = content[m[2]:m[3]]
		} else if len(m) >= 6 && m[4] >= 0 {
			fnName = content[m[4]:m[5]]
		}
		if name != "" && fnName != name {
			continue
		}
		open := strings.Index(content[m[1]:], "{")
		if open < 0 {
			continue
		}
		start := m[0]
		bodyStart := m[1] + open
		end := findMatchingBrace(content, bodyStart)
		if end < 0 {
			continue
		}
		body := content[bodyStart : end+1]
		if contains != "" && !strings.Contains(body, contains) && !strings.Contains(compactSourceText(body), compactSourceText(contains)) {
			continue
		}
		compact := compactSourceText(body)
		line := 1 + strings.Count(content[:start], "\n")
		out = append(out, functionContextPreview{
			Path:           path,
			Name:           fnName,
			Line:           line,
			Prefix:         "lang=" + lang + "\x00name=" + fnName,
			CompactPreview: compactSnippet(compact, 1600),
			SuggestedVals:  suggestContextVals(fnName, compact),
		})
		if len(out) >= max {
			break
		}
	}
	return out
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
		"prepare", "execute", "processOrderBy", "$orderBy['direction']", "$orderBy[\"direction\"]",
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
		"redirect", "header(", "$_GET", "$_POST", "$_FILES", "$_REQUEST",
		"restore", "import", "backup", "archive", "extract", "filename", "rrdtool",
		"ThreadLocal", "beginRequest", "endRequest", "activate(", "deactivate(",
		"associate(", "dissociate(", "RequestScoped",
		"isFieldEnabled", "getRelatableResourceTypes", "ResourceTypeRelationship",
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
	host := "aiplatform.googleapis.com"
	if p.location != "global" {
		host = p.location + "-aiplatform.googleapis.com"
	}
	return fmt.Sprintf("https://%s/v1/projects/%s/locations/%s/publishers/google/models/%s:generateContent",
		host, p.project, p.location, p.model)
}
