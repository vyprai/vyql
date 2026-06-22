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
  single function context. Do not combine vals from different functions.
- Before writing mark exact "analysis.module.context", call module_context
  for the target file and choose val/nval substrings from one returned top-level
  declaration context. Use this for static role, permission, route, or policy maps.
- For scan catch-rate work, prefer concepts with surface=scan from
  concept_reference. surface=review_only can be useful for review/ATTENTION,
  but it will not make vyql scan emit a finding unless a scan rule matches it.
- Once validate_overlay returns ok=true with at least one valid adapter, call
  finish_overlay immediately unless a specific validation warning requires a
  correction.
- Prefer repo_structure, search_context, and read_files over repeated
  single-file reads. Use read_file only when one exact file or offset is needed.
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
  5. security_relevant_files, then list_files, search_context, or search_text
     for exact
     wrappers/routes/config. For PHP and similar ecosystems, include helper
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
     For upload XSS CVEs, inspect upload services/helpers that derive extensions
     from client filenames or MIME types and store SVG, HTML, or XML-capable files;
     check for SVG/XML sanitizers before storeAs/move/save/write.
     For information-disclosure CVEs, inspect filesystem drivers and methods
     using rename/copy/unlink/touch/move_uploaded_file/readfile on absolute
     paths, especially when failures become exceptions or framework warnings;
     check for warning suppression, sanitized error handling, or path removal.
  6. read_files or read_file on exact evidence
  7. function_context before any exact context mark
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
			return Proposal{AgentLog: log, Notes: notes}, err
		}
		p.debugf("step=%d finish=%s text_bytes=%d tool_calls=%s", step, finish, len(text), toolCallNames(calls))
		entry := AgentStep{Index: step, Text: text, Finish: finish}
		for _, call := range calls {
			entry.ToolCalls = append(entry.ToolCalls, AgentToolCall{ID: call.ID, Name: call.Name, Arguments: call.Arguments})
		}
		if len(calls) == 0 {
			proposal := Proposal{AgentLog: append(log, entry), Notes: append([]string{}, notes...)}
			if strings.TrimSpace(text) != "" {
				if err := json.Unmarshal([]byte(text), &proposal); err == nil {
					proposal.AgentLog = append(log, entry)
					proposal.Notes = append(notes, proposal.Notes...)
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
			result := p.executePrepTool(profile, call)
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
					"text": "Decision checkpoint: you have enough deterministic repo setup evidence. Do not keep searching. If you have a concrete adapter with source plus sink/mark/control evidence, call validate_overlay now. If not, call finish_overlay with adapter_files=[] and concise notes about scan_config/trust_model and missing concrete adapter evidence.",
				}},
			})
		}
		log = append(log, entry)
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
    mark exact "analysis.module.context" val "var_name:PermissionsByRole" val "RoleNetworkManager" val "PermBackup" nval "RoleAdmin:{PermBackup" -> code.OverbroadRolePermissionGrant
  }
}

When package_reference returns packages, wrap generated mappings in package blocks.
Use path/method/receiver only before the quoted pattern. Put arg after the pattern.
Use source param only when the same overlay also adds a concrete sink, mark, or
control for the package. Do not emit source-only source param overlays.
Use mark exact analysis.function.context for narrow local patterns already visible in the scanned function.
Use mark exact analysis.module.context for top-level role, route, permission, ACL, or policy maps.
Call function_context before exact marks and copy short returned substrings from one context only.
Call module_context before analysis.module.context marks and copy short returned substrings from one context only.
For exact context marks, each val must be present in the compact context returned
by function_context or module_context, and each nval must be absent.
Use existing code.* concepts only. Common target concepts include:
code.CommandExecution, code.CodeEval, code.FilePathAccess, code.SqlExecution,
code.HtmlRender, code.UrlFetch, code.Deserialization, code.RedirectTarget,
code.ResponseHeaderWrite, code.LogOutput, code.RegexCompile, code.XmlParse,
code.DynamicCodeLoad, code.UnsafeUpload, code.ArchiveEntryWrite,
code.UnboundedCopy, code.RawMemoryCopySize, code.SizeComputation,
code.UnparameterizedSqlQueryParser, code.ProtocolStateReview,
code.MethodGatedRedirectValidationBypass, code.SessionStoredRedirectTarget,
code.AbsolutePathDisclosure, code.OverbroadRolePermissionGrant.
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
		{"concept": "code.MethodGatedRedirectValidationBypass", "surface": "scan", "use": "mark for URL validation skipped for some HTTP methods before redirect/callback handling"},
		{"concept": "code.SessionStoredRedirectTarget", "surface": "scan", "use": "mark for redirects using session-stored or request-influenced targets without relative/same-origin validation"},
		{"concept": "code.RedirectTarget", "surface": "scan", "use": "taint sink for redirect APIs or methods returning redirect destinations"},
		{"concept": "core.RedirectAllowlist", "surface": "control", "use": "control concept for same-origin, relative URL, or allowlist redirect validation"},
		{"concept": "code.Deserialization", "surface": "scan", "use": "taint sink for unsafe object deserialization such as yaml.load, pickle, unserialize"},
		{"concept": "core.SafeDeserialization", "surface": "control", "use": "control concept for safe deserialization APIs such as safe_load or explicit safe loaders"},
		{"concept": "code.HtmlRender", "surface": "scan", "use": "taint sink for raw HTML/template rendering or unescaped response content"},
		{"concept": "code.UnsanitizedSvgUpload", "surface": "scan", "use": "mark for upload services that accept/store SVG files without sanitizing SVG XML/script content before saving"},
		{"concept": "core.HtmlEscape", "surface": "control", "use": "control concept for HTML escaping or safe text-node wrapping"},
		{"concept": "code.AbsolutePathDisclosure", "surface": "scan", "use": "mark for filesystem, path resolution, error, or warning flows that can expose absolute local paths"},
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
		if strings.Contains(src, "source param") && !strings.Contains(src, "sink ") && !strings.Contains(src, "mark ") && !strings.Contains(src, "control ") {
			hints = append(hints, "source param without a concrete sink, mark, or control is broad source-only expansion; return an empty overlay instead of widening public parameters.")
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
		"move_uploaded_file", "rename(", "copy(", "unlink(", "touch(",
		"getAbsolutePath", "absolutePath", "absolute path", "E_WARNING",
		"RuntimeException", "FileOperationErrorException",
		"UploadedFile", "FileUploader", "storeAs(", "getClientOriginalExtension",
		"getClientMimeType", "svg", "getSvgDimensions", "svgSanitize",
		"sanitizeSvg", "Sanitizer",
		"redirect", "header(", "$_GET", "$_POST", "$_FILES", "$_REQUEST",
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
