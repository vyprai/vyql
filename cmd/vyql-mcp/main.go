// Command vyql-mcp is a Model Context Protocol (MCP) server that exposes the
// VyQL security scanner to MCP clients (Claude Code/Desktop, IDEs, agents) as a
// set of read-only tools over stdio.
//
// Like cmd/vyqld, it is a thin wrapper: it shells out to the `vyql` CLI and
// returns its output. No analysis logic lives here, so the tools stay in
// lock-step with the CLI. Tools operate on local filesystem paths.
//
// Usage:
//
//	vyql-mcp -bin /path/to/vyql -home /path/to/vyql/data
//
// -home (or $VYQL_HOME) points at the VyQL data dir (the one containing
// ontology/concepts.vyql) and is effectively required unless the vyql binary is
// colocated with its data dir. Register it with an MCP client, e.g.:
//
//	claude mcp add vyql -- vyql-mcp -bin /usr/local/bin/vyql -home /opt/vyql
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const version = "0.1.0"

type server struct {
	bin     string        // path to the vyql CLI binary
	home    string        // VYQL_HOME passed to vyql (empty → inherit/searchUp)
	timeout time.Duration // max wall-clock per tool invocation
	maxOut  int           // cap on bytes of text output returned (0 = unlimited)
}

func main() {
	bin := flag.String("bin", envOr("VYQL_BIN", "vyql"), "path to the vyql CLI binary")
	home := flag.String("home", os.Getenv("VYQL_HOME"), "VyQL data dir passed as VYQL_HOME (default: $VYQL_HOME)")
	timeout := flag.Duration("timeout", 180*time.Second, "max wall-clock per tool invocation")
	maxOut := flag.Int("max-output", 256*1024, "cap text-tool output at this many bytes (0 = unlimited)")
	flag.Parse()

	// stdout is the MCP transport — keep all diagnostics on stderr.
	log.SetFlags(0)
	log.SetOutput(os.Stderr)

	s := &server{bin: *bin, home: *home, timeout: *timeout, maxOut: *maxOut}

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "vyql",
		Title:   "VyQL security scanner",
		Version: version,
	}, nil)
	s.register(srv)

	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("vyql-mcp: %v", err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// readOnly builds the standard annotation for a VyQL tool: it never mutates the
// target and its world is closed (it only reads the given local path / data).
func readOnly(title string) *mcp.ToolAnnotations {
	closed := false
	return &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closed, Title: title}
}

// ---- structured scan output (mirrors the CLI's `scan -format json` shape) ----

type scanFinding struct {
	Rule            string `json:"rule" jsonschema:"the rule id that fired (e.g. VYQL-INJ-001)"`
	Severity        string `json:"severity" jsonschema:"info | low | medium | high | critical"`
	FP              string `json:"fp" jsonschema:"stable fingerprint (rule + binding locations), survives line drift"`
	Source          string `json:"source" jsonschema:"source location file:line (taint origin), empty for presence/config findings"`
	Sink            string `json:"sink" jsonschema:"sink location file:line (where the weakness manifests)"`
	AssumptionNoted bool   `json:"assumption_noted" jsonschema:"true if an unsound assumption (declared neutralizer) was noted on the path"`
}

type scanOutput struct {
	Findings []scanFinding `json:"findings" jsonschema:"security findings, deduplicated to one per (rule, sink)"`
	Count    int           `json:"count" jsonschema:"number of findings"`
}

// ---- tool input schemas (struct tags drive the auto-generated JSON Schema) ----

type scanIn struct {
	Path    string   `json:"path" jsonschema:"local file or directory to scan"`
	Profile string   `json:"profile,omitempty" jsonschema:"threat-model profile (web, api, cli, electron, mobile_android, library, ...); default auto-detect"`
	Exclude []string `json:"exclude,omitempty" jsonschema:"glob patterns to skip, layered on the built-in deps/build skips (e.g. test, examples, *.spec.js)"`
}

type exportIn struct {
	Path    string   `json:"path" jsonschema:"local file or directory to scan"`
	Format  string   `json:"format" jsonschema:"export format: sarif (CI interchange), graph-json (structured code-map), or text (human report)"`
	Profile string   `json:"profile,omitempty" jsonschema:"threat-model profile; default auto-detect"`
	Exclude []string `json:"exclude,omitempty" jsonschema:"glob patterns to skip (e.g. test, *.spec.js)"`
}

type diffIn struct {
	Before string `json:"before" jsonschema:"path to a baseline 'vyql scan -format json' / vyql_export json file"`
	After  string `json:"after" jsonschema:"path to the current 'vyql scan -format json' / vyql_export json file"`
}

type pathProfileIn struct {
	Path    string `json:"path" jsonschema:"local file or directory"`
	Profile string `json:"profile,omitempty" jsonschema:"threat-model profile; default auto-detect"`
}

type traceIn struct {
	Path    string `json:"path" jsonschema:"local file or directory"`
	From    string `json:"from,omitempty" jsonschema:"only trace sources whose concept contains this substring (e.g. HttpInput)"`
	To      string `json:"to,omitempty" jsonschema:"only count sinks whose concept contains this substring (e.g. SqlExecution)"`
	Profile string `json:"profile,omitempty" jsonschema:"threat-model profile; default auto-detect"`
}

type queryIn struct {
	Path    string `json:"path" jsonschema:"local file or directory"`
	Type    string `json:"type,omitempty" jsonschema:"match node type substring (e.g. code.Call)"`
	Concept string `json:"concept,omitempty" jsonschema:"match a concept label substring (e.g. HttpInput)"`
	Call    string `json:"call,omitempty" jsonschema:"match callee_path/method substring (e.g. db.Query)"`
	Loc     string `json:"loc,omitempty" jsonschema:"match location substring (e.g. .go or a filename)"`
	From    string `json:"from,omitempty" jsonschema:"reachability mode: source concept (use together with 'to')"`
	To      string `json:"to,omitempty" jsonschema:"reachability mode: sink concept (use together with 'from')"`
	Edges   bool   `json:"edges,omitempty" jsonschema:"also print each matching node's outgoing edges"`
	Count   bool   `json:"count,omitempty" jsonschema:"print only the number of matches"`
	Profile string `json:"profile,omitempty" jsonschema:"threat-model profile; default auto-detect"`
}

type adaptersIn struct {
	Lang string `json:"lang" jsonschema:"technology/adapter to list (e.g. go, javascript, java, python, php)"`
}

type graphIn struct {
	Path    string `json:"path" jsonschema:"local file or directory"`
	Taint   bool   `json:"taint,omitempty" jsonschema:"show per-source FLOWS reachability instead of the full graph"`
	Profile string `json:"profile,omitempty" jsonschema:"threat-model profile; default auto-detect"`
}

// register wires every tool. Tools mirror the vyql CLI subcommands.
func (s *server) register(srv *mcp.Server) {
	// vyql_scan — the primary tool, with typed structured output.
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "vyql_scan",
		Annotations: readOnly("Scan"),
		Description: "Run a full VyQL security scan over a local file or directory and return structured " +
			"findings (taint/flow injection, reachability, presence/config). Each finding has rule, severity, " +
			"fingerprint (fp), and source/sink locations; findings are deduplicated to one per (rule, sink). " +
			"This is the primary tool — start here. For SARIF/graph-json/text output use vyql_export; for the " +
			"proof tree behind a finding use vyql_explain.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in scanIn) (*mcp.CallToolResult, scanOutput, error) {
		if err := checkPath("path", in.Path); err != nil {
			return nil, scanOutput{}, err
		}
		args := withProfile([]string{"scan", "-format", "json"}, in.Profile)
		args = withExclude(args, in.Exclude)
		args = append(args, in.Path)
		out, err := s.runBytes(ctx, args...)
		if err != nil {
			return nil, scanOutput{}, err
		}
		var fs []scanFinding
		if err := json.Unmarshal(out, &fs); err != nil {
			return nil, scanOutput{}, fmt.Errorf("could not parse scan output: %v", err)
		}
		return nil, scanOutput{Findings: fs, Count: len(fs)}, nil
	})

	// vyql_export — raw scan output in a non-default format.
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "vyql_export",
		Annotations: readOnly("Export"),
		Description: "Run a scan and return the raw report in a non-default format: sarif (CI/code-scanning " +
			"interchange), graph-json (the structured CODE_MAPPER export — functions, call edges, findings), " +
			"or text (the human-readable report with risk bands). For structured findings to reason over, " +
			"prefer vyql_scan.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in exportIn) (*mcp.CallToolResult, any, error) {
		if err := checkPath("path", in.Path); err != nil {
			return nil, nil, err
		}
		switch in.Format {
		case "sarif", "graph-json", "text":
		default:
			return nil, nil, fmt.Errorf("invalid format %q (want sarif | graph-json | text)", in.Format)
		}
		args := withProfile([]string{"scan", "-format", in.Format}, in.Profile)
		args = withExclude(args, in.Exclude)
		args = append(args, in.Path)
		return s.run(ctx, args...)
	})

	// vyql_diff — compare two prior scan json outputs by fingerprint.
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "vyql_diff",
		Annotations: readOnly("Diff findings"),
		Description: "Diff two prior scan results by fingerprint and report which findings were added vs. " +
			"removed. Provide filesystem paths to two json files previously saved from vyql_scan (or " +
			"vyql_export format=json). Use to prove a change is finding-preserving, or to see exactly which " +
			"findings a fix resolved or introduced.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in diffIn) (*mcp.CallToolResult, any, error) {
		if err := checkPath("before", in.Before); err != nil {
			return nil, nil, err
		}
		if err := checkPath("after", in.After); err != nil {
			return nil, nil, err
		}
		return s.run(ctx, "diff", in.Before, in.After)
	})

	// vyql_explain — findings with full proof trees.
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "vyql_explain",
		Annotations: readOnly("Explain"),
		Description: "Scan and return each finding WITH its full proof tree: concept bindings, the taint " +
			"witness path (source → sink), and negation/sanitizer evidence (which guards fired or were " +
			"absent). Use to understand WHY a finding fired or to audit a specific result.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in pathProfileIn) (*mcp.CallToolResult, any, error) {
		if err := checkPath("path", in.Path); err != nil {
			return nil, nil, err
		}
		return s.run(ctx, withProfile([]string{"explain"}, in.Profile, in.Path)...)
	})

	// vyql_trace — taint reachability source → sink.
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "vyql_trace",
		Annotations: readOnly("Trace taint"),
		Description: "Trace taint reachability from a source concept to a sink concept (e.g. from=HttpInput " +
			"to=SqlExecution) over the dataflow graph, WITHOUT running rules. Prints the shortest source→sink " +
			"path, or the 'frontier' where taint dead-ends. The tool to answer 'why is this (not) flagged'.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in traceIn) (*mcp.CallToolResult, any, error) {
		if err := checkPath("path", in.Path); err != nil {
			return nil, nil, err
		}
		args := []string{"trace"}
		if in.From != "" {
			args = append(args, "-from", in.From)
		}
		if in.To != "" {
			args = append(args, "-to", in.To)
		}
		return s.run(ctx, withProfile(args, in.Profile, in.Path)...)
	})

	// vyql_query — ad-hoc graph query.
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "vyql_query",
		Annotations: readOnly("Query graph"),
		Description: "Ad-hoc query of the extracted code graph: select nodes by type/concept/call/loc " +
			"substrings (AND-ed), or check reachability with from+to. Optionally show outgoing edges or just a " +
			"count. Use to explore what VyQL extracted and labeled.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in queryIn) (*mcp.CallToolResult, any, error) {
		if err := checkPath("path", in.Path); err != nil {
			return nil, nil, err
		}
		args := []string{"query"}
		for _, kv := range []struct{ flag, val string }{
			{"-type", in.Type}, {"-concept", in.Concept}, {"-call", in.Call},
			{"-loc", in.Loc}, {"-from", in.From}, {"-to", in.To},
		} {
			if kv.val != "" {
				args = append(args, kv.flag, kv.val)
			}
		}
		if in.Edges {
			args = append(args, "-edges")
		}
		if in.Count {
			args = append(args, "-count")
		}
		return s.run(ctx, withProfile(args, in.Profile, in.Path)...)
	})

	// vyql_adapters — adapter vocabulary for a language (no source path).
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "vyql_adapters",
		Annotations: readOnly("List adapters"),
		Description: "List the source/sink/control/mark vocabulary an adapter provides for a language " +
			"(e.g. lang=javascript). Pure introspection — no source path needed. Use to discover which " +
			"framework/library APIs VyQL recognizes for a language.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in adaptersIn) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(in.Lang) == "" {
			return nil, nil, fmt.Errorf("lang is required (e.g. go, javascript, java, python)")
		}
		return s.run(ctx, "adapters", "-lang", in.Lang)
	})

	// vyql_graph — dump the Universal Security Graph (debug).
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "vyql_graph",
		Annotations: readOnly("Dump graph"),
		Description: "Dump the Universal Security Graph (nodes + typed edges: FLOWS, CONTROL, PROTECTS, " +
			"CHECKS, NET, STEP) for a path, or with taint=true the per-source dataflow reachability. Verbose " +
			"— intended for debugging extraction/lowering.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in graphIn) (*mcp.CallToolResult, any, error) {
		if err := checkPath("path", in.Path); err != nil {
			return nil, nil, err
		}
		args := []string{"graph"}
		if in.Taint {
			args = append(args, "-taint")
		}
		return s.run(ctx, withProfile(args, in.Profile, in.Path)...)
	})

	// vyql_match — what each adapter labeled (debug).
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "vyql_match",
		Annotations: readOnly("Show labels"),
		Description: "List every node an adapter labeled with a concept, grouped by role " +
			"(source/sink/control/other), with the adapter and match fidelity. Use to see exactly what got " +
			"recognized as a source or sink in the target code.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in pathProfileIn) (*mcp.CallToolResult, any, error) {
		if err := checkPath("path", in.Path); err != nil {
			return nil, nil, err
		}
		return s.run(ctx, withProfile([]string{"match"}, in.Profile, in.Path)...)
	})

	// vyql_resolve — interprocedural call resolution (debug).
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "vyql_resolve",
		Annotations: readOnly("Call resolution"),
		Description: "Report interprocedural call resolution — which call sites got a callee body wired vs. " +
			"stayed unresolved (where taint silently stops). Use to debug missing cross-function flows.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in pathProfileIn) (*mcp.CallToolResult, any, error) {
		if err := checkPath("path", in.Path); err != nil {
			return nil, nil, err
		}
		return s.run(ctx, withProfile([]string{"resolve"}, in.Profile, in.Path)...)
	})
}

// withProfile appends "-profile <p>" (when set) and then any trailing positional
// args (typically the path), preserving the CLI's flags-before-path ordering.
func withProfile(args []string, profile string, trailing ...string) []string {
	if profile != "" {
		args = append(args, "-profile", profile)
	}
	return append(args, trailing...)
}

func withExclude(args, exclude []string) []string {
	if len(exclude) > 0 {
		args = append(args, "-exclude", strings.Join(exclude, ","))
	}
	return args
}

// runBytes execs the vyql CLI and returns raw stdout, enforcing the timeout.
// A non-zero exit (vyql only exits non-zero on real errors, not on findings)
// becomes a Go error, which the typed tool handlers turn into a tool error.
func (s *server) runBytes(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.bin, args...)
	cmd.Env = os.Environ()
	if s.home != "" {
		cmd.Env = append(cmd.Env, "VYQL_HOME="+s.home)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("vyql %s timed out after %s", args[0], s.timeout)
		}
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("vyql %s failed: %s", args[0], msg)
	}
	return out.Bytes(), nil
}

// run wraps runBytes for text-output tools: it caps the output and packages it
// as MCP text content.
func (s *server) run(ctx context.Context, args ...string) (*mcp.CallToolResult, any, error) {
	out, err := s.runBytes(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	text := string(out)
	if s.maxOut > 0 && len(text) > s.maxOut {
		text = text[:s.maxOut] + fmt.Sprintf("\n\n[output truncated at %d bytes — narrow the query or scan a subpath]", s.maxOut)
	}
	if strings.TrimSpace(text) == "" {
		text = "(vyql produced no output — e.g. no findings)"
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
}

// checkPath returns an error (→ tool error) if a required path arg is missing or
// unreadable.
func checkPath(field, p string) error {
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("%s is required", field)
	}
	if _, err := os.Stat(p); err != nil {
		return fmt.Errorf("cannot access %s %q: %v", field, p, err)
	}
	return nil
}
