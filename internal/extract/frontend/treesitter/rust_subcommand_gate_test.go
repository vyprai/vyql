package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// rustFunctionContextNode returns the analysis.function.context node of the
// named function, with its context tokens as a slice.
func rustFunctionContextNode(t *testing.T, src string, fn string) ([]string, []usg.Node) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "main.rs")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := ExtractRust([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		tokens := strings.Split(n.Prop("str_args"), "\x00")
		for _, tok := range tokens {
			if tok == "name="+fn {
				return tokens, nodes
			}
		}
	}
	t.Fatalf("no function context for %s; nodes=%v", fn, nodeSummaries(nodes))
	return nil, nodes
}

func nodeSummaries(nodes []usg.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if n.Type == "code.Call" {
			out = append(out, n.Prop("callee_path"))
		}
	}
	return out
}

func tokensWithPrefix(tokens []string, prefix string) []string {
	var out []string
	for _, tok := range tokens {
		if strings.HasPrefix(tok, prefix) {
			out = append(out, strings.TrimPrefix(tok, prefix))
		}
	}
	return out
}

// The CVE shape: a binary whose clap enum declares commands a compile-time
// command-name array gating its fallback execution omits. The omission is the
// whole vulnerable/fixed delta -- no call, type or control flow moves -- so the
// pairing has to state it: the array's entries beside the declared commands,
// and each declared command the array leaves out.
const rustGateVulnerableSrc = `
use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Gain,
    #[command(name = "hook-audit")]
    HookAudit {
        #[arg(short, long, default_value = "7")]
        since: u64,
    },
    Trust {
        #[arg(long)]
        list: bool,
    },
    Untrust,
}

#[derive(Subcommand)]
enum GitCommands {
    Add,
}

const RTK_META_COMMANDS: &[&str] = &[
    "gain",
    "hook-audit",
];

fn run_fallback(parse_error: clap::Error) -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if RTK_META_COMMANDS.contains(&args[0].as_str()) {
        parse_error.exit();
    }
    let status = resolved_command(&args[0]).args(&args[1..]).status();
    Ok(())
}

fn unrelated() {
    let v = vec!["a"];
}
`

func TestRustCommandGatePairsArrayWithDeclaredSubcommands(t *testing.T) {
	tokens, _ := rustFunctionContextNode(t, rustGateVulnerableSrc, "run_fallback")
	if !hasToken(tokens, "gate_array:RTK_META_COMMANDS") {
		t.Fatalf("gate array identity missing; gate tokens: %v", tokensWithPrefix(tokens, "gate_"))
	}
	for _, entry := range []string{"gain", "hook-audit"} {
		if !hasToken(tokens, "gate_entry:"+entry) {
			t.Fatalf("gate_entry:%s missing; gate tokens: %v", entry, tokensWithPrefix(tokens, "gate_"))
		}
	}
	// The declared set is the parser struct's own enum: kebab-case by default,
	// an explicit #[command(name = …)] where the variant carries one, and the
	// nested GitCommands enum -- also #[derive(Subcommand)] -- stays out.
	for _, sub := range []string{"gain", "hook-audit", "trust", "untrust"} {
		if !hasToken(tokens, "gate_subcommand:"+sub) {
			t.Fatalf("gate_subcommand:%s missing; gate tokens: %v", sub, tokensWithPrefix(tokens, "gate_"))
		}
	}
	if hasToken(tokens, "gate_subcommand:add") {
		t.Fatalf("nested subcommand enum leaked into the pairing; gate tokens: %v", tokensWithPrefix(tokens, "gate_"))
	}
	// The omission is the fact a rule judges: the commands the enum declares
	// that the gate array does not carry.
	for _, omitted := range []string{"trust", "untrust"} {
		if !hasToken(tokens, "gate_omission:"+omitted) {
			t.Fatalf("gate_omission:%s missing; gate tokens: %v", omitted, tokensWithPrefix(tokens, "gate_"))
		}
	}
	for _, covered := range []string{"gain", "hook-audit"} {
		if hasToken(tokens, "gate_omission:"+covered) {
			t.Fatalf("gate_omission:%s reported for a gated command; gate tokens: %v", covered, tokensWithPrefix(tokens, "gate_"))
		}
	}
}

func TestRustCommandGateCoversFixedRevision(t *testing.T) {
	fixed := strings.Replace(rustGateVulnerableSrc,
		`const RTK_META_COMMANDS: &[&str] = &[
    "gain",
    "hook-audit",
];`,
		`const RTK_META_COMMANDS: &[&str] = &[
    "gain",
    "hook-audit",
    "trust",
    "untrust",
];`, 1)
	if !strings.Contains(fixed, `"trust",`) {
		t.Fatal("test source edit did not apply")
	}
	tokens, _ := rustFunctionContextNode(t, fixed, "run_fallback")
	if omissions := tokensWithPrefix(tokens, "gate_omission:"); len(omissions) != 0 {
		t.Fatalf("fixed revision still reports omissions %v", omissions)
	}
	if !hasToken(tokens, "gate_entry:trust") || !hasToken(tokens, "gate_subcommand:trust") {
		t.Fatalf("fixed revision lost the pairing; gate tokens: %v", tokensWithPrefix(tokens, "gate_"))
	}
}

func TestRustCommandGateOnlyReachesReferencingFunctions(t *testing.T) {
	tokens, _ := rustFunctionContextNode(t, rustGateVulnerableSrc, "unrelated")
	if got := tokensWithPrefix(tokens, "gate_"); len(got) != 0 {
		t.Fatalf("function that never reads the array carries gate tokens %v", got)
	}
}

func TestRustCommandGateNeedsParserRootEnum(t *testing.T) {
	// The same enum without the #[derive(Parser)] struct naming it: not the
	// binary's own command set, so no pairing is stated.
	src := strings.Replace(rustGateVulnerableSrc, "#[derive(Parser)]\nstruct Cli {", "struct Cli {", 1)
	tokens, _ := rustFunctionContextNode(t, src, "run_fallback")
	if got := tokensWithPrefix(tokens, "gate_"); len(got) != 0 {
		t.Fatalf("pairing stated without a derive(Parser) root; gate tokens %v", got)
	}
}

func TestRustCommandGateIgnoresComputedArrays(t *testing.T) {
	src := strings.Replace(rustGateVulnerableSrc,
		`const RTK_META_COMMANDS: &[&str] = &[
    "gain",
    "hook-audit",
];`,
		`const RTK_META_COMMANDS: &[&str] = &[build_names()];`, 1)
	tokens, _ := rustFunctionContextNode(t, src, "run_fallback")
	if got := tokensWithPrefix(tokens, "gate_"); len(got) != 0 {
		t.Fatalf("computed array treated as a command gate; gate tokens %v", got)
	}
}

func TestRustKebabCase(t *testing.T) {
	cases := map[string]string{
		"Gain":         "gain",
		"Untrust":      "untrust",
		"HookAudit":    "hook-audit",
		"CcEconomics":  "cc-economics",
		"ParseHTTPOpt": "parse-http-opt",
		"V0Notequal":   "v0-notequal",
	}
	for in, want := range cases {
		if got := rustKebabCase(in); got != want {
			t.Fatalf("rustKebabCase(%q) = %q, want %q", in, got, want)
		}
	}
}
