package bindings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// The Rust fixture the frontend tests use: a clap root enum declaring commands
// a compile-time command-name array gating the fallback execution omits.
const rustCommandGateFixture = `
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

// A binding states the honest detection the pairing makes expressible: an
// unqualified-executable issue on the search-path fallback execution whose gate
// array omits a command the binary's own subcommand enum declares. The whole
// path is exercised here -- the Rust frontend's context tokens, the lowering,
// and the compiled presence predicates agreeing on one node -- because the
// vulnerable/fixed delta is four string literals, nothing a call-shaped
// predicate could ever see.
func TestPresenceCommandGateOmissionFlagsVulnerableFallbackOnly(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.rust.native;
binding fallbackGateOmitsDeclaredSubcommand {
  query pattern presenceNode where node.scope == "function"
    and node.context.language == "rust"
    and node.context.callPath contains "resolved_command"
    and node.context.gateArray contains "RTK_META_COMMANDS"
    and node.context.gateOmission contains "trust"
  emit issue code.UnqualifiedExecutableDiscovery at node
}
`)
	if err != nil {
		t.Fatalf("compile gate binding: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, sets))

	run := func(t *testing.T, src string) []string {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "main.rs")
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		prog, err := treesitter.ExtractRust([]string{path}, dir)
		if err != nil {
			t.Fatal(err)
		}
		store, err := lowering.Lower(prog, true)
		if err != nil {
			t.Fatal(err)
		}
		nodes, err := store.AllNodes()
		if err != nil {
			t.Fatal(err)
		}
		byID := make(map[string]usg.Node, len(nodes))
		for _, n := range nodes {
			byID[n.ID] = n
		}
		var matched []string
		for _, m := range spec.presenceApplicator().Apply(store) {
			for _, tok := range strings.Split(byID[m.NodeID].Prop("str_args"), "\x00") {
				if strings.HasPrefix(tok, "name=") {
					matched = append(matched, strings.TrimPrefix(tok, "name="))
				}
			}
		}
		return matched
	}

	if got := run(t, rustCommandGateFixture); len(got) != 1 || got[0] != "run_fallback" {
		t.Fatalf("vulnerable revision matched %v, want exactly run_fallback", got)
	}

	fixed := strings.Replace(rustCommandGateFixture,
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
	if got := run(t, fixed); len(got) != 0 {
		t.Fatalf("fixed revision still matched %v", got)
	}
}
