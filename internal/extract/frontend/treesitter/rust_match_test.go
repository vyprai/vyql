package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// The forwarder shape CVE-2026-24902 turns on: one arm of a value-position match hands the
// destination straight through and the other screens it. The two revisions differ only in
// whether the first arm carries the screen.
const rustMatchForwarderUnguarded = `
fn forward(meta: Meta) {
    let peer = match meta.destination {
        TcpDestination::Address(addr) => addr,
        TcpDestination::HostName(host) => {
            let resolved = lookup_host(host);
            if !is_global_ip(&resolved) {
                return;
            }
            resolved
        }
    };
    TcpStream::connect(peer);
}
`

const rustMatchForwarderGuarded = `
fn forward(meta: Meta) {
    let peer = match meta.destination {
        TcpDestination::Address(addr) => {
            if !is_global_ip(&addr) {
                return;
            }
            addr
        }
        TcpDestination::HostName(host) => {
            let resolved = lookup_host(host);
            if !is_global_ip(&resolved) {
                return;
            }
            resolved
        }
    };
    TcpStream::connect(peer);
}
`

func rustLowerFile(t *testing.T, name, src string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := ExtractRust([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// rustFlowPath returns a FLOWS path from the parameter named param to the call whose callee
// path is method, or nil when there is none.
func rustFlowPath(t *testing.T, g usg.Store, param, method string) []string {
	t.Helper()
	all, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var start string
	sinks := map[string]bool{}
	for _, n := range all {
		if n.Type == "code.Param" && n.Prop("name") == param {
			start = n.ID
		}
		if n.Prop("callee_path") == method {
			sinks[n.ID] = true
		}
	}
	if start == "" {
		t.Fatalf("no code.Param node named %q", param)
	}
	if len(sinks) == 0 {
		t.Fatalf("no call node with callee path %q", method)
	}
	prev := map[string]string{start: ""}
	for queue := []string{start}; len(queue) > 0; {
		cur := queue[0]
		queue = queue[1:]
		if sinks[cur] {
			var path []string
			for id := cur; id != ""; id = prev[id] {
				path = append([]string{id}, path...)
			}
			return path
		}
		edges, err := g.OutEdges(cur, "FLOWS")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range edges {
			if _, seen := prev[e.Dst]; !seen {
				prev[e.Dst] = cur
				queue = append(queue, e.Dst)
			}
		}
	}
	return nil
}

// mergeBranchesOnPath returns the branch regions recorded by the first control-flow merge on
// the path that records any.
func mergeBranchesOnPath(t *testing.T, g usg.Store, path []string) []string {
	t.Helper()
	for _, id := range path {
		n, ok, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			continue
		}
		if v := n.Prop("merge_branches"); v != "" {
			return strings.Split(v, "\x00")
		}
	}
	return nil
}

// regionsOfCallsTo returns the control region of every call to method.
func regionsOfCallsTo(t *testing.T, g usg.Store, method string) []string {
	t.Helper()
	all, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, n := range all {
		if n.Prop("callee_path") == method {
			out = append(out, n.Prop("region"))
		}
	}
	return out
}

func inBranch(region, branch string) bool {
	return region == branch || strings.HasPrefix(region, branch+"/")
}

// A value-position Rust match used to lower to one Seq containing the scrutinee and every arm
// at once, so the flow to the sink ran source -> that one node -> sink and a check written in
// one arm was indistinguishable from no check at all: the guarded and the unguarded revision
// of the forwarder above produced the same taint path over the same nodes.
//
// Each arm is now its own control region contributing its own operand to the merge that follows
// the match, and the merge records which regions those were. The taint still reaches the sink
// in both revisions — the screen rejects the value rather than transforming it — but the
// revisions are now distinguishable: the guarded one has a screen inside EVERY region the
// merge names, the unguarded one inside only one of them.
func TestRustValuePositionMatchSeparatesItsArms(t *testing.T) {
	for _, tc := range []struct {
		name          string
		src           string
		wantGuardArms int
	}{
		{"unguarded", rustMatchForwarderUnguarded, 1},
		{"guarded", rustMatchForwarderGuarded, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := rustLowerFile(t, "forwarder.rs", tc.src)

			path := rustFlowPath(t, g, "meta", "TcpStream.connect")
			if path == nil {
				t.Fatalf("meta does not reach TcpStream::connect: the match no longer carries the scrutinee's taint")
			}

			branches := mergeBranchesOnPath(t, g, path)
			if len(branches) != 2 {
				t.Fatalf("merge on the path names %d branch regions, want one per arm: %q", len(branches), branches)
			}
			if branches[0] == branches[1] {
				t.Fatalf("both arms lowered into the same region %q", branches[0])
			}

			guards := regionsOfCallsTo(t, g, "is_global_ip")
			covered := 0
			for _, b := range branches {
				for _, r := range guards {
					if inBranch(r, b) {
						covered++
						break
					}
				}
			}
			if covered != tc.wantGuardArms {
				t.Fatalf("%d of the merge's %d arms contain the screen, want %d (guards at %q, arms %q)",
					covered, len(branches), tc.wantGuardArms, guards, branches)
			}
		})
	}
}

// A match arm's pattern is how Rust NAMES the value being matched on. Without binding those
// names the arm body reads an identifier bound to nothing, and the scrutinee's taint stops at
// the match — which is what would happen to the forwarder above once its arms stopped being
// one flat container.
func TestRustMatchArmPatternBindsTheScrutinee(t *testing.T) {
	g := rustLowerFile(t, "bind.rs", `
fn handle(req: Request) {
    match req.body {
        Payload::Text(text) => sink_text(text),
        Payload::Pair { first, second: renamed } => {
            sink_first(first);
            sink_renamed(renamed);
        }
        Payload::Tuple((left, right)) => sink_left(left),
        other => sink_other(other),
    }
}
`)
	for _, sink := range []string{"sink_text", "sink_first", "sink_renamed", "sink_left", "sink_other"} {
		if rustFlowPath(t, g, "req", sink) == nil {
			t.Errorf("req does not reach %s: the arm's pattern bound no name to the scrutinee", sink)
		}
	}
	// A path in a pattern selects the arm; it names no value, so it must not be bound to the
	// scrutinee and must not carry its taint.
	if rustFlowPath(t, g, "req", "Payload::Text") != nil {
		t.Errorf("the variant path Payload::Text was bound as if it named a value")
	}
}
