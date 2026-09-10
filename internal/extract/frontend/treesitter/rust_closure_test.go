package treesitter

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// A closure passed as an argument is the value of that argument, but it is still a body:
// the statements inside it are lowered as statements, so a local bound inside the callback
// carries an edge to its uses and a source and a sink written in the same callback connect.
const rustClosureCallbackBody = `
fn render(panel: &Panel) {
    panel.on_click().subscribe(|evt| {
        let payload = decode(evt);
        run(payload);
    });
}
`

func TestRustClosureBodyCarriesLocalToItsUse(t *testing.T) {
	g := rustLowerFile(t, "lib.rs", rustClosureCallbackBody)
	if path := rustCallFlowPath(t, g, "decode", "run"); path == nil {
		t.Fatalf("no FLOWS path from decode to run inside the closure body")
	}
}

func TestRustClosureParameterIsBoundInItsBody(t *testing.T) {
	g := rustLowerFile(t, "lib.rs", rustClosureCallbackBody)
	if path := rustFlowPath(t, g, "evt", "decode"); path == nil {
		t.Fatalf("no FLOWS path from the closure parameter evt to decode")
	}
}

func TestRustClosureBodySeesTheEnclosingScope(t *testing.T) {
	g := rustLowerFile(t, "lib.rs", `
fn render(input: &str) {
    let picked = pick(input);
    btn.on_click().subscribe(|| {
        run(picked);
    });
}
`)
	if path := rustCallFlowPath(t, g, "pick", "run"); path == nil {
		t.Fatalf("no FLOWS path from pick in the enclosing function to run in the closure body")
	}
}

// rustCallFlowPath returns a FLOWS path from the call whose callee path is from to the call
// whose callee path is to, or nil when there is none.
func rustCallFlowPath(t *testing.T, g usg.Store, from, to string) []string {
	t.Helper()
	all, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var start string
	sinks := map[string]bool{}
	for _, n := range all {
		if n.Prop("callee_path") == from {
			start = n.ID
		}
		if n.Prop("callee_path") == to {
			sinks[n.ID] = true
		}
	}
	if start == "" {
		t.Fatalf("no call node with callee path %q", from)
	}
	if len(sinks) == 0 {
		t.Fatalf("no call node with callee path %q", to)
	}
	seen := map[string]bool{start: true}
	for queue := []string{start}; len(queue) > 0; {
		cur := queue[0]
		queue = queue[1:]
		if sinks[cur] {
			return []string{start, cur}
		}
		edges, err := g.OutEdges(cur, "FLOWS")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range edges {
			if !seen[e.Dst] {
				seen[e.Dst] = true
				queue = append(queue, e.Dst)
			}
		}
	}
	return nil
}
