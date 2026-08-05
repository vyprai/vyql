package attackpath

import (
	"testing"

	"github.com/vyprai/vyql/internal/findings"
	"github.com/vyprai/vyql/internal/solvers"
	"github.com/vyprai/vyql/internal/usg"
)

// A cross-domain path internet -reach-> svc
// -exploits-> db -can_access-> data, with choke-point analysis. The exploits hop
// carries the real SQLi finding (nested taint proof, case 06c); the can_access
// hop is produced by the effective-permission solver, not a literal.
func TestCrossDomainPathAndChokePoints(t *testing.T) {
	// the SAST stage produced this SQLi finding for the exposed handler
	sqli := &findings.Finding{
		RuleID: "VYQL-INJ-001", Severity: "high", WitnessKind: "taint",
		Witness: []string{"req", "sink"},
		Bindings: []findings.Binding{
			{Name: "source", NodeID: "req", Concept: "code.HttpInput", Loc: "refund.py:8"},
			{Name: "sink", NodeID: "sink", Concept: "code.SqlExecution", Loc: "refund.py:10"},
		},
	}

	// identity hop computed by the can_access solver over a STEP grant
	s := usg.NewInMemStore()
	s.AddNode(usg.Node{ID: "dbrole", Type: "identity.Role"})
	s.AddNode(usg.Node{ID: "bucket", Type: "cloud.Bucket"})
	s.AddEdge(usg.Edge{Type: "STEP", Src: "dbrole", Dst: "bucket", Props: map[string]string{"ability": "s3:GetObject*"}})
	access, err := solvers.FindCanAccess(s, []string{"dbrole"}, []string{"bucket"}, "s3:GetObject")
	if err != nil || len(access) != 1 {
		t.Fatalf("can_access should find dbrole->bucket, got %v err=%v", access, err)
	}

	steps := []Step{
		{Src: "internet", Dst: "alb", Kind: "reach", Witness: "sg-pub:443"},
		{Src: "alb", Dst: "svc", Kind: "reach", Witness: "sg-app:8080"},
		{Src: "svc", Dst: "db", Kind: "exploits", Witness: sqli}, // finding feeds back as a hop
		{Src: "db", Dst: "bucket", Kind: "can_access", Witness: access[0]},
	}
	start := map[string]bool{"internet": true}
	target := map[string]bool{"bucket": true}

	paths := FindPaths(steps, start, target, 8)
	if len(paths) != 1 {
		t.Fatalf("expected exactly one internet->data path, got %d", len(paths))
	}
	kinds := []string{}
	var exploit Step
	for _, s := range paths[0].Steps {
		kinds = append(kinds, s.Kind)
		if s.Kind == "exploits" {
			exploit = s
		}
	}
	want := []string{"reach", "reach", "exploits", "can_access"}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("path crosses domains wrong: got %v want %v", kinds, want)
		}
	}

	// the exploit hop carries the nested taint proof (case 06c)
	f, ok := exploit.Witness.(*findings.Finding)
	if !ok || f.WitnessKind != "taint" {
		t.Fatalf("exploit hop should carry the nested taint proof, got %#v", exploit.Witness)
	}

	chokes := ChokePoints(steps, start, target)
	if len(chokes) < 1 {
		t.Fatal("expected choke points")
	}
	hasExploit := false
	for _, c := range chokes {
		if c.Kind == "exploits" {
			hasExploit = true
		}
		if c.Severed != 1 {
			t.Fatalf("each step should sever the single path, got %d for %s->%s", c.Severed, c.Src, c.Dst)
		}
	}
	if !hasExploit {
		t.Fatal("fixing the SQLi (exploits hop) should be a choke point")
	}
}

// A diamond: two disjoint paths; removing a shared step severs both.
func TestChokeRanking(t *testing.T) {
	steps := []Step{
		{Src: "s", Dst: "a", Kind: "reach"},
		{Src: "s", Dst: "b", Kind: "reach"},
		{Src: "a", Dst: "g", Kind: "reach"},
		{Src: "b", Dst: "g", Kind: "reach"},
		{Src: "g", Dst: "t", Kind: "exploits"}, // shared by both paths
	}
	start := map[string]bool{"s": true}
	target := map[string]bool{"t": true}
	if got := len(FindPaths(steps, start, target, 8)); got != 2 {
		t.Fatalf("expected 2 paths, got %d", got)
	}
	chokes := ChokePoints(steps, start, target)
	if len(chokes) == 0 || chokes[0].Kind != "exploits" || chokes[0].Severed != 2 {
		t.Fatalf("the shared g->t step should sever both paths, got %+v", chokes)
	}
}
