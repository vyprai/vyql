package solvers

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/ontology"
	"github.com/vyprai/vyql/internal/usg"
)

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func TestSolversDoNotHardcodeOntologyConcepts(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	concepts := solverOntologyConceptNeedles(t)
	var hits []string
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		for _, needle := range concepts {
			if strings.Contains(text, needle) {
				hits = append(hits, filepath.Base(path)+": "+needle)
			}
		}
	}
	if len(hits) > 0 {
		t.Fatalf("solvers must not hardcode ontology concepts; pass semantic role sets in from the caller: %s", strings.Join(hits, ", "))
	}
}

func solverOntologyConceptNeedles(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, c := range ontology.Seed().AllConcepts() {
		if ontology.IsInternalConceptRoleConcept(c.QualifiedName()) {
			continue
		}
		seen["\""+c.Name+"\""] = true
		seen["\""+c.QualifiedName()+"\""] = true
	}
	out := make([]string, 0, len(seen))
	for needle := range seen {
		out = append(out, needle)
	}
	return out
}

// The stub and the three real solvers all conform
// to the versioned solver contract.
func TestSolverContractConformance(t *testing.T) {
	// stub conforms and declares the contract version
	stub := StubSolver{}
	if stub.Version() != SolverContractVersion {
		t.Fatalf("stub version %q != %q", stub.Version(), SolverContractVersion)
	}
	if v := ValidateResults(stub.Solve([]string{"s"}, []string{"k"})); len(v) != 0 {
		t.Fatalf("stub solver should conform, got %v", v)
	}

	// taint: HttpInput -> SqlExecution, one flow, conforms
	gt := usg.NewInMemStore()
	gt.AddNode(usg.Node{ID: "a", Type: "code.X", Props: map[string]string{"loc": "a"}})
	gt.AddNode(usg.Node{ID: "b", Type: "code.X", Props: map[string]string{"loc": "b"}})
	gt.AddLabel("a", usg.Label{Concept: "code.HttpInput"})
	gt.AddLabel("b", usg.Label{Concept: "code.SqlExecution"})
	gt.AddEdge(usg.Edge{Type: "FLOWS", Src: "a", Dst: "b"})
	tflows, err := FindTaintFlows(gt, set("code.HttpInput"), set("code.SqlExecution"), set("code.UntrustedData"), set(), "", set())
	if err != nil {
		t.Fatal(err)
	}
	if v := ValidateResults(tflows); len(v) != 0 || len(tflows) != 1 {
		t.Fatalf("taint results should conform and be 1, got %d %v", len(tflows), v)
	}

	// reach: net -> db over a permitting NET edge
	gr := usg.NewInMemStore()
	gr.AddNode(usg.Node{ID: "net", Type: "cloud.Internet", Props: map[string]string{"loc": "net"}})
	gr.AddNode(usg.Node{ID: "db", Type: "cloud.Database", Props: map[string]string{"loc": "db"}})
	gr.AddEdge(usg.Edge{Type: "NET", Src: "net", Dst: "db",
		Props: map[string]string{"rule": "sg-1", "proto": "tcp", "port": "5432"}})
	rpaths, err := FindReach(gr, []string{"net"}, []string{"db"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := ValidateResults(rpaths); len(v) != 0 || len(rpaths) != 1 {
		t.Fatalf("reach results should conform and be 1, got %d %v", len(rpaths), v)
	}

	// assume: principal -> admin role over a STEP edge
	ga := usg.NewInMemStore()
	ga.AddNode(usg.Node{ID: "p", Type: "identity.User", Props: map[string]string{"loc": "p"}})
	ga.AddNode(usg.Node{ID: "adm", Type: "identity.Role", Props: map[string]string{"loc": "adm", "priv_level": "ADMIN"}})
	ga.AddEdge(usg.Edge{Type: "STEP", Src: "p", Dst: "adm", Props: map[string]string{"ability": "AssumeRole"}})
	apaths, err := FindAssume(ga, []string{"p"}, []string{"adm"}, "ADMIN")
	if err != nil {
		t.Fatal(err)
	}
	if v := ValidateResults(apaths); len(v) != 0 || len(apaths) != 1 {
		t.Fatalf("assume results should conform and be 1, got %d %v", len(apaths), v)
	}
}

func TestIntTaintScratchDoesNotLeakPolicyState(t *testing.T) {
	g := usg.NewIntStore(3)
	for _, id := range []string{"src", "mid", "sink"} {
		if err := g.AddNode(usg.Node{ID: id, Type: "code.X", Props: map[string]string{"loc": id}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.AddLabel("src", usg.Label{Concept: "test.Source"}); err != nil {
		t.Fatal(err)
	}
	if err := g.AddLabel("mid", usg.Label{Concept: "test.Kill"}); err != nil {
		t.Fatal(err)
	}
	if err := g.AddLabel("sink", usg.Label{Concept: "test.Sink"}); err != nil {
		t.Fatal(err)
	}
	if err := g.AddEdge(usg.Edge{Type: "FLOWS", Src: "src", Dst: "mid"}); err != nil {
		t.Fatal(err)
	}
	if err := g.AddEdge(usg.Edge{Type: "FLOWS", Src: "mid", Dst: "sink"}); err != nil {
		t.Fatal(err)
	}

	killed, err := FindTaintFlows(g, set("test.Source"), set("test.Sink"), set("test.Kind"), set("test.Kill"), "", set())
	if err != nil {
		t.Fatal(err)
	}
	if len(killed) != 0 {
		t.Fatalf("kill-control run emitted %d flow(s), want 0", len(killed))
	}

	live, err := FindTaintFlows(g, set("test.Source"), set("test.Sink"), set("test.Kind"), set(), "", set())
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 {
		t.Fatalf("live run emitted %d flow(s), want 1", len(live))
	}

	killedAgain, err := FindTaintFlows(g, set("test.Source"), set("test.Sink"), set("test.Kind"), set("test.Kill"), "", set())
	if err != nil {
		t.Fatal(err)
	}
	if len(killedAgain) != 0 {
		t.Fatalf("second kill-control run emitted %d flow(s), want 0", len(killedAgain))
	}
}

func TestCacheFingerprintStable(t *testing.T) {
	a := CacheFingerprint("taint", "code.HttpInput", "code.SqlExecution")
	b := CacheFingerprint("taint", "code.HttpInput", "code.SqlExecution")
	c := CacheFingerprint("taint", "code.HttpInput", "code.CommandExecution")
	if a != b {
		t.Fatal("cache fingerprint should be deterministic")
	}
	if a == c {
		t.Fatal("cache fingerprint should change with inputs")
	}
}
