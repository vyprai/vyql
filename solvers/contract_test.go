package solvers

import (
	"testing"

	"github.com/vyprai/vyql/usg"
)

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Mirrors poc/cases/case_21 (a): the stub and the three real solvers all conform
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
	tflows, err := FindTaintFlows(gt, set("code.HttpInput"), set("code.SqlExecution"), set("code.UntrustedData"), set(), "")
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
