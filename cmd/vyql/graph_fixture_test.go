package main

// Graph-fixture harness (plan/test-coverage-tasklist.md T0.6). The .test.vyql harness
// scans CODE; the cloud/identity/business/runtime/SCA rules instead run over an
// asset/identity graph. This harness loads a synthetic graph (vyql/tests/graph/*.graph.json),
// runs the SHIPPED packs over it, and asserts which rule ids fire/reject — the graph
// analogue of TestVyqlSpecs.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

type graphNode struct {
	ID    string            `json:"id"`
	Type  string            `json:"type"`
	Props map[string]string `json:"props,omitempty"`
}
type graphEdge struct {
	Type  string            `json:"type"`
	Src   string            `json:"src"`
	Dst   string            `json:"dst"`
	Props map[string]string `json:"props,omitempty"`
}
type graphLabel struct {
	Node    string            `json:"node"`
	Concept string            `json:"concept"`
	Detail  map[string]string `json:"detail,omitempty"`
}
type graphFixture struct {
	Name   string       `json:"name"`
	Expect []string     `json:"expect"`
	Reject []string     `json:"reject"`
	Nodes  []graphNode  `json:"nodes"`
	Edges  []graphEdge  `json:"edges"`
	Labels []graphLabel `json:"labels"`
}

func TestGraphFixtures(t *testing.T) {
	dir := filepath.Join(datadir.Root(), "tests", "graph")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("no vyql/tests/graph dir: %v", err)
	}

	// shipped packs, compiled once (production path).
	src, err := loadRules("")
	if err != nil {
		t.Fatalf("load packs: %v", err)
	}
	onto := ontology.Seed()
	decls, err := parser.Parse(src)
	if err != nil {
		t.Fatalf("parse packs: %v", err)
	}
	compiled, cerrs := engine.CompileRules(decls, onto)
	if len(cerrs) != 0 {
		t.Fatalf("compile packs: %v", cerrs)
	}

	var files []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".graph.json") {
			files = append(files, p)
		}
		return nil
	})
	if len(files) == 0 {
		t.Skip("no .graph.json fixtures found")
	}

	total := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var fixtures []graphFixture
		if err := json.Unmarshal(b, &fixtures); err != nil {
			t.Fatalf("%s: %v", filepath.Base(f), err)
		}
		for _, fx := range fixtures {
			fx := fx
			total++
			t.Run(filepath.Base(f)+"/"+fx.Name, func(t *testing.T) {
				if len(fx.Expect) == 0 && len(fx.Reject) == 0 {
					t.Fatalf("fixture %q has neither expect nor reject", fx.Name)
				}
				store := usg.NewInMemStore()
				for _, n := range fx.Nodes {
					if err := store.AddNode(usg.Node{ID: n.ID, Type: n.Type, Props: n.Props}); err != nil {
						t.Fatal(err)
					}
				}
				for _, e := range fx.Edges {
					if err := store.AddEdge(usg.Edge{Type: e.Type, Src: e.Src, Dst: e.Dst, Props: e.Props}); err != nil {
						t.Fatal(err)
					}
				}
				for _, l := range fx.Labels {
					if err := store.AddLabel(l.Node, usg.Label{Concept: l.Concept, Detail: l.Detail}); err != nil {
						t.Fatal(err)
					}
				}
				eng := engine.New(onto, store)
				fired := map[string]bool{}
				for _, cr := range compiled {
					got, err := eng.Evaluate(cr)
					if err != nil {
						t.Fatalf("evaluate: %v", err)
					}
					for _, fnd := range got {
						fired[fnd.RuleID] = true
					}
				}
				for _, want := range fx.Expect {
					if !fired[want] {
						t.Errorf("expected rule %s to fire, but it did not (fired: %s)", want, firedKeys(fired))
					}
				}
				for _, no := range fx.Reject {
					if fired[no] {
						t.Errorf("rule %s fired but should not have", no)
					}
				}
			})
		}
	}
	t.Logf("ran %d graph fixture(s) from %d file(s)", total, len(files))
}

func firedKeys(m map[string]bool) string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return strings.Join(out, ", ")
}

var _ = findings.Finding{}
