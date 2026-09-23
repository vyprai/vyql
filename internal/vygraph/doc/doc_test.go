package doc

import (
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/graph"
)

// The design's worked parse, verbatim expectations.
const deployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
          securityContext:
            privileged: true
          ports:
            - containerPort: 8080
`

func parse(t *testing.T, src string) *graph.Store {
	t.Helper()
	s := graph.NewSchemas()
	if err := Register(s); err != nil {
		t.Fatal(err)
	}
	g := graph.New(s)
	if err := New(g).Extract("deployment.yaml", []byte(src)); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	return g
}

func find(t *testing.T, g *graph.Store, path string) graph.Node {
	t.Helper()
	for _, typ := range []string{"doc.Map", "doc.Seq", "doc.Scalar"} {
		for _, n := range g.NodesOfType(typ) {
			if v, ok := n.Fields.Get("path"); ok && v.S == path {
				return n
			}
		}
	}
	t.Fatalf("no doc node at path %q", path)
	return graph.Node{}
}

func TestWorkedDeploymentParse(t *testing.T) {
	g := parse(t, deployment)

	root := find(t, g, "$")
	if root.Type != "doc.Map" {
		t.Fatalf("root = %s", root.Type)
	}
	if v, _ := root.Fields.Get("kind"); v.S != "Deployment" {
		t.Fatalf("root kind = %q", v.S)
	}
	sc := find(t, g, "spec.template.spec.containers[0].securityContext.privileged")
	if sc.Type != "doc.Scalar" {
		t.Fatalf("privileged node = %s", sc.Type)
	}
	if v, _ := sc.Fields.Get("value"); v.S != "true" {
		t.Fatalf("privileged = %q", v.S)
	}
	if v, _ := sc.Fields.Get("kind"); v.S != "Deployment" {
		t.Fatalf("kind must propagate to every node, got %q", v.S)
	}
	img := find(t, g, "spec.template.spec.containers[0].image")
	if v, _ := img.Fields.Get("value"); v.S != "nginx:1.25" {
		t.Fatalf("image = %q", v.S)
	}
	port := find(t, g, "spec.template.spec.containers[0].ports[0].containerPort")
	if v, _ := port.Fields.Get("value"); v.S != "8080" {
		t.Fatalf("containerPort = %q", v.S)
	}
	if find(t, g, "spec.template.spec.containers").Type != "doc.Seq" {
		t.Fatal("containers must be a doc.Seq")
	}
}

func TestKeyedContainmentEdges(t *testing.T) {
	g := parse(t, deployment)
	root := find(t, g, "$")
	found := map[string]string{}
	for _, e := range g.Out(root.ID, "child") {
		kf, ok := e.Fields.Get("key")
		if !ok {
			t.Fatal("child edges carry their member key as a typed field")
		}
		to, _ := g.Node(e.To)
		found[kf.S] = to.Type
	}
	if found["kind"] != "doc.Scalar" || found["metadata"] != "doc.Map" || found["spec"] != "doc.Map" {
		t.Fatalf("root children = %v", found)
	}
	// Sequence keys are decimal indices.
	seq := find(t, g, "spec.template.spec.containers")
	keys := map[string]bool{}
	for _, e := range g.Out(seq.ID, "child") {
		kf, _ := e.Fields.Get("key")
		keys[kf.S] = true
	}
	if !keys["0"] {
		t.Fatalf("seq keys = %v", keys)
	}
}

func TestMultiDocumentYieldsIndependentRoots(t *testing.T) {
	multi := `kind: Deployment
metadata:
  name: a
---
kind: Service
metadata:
  name: b
`
	g := parse(t, multi)
	kinds := map[string]int{}
	for _, n := range g.NodesOfType("doc.Map") {
		if v, ok := n.Fields.Get("path"); ok && v.S == "$" {
			k, _ := n.Fields.Get("kind")
			kinds[k.S]++
		}
	}
	if kinds["Deployment"] != 1 || kinds["Service"] != 1 {
		t.Fatalf("roots by kind = %v", kinds)
	}
}

func TestJSONParsesIntoTheSameTree(t *testing.T) {
	g := parse(t, `{"kind": "Deployment", "spec": {"template": {"spec": {"containers": [{"name": "app", "image": "nginx"}]}}}}`)
	root := find(t, g, "$")
	if v, _ := root.Fields.Get("kind"); v.S != "Deployment" {
		t.Fatalf("json kind = %q", v.S)
	}
	c := find(t, g, "spec.template.spec.containers[0].image")
	if v, _ := c.Fields.Get("value"); v.S != "nginx" {
		t.Fatalf("json image = %q", v.S)
	}
}

func TestDeterministicParse(t *testing.T) {
	a := parse(t, deployment)
	b := parse(t, deployment)
	if a.NodeCount() != b.NodeCount() {
		t.Fatalf("node counts differ: %d vs %d", a.NodeCount(), b.NodeCount())
	}
}
