// Package doc is the v3 generic document substrate: one syntax-only parser
// lowering YAML and JSON into the closed three-node config graph . doc.Map, doc.Seq, and doc.Scalar joined by keyed child edges — no
// vocabulary above syntax: the parser knows never Kubernetes, never Terraform.
// No Region/Order here: a declarative document has no control flow, the one
// asymmetry between the two low-level families.
package doc

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/vyprai/vyql/internal/vygraph/graph"
)

// Register declares the closed doc.* schema: exactly three node types, and no
// frontend may add a fourth.
func Register(s *graph.Schemas) error {
	key := []string{"file", "path"}
	common := []graph.FieldSpec{
		{Name: "path", Kind: graph.KindString},
		{Name: "file", Kind: graph.KindString},
		{Name: "kind", Kind: graph.KindString},
	}
	if err := s.Register(&graph.TypeSchema{Type: "doc.Map", Layer: graph.LayerLow, Fields: common, Key: key}); err != nil {
		return err
	}
	if err := s.Register(&graph.TypeSchema{Type: "doc.Seq", Layer: graph.LayerLow, Fields: common, Key: key}); err != nil {
		return err
	}
	return s.Register(&graph.TypeSchema{Type: "doc.Scalar", Layer: graph.LayerLow,
		Fields: append(common, graph.FieldSpec{Name: "value", Kind: graph.KindString}), Key: key})
}

// Parser writes doc.* nodes into a store.
type Parser struct {
	store *graph.Store
	order int64
	doc   int // multi-document index: each --- root is its own tree
}

func New(store *graph.Store) *Parser { return &Parser{store: store} }

// Extract parses one file's source (YAML or JSON, by syntax probe) into the
// store. Multi-document YAML yields one root per `---` document, each with its
// own independently extracted kind.
func (p *Parser) Extract(file string, src []byte) error {
	if looksJSON(src) {
		var v interface{}
		if err := json.Unmarshal(src, &v); err != nil {
			return fmt.Errorf("doc: parse %s: %w", file, err)
		}
		p.value(file, "$", kindOf(v), v)
		return nil
	}
	dec := yaml.NewDecoder(strings.NewReader(string(src)))
	for {
		var v interface{}
		if err := dec.Decode(&v); err != nil {
			if err.Error() == "EOF" || strings.Contains(err.Error(), "EOF") {
				break
			}
			return fmt.Errorf("doc: parse %s: %w", file, err)
		}
		if v == nil {
			continue
		}
		p.value(file, "$", kindOf(v), v)
		p.doc++
	}
	return nil
}

func looksJSON(src []byte) bool {
	t := strings.TrimSpace(string(src))
	return strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[")
}

// kindOf extracts the artifact's own declared type verbatim — the top-level
// kind (or Type) field for YAML/JSON. Copying the token, attaching no meaning.
func kindOf(root interface{}) string {
	m, ok := root.(map[string]interface{})
	if !ok {
		return ""
	}
	for _, k := range []string{"kind", "Kind", "Type", "type"} {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

func (p *Parser) add(file, path, kind, typ, value string) (graph.Node, bool) {
	// Multi-document files: each --- root is its own tree sharing the file, so
	// the identity carries the document index (doc 0 keeps the bare path).
	idPath := path
	if p.doc > 0 {
		idPath = fmt.Sprintf("%d!%s", p.doc, path)
	}
	id := fmt.Sprintf("%s:%s:%s", file, idPath, typ)
	var f graph.Fields
	f.Set("path", graph.Str(path))
	f.Set("file", graph.Str(file))
	f.Set("kind", graph.Str(kind))
	if typ == "doc.Scalar" {
		f.Set("value", graph.Str(value))
	}
	n := graph.Node{ID: id, Type: typ, Layer: graph.LayerLow, Fields: f,
		Prov: graph.Provenance{Producer: "doc", Build: graph.BuildParsed, Trust: graph.TrustTrusted}}
	if err := p.store.Upsert(n); err != nil {
		return graph.Node{}, false
	}
	got, _ := p.store.Node(id)
	p.order++
	return got, true
}

// edge wires a keyed containment link; the key discriminates the member and is
// carried as the edge's own typed field.
func (p *Parser) edge(from graph.Node, to graph.Node, key string) {
	var ef graph.Fields
	ef.Set("key", graph.Str(key))
	_ = p.store.AddEdge(graph.Edge{
		ID: fmt.Sprintf("child:%s:%s:%s", from.ID, key, to.ID), Type: "child",
		From: from.ID, To: to.ID, Fields: ef,
		Prov: graph.Provenance{Producer: "doc", Build: graph.BuildParsed, Trust: graph.TrustTrusted},
	})
}

func (p *Parser) value(file, path, kind string, v interface{}) graph.Node {
	switch t := v.(type) {
	case map[string]interface{}:
		if k := kindOf(t); k != "" && path == "$" {
			kind = k
		}
		n, ok := p.add(file, path, kind, "doc.Map", "")
		if !ok {
			return n
		}
		for _, k := range sortedKeys(t) {
			child := p.value(file, join(path, k), kind, t[k])
			if child.ID != "" {
				p.edge(n, child, k)
			}
		}
		return n
	case []interface{}:
		n, ok := p.add(file, path, kind, "doc.Seq", "")
		if !ok {
			return n
		}
		for i, el := range t {
			child := p.value(file, path+"["+strconv.Itoa(i)+"]", kind, el)
			if child.ID != "" {
				p.edge(n, child, strconv.Itoa(i))
			}
		}
		return n
	default:
		val := ""
		switch t := v.(type) {
		case string:
			val = t
		case bool:
			val = strconv.FormatBool(t)
		case int:
			val = strconv.Itoa(t)
		case int64:
			val = strconv.FormatInt(t, 10)
		case float64:
			val = strconv.FormatFloat(t, 'g', -1, 64)
		case nil:
			val = "null"
		}
		n, _ := p.add(file, path, kind, "doc.Scalar", val)
		return n
	}
}

func join(parent, key string) string {
	if parent == "$" {
		return key
	}
	return parent + "." + key
}

func sortedKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// insertion-stable: sort for determinism
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
