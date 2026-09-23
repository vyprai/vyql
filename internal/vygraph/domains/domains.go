// Package domains registers the cross-artifact domain schemas  and provides the Phase 4 end-to-end acceptance: real YAML/JSON
// artifacts through the generic doc.* substrate, lifted into api./iac./iam./
// data. domain nodes in the same store as code, anchored to implementing
// handlers, with declared-vs-enforced conformance as an ordinary rule.
package domains

import (
	doc "github.com/vyprai/vyql/internal/vygraph/doc"
	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/nir"
)

// Register declares the four domain families' high-level schemas plus the
// anchor edge. Domain schemas arrive as knowledge in the full design; in the
// engine's acceptance fixtures they are declared here.
func Register(s *graph.Schemas) error {
	if err := nir.Register(s); err != nil {
		return err
	}
	if err := doc.Register(s); err != nil {
		return err
	}
	must := func(ts *graph.TypeSchema) error { return s.Register(ts) }
	if err := must(&graph.TypeSchema{Type: "code.Entrypoint", Layer: graph.LayerHigh,
		Fields: []graph.FieldSpec{
			{Name: "httpMethod", Kind: graph.KindString},
			{Name: "httpPath", Kind: graph.KindString},
			{Name: "handler", Kind: graph.KindString},
		}, Key: []string{"handler"}}); err != nil {
		return err
	}
	if err := must(&graph.TypeSchema{Type: "iac.Resource", Layer: graph.LayerHigh,
		Fields: []graph.FieldSpec{
			{Name: "kind", Kind: graph.KindString},
			{Name: "name", Kind: graph.KindString},
		}, Key: []string{"name"}}); err != nil {
		return err
	}
	if err := must(&graph.TypeSchema{Type: "iac.Container", Layer: graph.LayerHigh,
		Fields: []graph.FieldSpec{
			{Name: "privileged", Kind: graph.KindBool},
			{Name: "image", Kind: graph.KindString},
		}, Key: []string{"image"}}); err != nil {
		return err
	}
	if err := must(&graph.TypeSchema{Type: "api.Operation", Layer: graph.LayerHigh,
		Fields: []graph.FieldSpec{
			{Name: "method", Kind: graph.KindString},
			{Name: "path", Kind: graph.KindString},
		}, Key: []string{"method", "path"}}); err != nil {
		return err
	}
	if err := must(&graph.TypeSchema{Type: "api.SecurityRequirement", Layer: graph.LayerHigh,
		Fields: []graph.FieldSpec{
			{Name: "scheme", Kind: graph.KindString},
		}, Key: []string{"scheme"}}); err != nil {
		return err
	}
	if err := must(&graph.TypeSchema{Type: "iam.Policy", Layer: graph.LayerHigh,
		Fields: []graph.FieldSpec{
			{Name: "name", Kind: graph.KindString},
			{Name: "effect", Kind: graph.KindString},
		}, Key: []string{"name"}}); err != nil {
		return err
	}
	if err := must(&graph.TypeSchema{Type: "data.Table", Layer: graph.LayerHigh,
		Fields: []graph.FieldSpec{
			{Name: "name", Kind: graph.KindString},
		}, Key: []string{"name"}}); err != nil {
		return err
	}
	return must(&graph.TypeSchema{Type: "requires", Layer: graph.LayerHigh, Fields: nil, Key: nil})
}
