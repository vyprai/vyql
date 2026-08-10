package bindings

import (
	"fmt"

	"github.com/vyprai/vyql/internal/parser"
)

// Compiling authored binding declarations into graph-labeling actions.
//
// This ran inside internal/parser, which made the syntax layer the binding compiler -- the
// place that decides what `arg 1 of a call to X carries concept Y` labels. The parser now
// resolves the language and emits the declarations; deciding what they mean is here.
//
// The input is the parsed corpus rather than the flattened declaration stream, because
// name resolution is per module: `use` aliases mean the same written name resolves
// differently in two files, and a flat list of declarations has lost which module each
// came from.

// CompileSources turns every binding and pattern declaration in the corpus into
// per-technology binding sets. The keep mask mirrors the parser's: a source can be
// validated as part of the corpus without being lowered.
func CompileSources(sources []parser.V2Source, keep []bool) ([]*Set, error) {
	c := compiler{
		ctx:          parser.V2ContextFor(sources),
		matcherSpecs: v2MatcherSpecsFor(sources),
		byTech:       map[string]*Set{},
	}
	for i, src := range sources {
		if (keep != nil && !keep[i]) || src.Program == nil {
			continue
		}
		if err := c.program(src.Program); err != nil {
			return nil, fmt.Errorf("%s: %w", src.Name, err)
		}
	}
	return c.order, nil
}

type compiler struct {
	ctx          parser.V2Context
	matcherSpecs map[string]v2MatcherSpec
	byTech       map[string]*Set
	order        []*Set
}

// setFor returns the accumulating set for a technology, creating it on first use so output
// order follows the order technologies are first seen -- the order the parser produced.
func (c *compiler) setFor(tech string) *Set {
	set := c.byTech[tech]
	if set == nil {
		set = &Set{Name: tech, Meta: map[string]any{}}
		c.byTech[tech] = set
		c.order = append(c.order, set)
	}
	return set
}

func (c *compiler) program(prog *parser.V2Program) error {
	names := parser.NewV2Names(prog)
	patterns := newV2PatternResolver(prog)
	matchers := newV2MatcherResolver(prog, c.matcherSpecs)
	for _, d := range prog.Decls {
		switch x := d.(type) {
		case *parser.V2PatternDecl:
			tech, meta, err := lowerV2BindingMetaPattern(x)
			if err != nil {
				return err
			}
			if tech == "" {
				continue
			}
			set := c.setFor(tech)
			for k, v := range meta {
				set.Meta[k] = v
			}
		case *parser.V2BindingDecl:
			tech := parser.V2BindingTechnology(x.Module)
			if tech == "" {
				return fmt.Errorf("binding %s: cannot infer technology from module %q", x.Name, x.Module)
			}
			actions, err := lowerV2Binding(x, names, patterns, matchers, c.ctx)
			if err != nil {
				return err
			}
			set := c.setFor(tech)
			set.Mappings = append(set.Mappings, actions...)
		}
	}
	return nil
}

// v2MatcherSpecsFor collects every authored matcher in the corpus by qualified name. It is
// corpus-wide rather than per-module because a binding may reference a matcher another
// module declared.
func v2MatcherSpecsFor(sources []parser.V2Source) map[string]v2MatcherSpec {
	out := map[string]v2MatcherSpec{}
	for _, src := range sources {
		if src.Program == nil {
			continue
		}
		for _, d := range src.Program.Decls {
			m, ok := d.(*parser.V2MatcherDecl)
			if !ok {
				continue
			}
			if _, fq := parser.V2DeclNames(src.Program.Module, m); fq != "" {
				out[fq] = v2MatcherSpecFromDecl(m)
			}
		}
	}
	return out
}
