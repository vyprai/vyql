package main

import (
	"github.com/vyprai/vyql/internal/bindings"
	"github.com/vyprai/vyql/internal/parser"
)

const v2CorePoliciesForCmdTest = `
module policies.core;
policy resultIdentity default {
  findingKey: [rule.id, primaryTarget.location, primaryTarget.concept]
  flagKey: [concept, location, call.path, call.method]
  fingerprint: [rule.id, primaryTarget.location, primaryTarget.concept]
  stableAcross: [formatting, requirementDiagnosticText, traversalOrder]
}
policy confidence default {
  values: [low, medium, high]
  order: [low, medium, high]
  aggregate: min(rule, endpoints, propagation, requirements)
  softRequirement missing: downgrade(1)
  softRequirement unknown: downgrade(1) annotate("uninspected evidence")
  softRequirement conflicting: downgrade(1) annotate("conflicting evidence")
  softRequirement satisfied: keep
}
`

// compileV2BindingsForTest runs both passes over one source: the parser lowers the
// declarations, the binding layer compiles the bindings.
func compileV2BindingsForTest(src string) ([]*bindings.Set, error) {
	parsed, err := parseV2SourcesForCmdTest(src)
	if err != nil {
		return nil, err
	}
	return bindings.CompileSources(parsed, nil)
}

func parseV2DefinitionsForTest(src string) ([]parser.Decl, error) {
	parsed, err := parseV2SourcesForCmdTest(src)
	if err != nil {
		return nil, err
	}
	return parser.LowerV2DefinitionSources(parsed)
}

func parseV2SourcesForCmdTest(src string) ([]parser.V2Source, error) {
	sources := []parser.V2DefinitionSource{{Name: "policies/core.vyql", Source: v2CorePoliciesForCmdTest}}
	sources = append(sources, parser.V2DefinitionSourcesFromText("test.vyql", src)...)
	parsed := make([]parser.V2Source, 0, len(sources))
	for _, source := range sources {
		prog, err := parser.ParseV2(source.Source)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, parser.V2Source{Name: source.Name, Program: prog})
	}
	return parsed, nil
}
