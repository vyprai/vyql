package adapters_test

import "github.com/vyprai/vyql/parser"

const v2CorePoliciesForAdaptersTest = `
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

func parseV2DefinitionsForTest(src string) ([]parser.Decl, error) {
	sources := []parser.V2DefinitionSource{{Name: "policies/core.vyql", Source: v2CorePoliciesForAdaptersTest}}
	sources = append(sources, parser.V2DefinitionSourcesFromText("test.vyql", src)...)
	parsed := make([]parser.V2Source, 0, len(sources))
	for _, source := range sources {
		prog, err := parser.ParseV2(source.Source)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, parser.V2Source{Name: source.Name, Program: prog})
	}
	return parser.LowerV2DefinitionSources(parsed)
}
