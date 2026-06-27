package lowering

import "github.com/vyprai/vyql/parser"

const v2CoreMechanicsForLoweringTest = `
module mechanics.core;
mechanic coverage path { capability: coverage.path requiresAnchor: true targetParts: [path] }
mechanic coverage endpoint { capability: coverage.endpoint requiresAnchor: true targetParts: [endpoint] }
mechanic coverage sameReceiver { capability: coverage.sameReceiver requiresAnchor: true targetParts: [sameReceiver] }
mechanic coverage sameScope { capability: coverage.sameScope requiresAnchor: true targetParts: [sameScope] }
mechanic coverage dominates { capability: coverage.dominates requiresAnchor: true targetParts: [dominates] }
mechanic coverage postDominates { capability: coverage.postDominates requiresAnchor: true targetParts: [postDominates] }
mechanic coverage global { capability: coverage.global requiresAnchor: false targetParts: [global] }
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
	sources := []parser.V2DefinitionSource{{Name: "mechanics/core.vyql", Source: v2CoreMechanicsForLoweringTest}}
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
