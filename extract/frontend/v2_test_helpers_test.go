package frontend

import "github.com/vyprai/vyql/parser"

const v2CoreMechanicsForFrontendTest = `
module mechanics.core;
mechanic ruleVerb taint { solver: dataflow.taint }
mechanic ruleVerb flow { solver: dataflow.flow }
mechanic ruleVerb reach { solver: graph.reach }
mechanic ruleVerb grant { solver: graph.grant }
mechanic ruleVerb assume { solver: graph.assume }
mechanic ruleVerb issue { solver: fact.exists }
mechanic ruleVerb fact { solver: fact.exists }
mechanic ruleVerb query { solver: query.semantic }
mechanic coverage path { capability: coverage.path requiresAnchor: true targetParts: [path] }
mechanic coverage endpoint { capability: coverage.endpoint requiresAnchor: true targetParts: [endpoint] }
mechanic coverage sameReceiver { capability: coverage.sameReceiver requiresAnchor: true targetParts: [sameReceiver] }
mechanic coverage sameScope { capability: coverage.sameScope requiresAnchor: true targetParts: [sameScope] }
mechanic coverage dominates { capability: coverage.dominates requiresAnchor: true targetParts: [dominates] }
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
	decls, err := parser.ParseV2Definitions(v2CoreMechanicsForFrontendTest + "\n" + src)
	if err != nil {
		return nil, err
	}
	out := decls[:0]
	for _, decl := range decls {
		switch decl.(type) {
		case *parser.V2MechanicDecl, *parser.V2PolicyDecl:
			continue
		default:
			out = append(out, decl)
		}
	}
	return out, nil
}
