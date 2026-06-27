package engine

import "github.com/vyprai/vyql/parser"

const v2CoreMechanicsForEngineTest = `
module mechanics.core;
mechanic ruleVerb taint { solver: dataflow.taint fromKinds: [source] toKinds: [sink] }
mechanic ruleVerb flow { solver: dataflow.flow fromKinds: [source] toKinds: [sink] }
mechanic ruleVerb reach { solver: graph.reach fromKinds: [asset, exposure] toKinds: [asset, exposure] }
mechanic ruleVerb grant { solver: graph.grant fromKinds: [principal] toKinds: [principal, privilege] }
mechanic ruleVerb assume { solver: graph.assume fromKinds: [principal] toKinds: [principal, privilege] }
mechanic ruleVerb issue { solver: fact.exists fromKinds: [issue] }
mechanic ruleVerb fact { solver: fact.exists fromKinds: [fact, asset, exposure, principal, privilege, state, observation] }
mechanic ruleVerb query { solver: query.semantic fromKinds: [concept, fact, asset, exposure, principal, privilege, state, observation] }
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
	decls, err := parser.ParseV2Definitions(v2CoreMechanicsForEngineTest + "\n" + src)
	if err != nil {
		return nil, err
	}
	return decls, nil
}
