package lowering

import "github.com/vyprai/vyql/parser"

const v2CoreMechanicsForLoweringTest = `
module mechanics.core;
mechanic ruleVerb taint { solver: dataflow.taint }
mechanic ruleVerb flow { solver: dataflow.flow }
mechanic ruleVerb reach { solver: graph.reach }
mechanic ruleVerb grant { solver: graph.grant }
mechanic ruleVerb assume { solver: graph.assume }
mechanic ruleVerb issue { solver: fact.exists }
mechanic ruleVerb fact { solver: fact.exists }
mechanic ruleVerb query { solver: query.semantic }
`

func parseV2DefinitionsForTest(src string) ([]parser.Decl, error) {
	decls, err := parser.ParseV2Definitions(v2CoreMechanicsForLoweringTest + "\n" + src)
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
