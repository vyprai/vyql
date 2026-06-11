// Package engine compiles and evaluates VyQL rules (docs/03, /05), ported from
// poc/vyql/engine.py. The hard boundary enforced here: every concept a rule
// references must resolve in the ontology, endpoints are kind-checked, and
// `unless sanitized_by`/`guarded_by` are typed against control<->threat<->sink
// typing at COMPILE time.
package engine

import (
	"fmt"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
)

// CompileError is a per-rule compile failure.
type CompileError struct {
	Rule string
	Msg  string
}

func (e CompileError) Error() string { return e.Rule + ": " + e.Msg }

// CompiledRule holds a rule plus precomputed typing info.
type CompiledRule struct {
	Rule               *parser.Rule
	Severity           string
	KillControls       map[string]bool // sanitizer concepts (+descendants) that kill taint
	NeutralizedThreats map[string]bool
}

// allowed concept kinds per flow verb endpoint (docs/05 §safety conditions)
var endpointKinds = map[string][2]map[string]bool{
	"taint":  {{"source": true}, {"sink": true}},
	"flow":   {{"source": true}, {"sink": true}},
	"reach":  {{"exposure": true, "asset": true}, {"asset": true, "exposure": true}},
	"assume": {{"principal": true}, {"privilege": true, "principal": true}},
}

// CompileRules compiles all rules; returns the compiled set and any errors.
func CompileRules(decls []parser.Decl, onto *ontology.Ontology) ([]*CompiledRule, []CompileError) {
	var compiled []*CompiledRule
	var errs []CompileError
	for _, d := range decls {
		r, ok := d.(*parser.Rule)
		if !ok {
			continue
		}
		cr, err := compileOne(r, onto)
		if err != nil {
			errs = append(errs, CompileError{Rule: r.QualifiedName(), Msg: err.Error()})
			continue
		}
		compiled = append(compiled, cr)
	}
	if err := checkRulesetStratified(compiled); err != nil {
		errs = append(errs, CompileError{Rule: "<ruleset>", Msg: err.Error()})
	}
	return compiled, errs
}

func requireConcept(onto *ontology.Ontology, name, where string) error {
	if !onto.Exists(name) {
		return fmt.Errorf("unknown concept '%s' in %s (rules may reference only ontology concepts)", name, where)
	}
	return nil
}

func compileOne(r *parser.Rule, onto *ontology.Ontology) (*CompiledRule, error) {
	sev := "medium"
	if s, ok := r.Meta["severity"].(string); ok {
		sev = s
	}
	cr := &CompiledRule{Rule: r, Severity: sev,
		KillControls: map[string]bool{}, NeutralizedThreats: map[string]bool{}}

	switch body := r.Body.(type) {
	case *parser.FlowStmt:
		if err := requireConcept(onto, body.Src.Concept, "source of "+r.QualifiedName()); err != nil {
			return nil, err
		}
		if err := requireConcept(onto, body.Dst.Concept, "sink/target of "+r.QualifiedName()); err != nil {
			return nil, err
		}
		if err := checkEndpointKinds(onto, body, r.QualifiedName()); err != nil {
			return nil, err
		}
		if body.Verb == "taint" || body.Verb == "flow" {
			for _, cl := range r.Clauses {
				if cl.Kind != "unless" {
					continue
				}
				switch ex := cl.Unless.(type) {
				case parser.SanitizedBy:
					if err := requireConcept(onto, ex.Concept, "sanitizer of "+r.QualifiedName()); err != nil {
						return nil, err
					}
					threat, err := onto.CheckSanitizerTyping(body.Src.Concept, body.Dst.Concept, ex.Concept)
					if err != nil {
						return nil, err
					}
					for c := range onto.Descendants(ex.Concept) {
						cr.KillControls[c] = true
					}
					cr.NeutralizedThreats[threat] = true
				case parser.GuardedBy:
					// guarded_by on a typed sink is threat-typed too (docs/06)
					if err := requireConcept(onto, ex.Concept, "guard of "+r.QualifiedName()); err != nil {
						return nil, err
					}
					if _, err := onto.CheckSanitizerTyping(body.Src.Concept, body.Dst.Concept, ex.Concept); err != nil {
						return nil, err
					}
				}
			}
		}
	case *parser.MatchStmt:
		if body.TargetKind == "concept" {
			if err := requireConcept(onto, body.Concept, "match target of "+r.QualifiedName()); err != nil {
				return nil, err
			}
		}
		for _, cl := range r.Clauses {
			if cl.Kind != "unless" {
				continue
			}
			switch ex := cl.Unless.(type) {
			case parser.SanitizedBy:
				if err := requireConcept(onto, ex.Concept, "control of "+r.QualifiedName()); err != nil {
					return nil, err
				}
			case parser.GuardedBy:
				if err := requireConcept(onto, ex.Concept, "control of "+r.QualifiedName()); err != nil {
					return nil, err
				}
			case parser.ClosedBy:
				if err := requireConcept(onto, ex.Concept, "release of "+r.QualifiedName()); err != nil {
					return nil, err
				}
			}
		}
	case *parser.OrderStmt:
		if err := requireConcept(onto, body.First.Concept, "first op of "+r.QualifiedName()); err != nil {
			return nil, err
		}
		if err := requireConcept(onto, body.Second.Concept, "second op of "+r.QualifiedName()); err != nil {
			return nil, err
		}
	}
	return cr, nil
}

func checkEndpointKinds(onto *ontology.Ontology, body *parser.FlowStmt, rule string) error {
	allowed, ok := endpointKinds[body.Verb]
	if !ok {
		return nil
	}
	src, _ := onto.Get(body.Src.Concept)
	dst, _ := onto.Get(body.Dst.Concept)
	if !allowed[0][src.Kind] {
		return fmt.Errorf("%s source '%s' is kind '%s', expected one of %v in %s (endpoints used in the wrong role)",
			body.Verb, body.Src.Concept, src.Kind, keys(allowed[0]), rule)
	}
	if !allowed[1][dst.Kind] {
		return fmt.Errorf("%s target '%s' is kind '%s', expected one of %v in %s (endpoints used in the wrong role)",
			body.Verb, body.Dst.Concept, dst.Kind, keys(allowed[1]), rule)
	}
	return nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
