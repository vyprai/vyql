// Package engine compiles and evaluates VyQL rules (docs/03, /05), ported from
// poc/vyql/engine.py. The hard boundary enforced here: every concept a rule
// references must resolve in the ontology, endpoints are kind-checked, and
// v2 coveredBy controls are typed against control<->threat<->sink at COMPILE time.
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
	SourceConcepts     map[string]bool
	SinkConcepts       map[string]bool
	TaintKinds         map[string]bool
	ExcludedChars      string
	KillControls       map[string]bool // sanitizer concepts (+descendants) that kill taint
	NeutralizedThreats map[string]bool
}

// CompileRules compiles all rules; returns the compiled set and any errors.
func CompileRules(decls []parser.Decl, onto *ontology.Ontology) ([]*CompiledRule, []CompileError) {
	var compiled []*CompiledRule
	var errs []CompileError
	ruleVerbs := ruleVerbMechanicsFromDecls(decls)
	for _, d := range decls {
		r, ok := d.(*parser.Rule)
		if !ok {
			continue
		}
		cr, err := compileOne(r, onto, ruleVerbs)
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

type ruleVerbMechanicPolicy struct {
	present bool
	verbs   map[string]ruleVerbMechanic
}

type ruleVerbMechanic struct {
	FromKinds map[string]bool
	ToKinds   map[string]bool
}

func ruleVerbMechanicsFromDecls(decls []parser.Decl) ruleVerbMechanicPolicy {
	out := ruleVerbMechanicPolicy{verbs: map[string]ruleVerbMechanic{}}
	for _, d := range decls {
		m, ok := d.(*parser.V2MechanicDecl)
		if !ok || m.Kind != "ruleVerb" {
			continue
		}
		out.present = true
		out.verbs[m.Name] = ruleVerbMechanic{
			FromKinds: v2MechanicStringSet(m.Items, "fromKinds"),
			ToKinds:   v2MechanicStringSet(m.Items, "toKinds"),
		}
	}
	return out
}

func v2MechanicStringSet(items []parser.V2BlockItem, key string) map[string]bool {
	out := map[string]bool{}
	for _, item := range items {
		if len(item.Key) != 1 || item.Key[0] != key {
			continue
		}
		values, ok := item.Value.([]any)
		if !ok {
			return out
		}
		for _, value := range values {
			switch x := value.(type) {
			case string:
				out[x] = true
			case parser.V2RefExpr:
				out[x.Name] = true
			case parser.V2LiteralExpr:
				if s, ok := x.Value.(string); ok {
					out[s] = true
				}
			}
		}
		break
	}
	return out
}

func compileOne(r *parser.Rule, onto *ontology.Ontology, ruleVerbs ruleVerbMechanicPolicy) (*CompiledRule, error) {
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
		if err := checkEndpointKinds(onto, body, r.QualifiedName(), ruleVerbs); err != nil {
			return nil, err
		}
		if body.Verb == "taint" || body.Verb == "flow" {
			cr.SourceConcepts = onto.Descendants(body.Src.Concept)
			cr.SinkConcepts = onto.Descendants(body.Dst.Concept)
			cr.TaintKinds = taintKindsFor(onto, cr.SourceConcepts)
			cr.ExcludedChars = excludedCharsFor(onto, cr.SinkConcepts)
			for _, cl := range r.Clauses {
				if cl.Kind != "unless" {
					continue
				}
				switch ex := cl.Unless.(type) {
				case parser.PathCoveredBy:
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
				case parser.EndpointCoveredBy:
					// Endpoint coverage on a typed sink is threat-typed too (docs/06).
					if err := requireConcept(onto, ex.Concept, "guard of "+r.QualifiedName()); err != nil {
						return nil, err
					}
					if _, err := onto.CheckSanitizerTyping(body.Src.Concept, body.Dst.Concept, ex.Concept); err != nil {
						return nil, err
					}
				case parser.DominatesCoveredBy:
					if err := requireConcept(onto, ex.Concept, "dominating guard of "+r.QualifiedName()); err != nil {
						return nil, err
					}
					if _, err := onto.CheckSanitizerTyping(body.Src.Concept, body.Dst.Concept, ex.Concept); err != nil {
						return nil, err
					}
				case parser.PostDominatesCoveredBy:
					if err := requireConcept(onto, ex.Concept, "post-dominating guard of "+r.QualifiedName()); err != nil {
						return nil, err
					}
					if _, err := onto.CheckSanitizerTyping(body.Src.Concept, body.Dst.Concept, ex.Concept); err != nil {
						return nil, err
					}
				case parser.SameReceiverCoveredBy:
					if err := requireConcept(onto, ex.Concept, "same-receiver guard of "+r.QualifiedName()); err != nil {
						return nil, err
					}
					if _, err := onto.CheckSanitizerTyping(body.Src.Concept, body.Dst.Concept, ex.Concept); err != nil {
						return nil, err
					}
				case parser.SameScopeCoveredBy:
					if err := requireConcept(onto, ex.Concept, "same-scope guard of "+r.QualifiedName()); err != nil {
						return nil, err
					}
					if _, err := onto.CheckSanitizerTyping(body.Src.Concept, body.Dst.Concept, ex.Concept); err != nil {
						return nil, err
					}
				case parser.GlobalCoveredBy:
					if err := requireConcept(onto, ex.Concept, "global guard of "+r.QualifiedName()); err != nil {
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
			case parser.PathCoveredBy:
				if err := requireConcept(onto, ex.Concept, "control of "+r.QualifiedName()); err != nil {
					return nil, err
				}
			case parser.EndpointCoveredBy:
				if err := requireConcept(onto, ex.Concept, "control of "+r.QualifiedName()); err != nil {
					return nil, err
				}
			case parser.DominatesCoveredBy:
				if err := requireConcept(onto, ex.Concept, "dominating control of "+r.QualifiedName()); err != nil {
					return nil, err
				}
			case parser.PostDominatesCoveredBy:
				if err := requireConcept(onto, ex.Concept, "post-dominating control of "+r.QualifiedName()); err != nil {
					return nil, err
				}
			case parser.SameReceiverCoveredBy:
				if err := requireConcept(onto, ex.Concept, "same-receiver control of "+r.QualifiedName()); err != nil {
					return nil, err
				}
			case parser.SameScopeCoveredBy:
				if err := requireConcept(onto, ex.Concept, "same-scope control of "+r.QualifiedName()); err != nil {
					return nil, err
				}
			case parser.GlobalCoveredBy:
				if err := requireConcept(onto, ex.Concept, "global control of "+r.QualifiedName()); err != nil {
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

func taintKindsFor(onto *ontology.Ontology, concepts map[string]bool) map[string]bool {
	out := map[string]bool{}
	for c := range concepts {
		if cc, err := onto.Get(c); err == nil {
			for _, t := range cc.Taint {
				out[t] = true
			}
		}
	}
	return out
}

func excludedCharsFor(onto *ontology.Ontology, concepts map[string]bool) string {
	seen := map[rune]bool{}
	out := ""
	for c := range concepts {
		if cc, err := onto.Get(c); err == nil {
			for _, r := range cc.ExcludedChars {
				if !seen[r] {
					seen[r] = true
					out += string(r)
				}
			}
		}
	}
	return out
}

func checkEndpointKinds(onto *ontology.Ontology, body *parser.FlowStmt, rule string, ruleVerbs ruleVerbMechanicPolicy) error {
	if !ruleVerbs.present {
		return fmt.Errorf("no loaded mechanic ruleVerb declarations")
	}
	allowed, ok := endpointKindPolicy(body.Verb, ruleVerbs)
	if !ok {
		return fmt.Errorf("rule verb %q has no loaded mechanic ruleVerb declaration", body.Verb)
	}
	src, _ := onto.Get(body.Src.Concept)
	dst, _ := onto.Get(body.Dst.Concept)
	if !allowed[0]["concept"] && !allowed[0][src.Kind] {
		return fmt.Errorf("%s source '%s' is kind '%s', expected one of %v in %s (endpoints used in the wrong role)",
			body.Verb, body.Src.Concept, src.Kind, keys(allowed[0]), rule)
	}
	if !allowed[1]["concept"] && !allowed[1][dst.Kind] {
		return fmt.Errorf("%s target '%s' is kind '%s', expected one of %v in %s (endpoints used in the wrong role)",
			body.Verb, body.Dst.Concept, dst.Kind, keys(allowed[1]), rule)
	}
	return nil
}

func endpointKindPolicy(verb string, ruleVerbs ruleVerbMechanicPolicy) ([2]map[string]bool, bool) {
	m, ok := ruleVerbs.verbs[verb]
	if !ok {
		return [2]map[string]bool{}, false
	}
	return [2]map[string]bool{m.FromKinds, m.ToKinds}, true
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
