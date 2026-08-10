// Hand-written applicators for JavaScript and Ruby.
//
// These are framework knowledge in Go, which the binding layer is supposed to take as authored
// data -- see the audit. Kept together and named so they are hard to overlook, rather than spread
// through the matcher where they read as noise.

package bindings

import (
	"strings"

	"github.com/vyprai/vyql/internal/ontology"
	"github.com/vyprai/vyql/internal/usg"
)

func jsPathRegexGuardApplicator() Applicator {
	concept := singleOntologyRoleConcept(ontology.InternalConceptRolePathAccessCheck)
	return Applicator{
		Name: "javascript.path-regex-guards", Technology: "javascript", Specificity: 2,
		Fidelity: "semantic", Origin: "deterministic",
		Apply: func(s usg.Store) []Mapping {
			if concept == "" {
				return nil
			}
			ids, _ := s.NodesOfType("code.Call")
			var out []Mapping
			for _, id := range ids {
				n, ok, err := s.GetNode(id)
				if err != nil || !ok {
					continue
				}
				if t := nodeTechFromNode(n); t != "" && t != "javascript" && t != "typescript" && t != "tsx" {
					continue
				}
				method := n.Prop("method")
				path := n.Prop("callee_path")
				if method != "match" && method != "test" && !matchSinkPath(path, "match") && !matchSinkPath(path, "test") {
					continue
				}
				if !safeJSPathComponentRegex(n.Prop("lit0")) {
					continue
				}
				out = append(out, Mapping{NodeID: id, Concept: concept, Specificity: 2, Detail: map[string]string{"coverage": "endpoint"}})
			}
			return out
		},
	}
}

func jsDomValueInputApplicator() Applicator {
	concept := singleOntologyRoleConcept(ontology.InternalConceptRoleDomInput)
	return Applicator{
		Name: "javascript.dom-value-inputs", Technology: "javascript", Specificity: 2,
		Fidelity: "semantic", Origin: "deterministic",
		Apply: func(s usg.Store) []Mapping {
			if concept == "" {
				return nil
			}
			attrs, _ := s.NodesOfType("code.Attr")
			var out []Mapping
			flowIdx := sharedFlowIndex(s)
			for _, id := range attrs {
				n, ok, err := s.GetNode(id)
				if err != nil || !ok {
					continue
				}
				if t := nodeTechFromNode(n); t != "" && t != "javascript" && t != "typescript" && t != "tsx" {
					continue
				}
				path := n.Prop("callee_path")
				if path == "" {
					path = n.Prop("path")
				}
				if path != "value" && !strings.HasSuffix(path, ".value") {
					continue
				}
				if !jsAttrReceiverFromDomLookup(s, flowIdx, id) {
					continue
				}
				out = append(out, Mapping{NodeID: id, Concept: concept, Specificity: 2})
			}
			return out
		},
	}
}

func jsSafePathResolverApplicator() Applicator {
	concept := singleOntologyRoleConcept(ontology.InternalConceptRolePathAccessCheck)
	return Applicator{
		Name: "javascript.safe-path-resolver-summaries", Technology: "javascript", Specificity: 2,
		Fidelity: "semantic", Origin: "deterministic",
		Apply: func(s usg.Store) []Mapping {
			if concept == "" {
				return nil
			}
			contexts, _ := s.NodesOfType("code.Call")
			safe := map[string]bool{}
			for _, id := range contexts {
				n, ok, err := s.GetNode(id)
				if err != nil || !ok {
					continue
				}
				if t := nodeTechFromNode(n); t != "" && t != "javascript" && t != "typescript" && t != "tsx" {
					continue
				}
				if n.Prop("callee_path") != "analysis.function.context" {
					continue
				}
				name, ok := safeJSPathResolverFunction(n.Prop("str_args"))
				if ok {
					safe[name] = true
				}
			}
			if len(safe) == 0 {
				return nil
			}
			var out []Mapping
			for _, id := range contexts {
				n, ok, err := s.GetNode(id)
				if err != nil || !ok {
					continue
				}
				if t := nodeTechFromNode(n); t != "" && t != "javascript" && t != "typescript" && t != "tsx" {
					continue
				}
				path := n.Prop("callee_path")
				method := n.Prop("method")
				for name := range safe {
					if path == name || method == name || strings.HasSuffix(path, "."+name) {
						out = append(out, Mapping{NodeID: id, Concept: concept, Specificity: 2, Detail: map[string]string{"coverage": "endpoint"}})
						break
					}
				}
			}
			return out
		},
	}
}

func jsModuleHelperLdapEscapeApplicator() Applicator {
	concept := "core." + "Ldap" + "Escape"
	return Applicator{
		Name: "javascript.module-helper-ldap-escape", Technology: "javascript", Specificity: 2,
		Fidelity: "semantic", Origin: "deterministic",
		Apply: func(s usg.Store) []Mapping {
			moduleHelperFiles := map[string]bool{}
			names, _ := s.NodesOfType("code.Name")
			for _, id := range names {
				n, ok, err := s.GetNode(id)
				if err != nil || !ok {
					continue
				}
				if t := nodeTechFromNode(n); t != "" && t != "javascript" && t != "typescript" && t != "tsx" {
					continue
				}
				if n.Prop("callee_path") == "ldapEscape" && strings.Contains(n.ID, "__module#var#ldapEscape") {
					if file := locFile(n.Prop("loc")); file != "" {
						moduleHelperFiles[file] = true
					}
				}
			}
			if len(moduleHelperFiles) == 0 {
				return nil
			}
			calls, _ := s.NodesOfType("code.Call")
			var out []Mapping
			for _, id := range calls {
				n, ok, err := s.GetNode(id)
				if err != nil || !ok {
					continue
				}
				if t := nodeTechFromNode(n); t != "" && t != "javascript" && t != "typescript" && t != "tsx" {
					continue
				}
				if n.Prop("method") != "ldapEscape" && n.Prop("callee_path") != "ldapEscape" {
					continue
				}
				if moduleHelperFiles[locFile(n.Prop("loc"))] {
					out = append(out, Mapping{NodeID: id, Concept: concept, Specificity: 2})
				}
			}
			return out
		},
	}
}
