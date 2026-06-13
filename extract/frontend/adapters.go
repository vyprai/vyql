// Package frontend turns extracted code.* graphs into concept labels using
// framework adapters (docs/07). The adapter CONTENT — which framework calls
// are inputs, sinks, controls, and which constructors yield which types — is
// VyQL, authored in vyql/adapters/<tech>.vyql and loaded at runtime. Only the
// matching engine and the language parsers are Go code.
package frontend

import (
	"strconv"
	"strings"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

type inputSpec struct {
	Concept    string
	Paths      []string
	Methods    []string // receiver-agnostic: match the call's `method` prop (last segment)
	Match      string   // "prefix" (default) | "contains"
	ValMatches []string // `val "substr"` (AND) — only a source when an arg literal matches (e.g. getenv("HTTP_*"))
	ValAbsents []string // `nval "substr"` (AND) — not a source if any arg literal contains a substr
}

type sinkSpec struct {
	Concept    string
	Pattern    string
	ByMethod   bool     // match the bare method name vs the dotted callee path
	Receiver   bool     // tainted data is the RECEIVER, not an arg — label the call node
	Constraint string   // optional `on <type>` receiver-type constraint
	ArgIndex   int      // which argument is the dangerous one (default 0)
	ValMatches []string // `val "substr"` (AND) — every substr must be in some arg/option literal
	ValAbsents []string // `nval "substr"` (AND) — no arg/option literal may contain any substr
	Collection bool     // also flag a Seq/collection-literal arg (e.g. ldap options {filter})
}

type controlSpec struct {
	Concept    string
	Pattern    string
	ByMethod   bool     // match the call's `method` prop (receiver-agnostic, e.g. .close())
	ValMatches []string // `val "substr"` (AND — marks AND controls)
	ValAbsents []string // `nval "substr"` (AND — marks AND controls)
}

// activeSources, when non-nil, restricts which source concepts the input adapters
// emit — i.e. the active profile's trust boundary. nil = every source active.
var activeSources map[string]bool

// SetActiveSources sets the trust-boundary filter for source labelling (the
// active application profile's entry-point families). Pass nil to disable.
func SetActiveSources(s map[string]bool) { activeSources = s }

// valContains reports whether the NUL-joined str_args prop contains sub,
// case-insensitively. Used by `val`/`nval` matching.
func valContains(tokens, sub string) bool {
	return strings.Contains(strings.ToLower(tokens), strings.ToLower(sub))
}

// valConds reports whether every `val` substring is present (AND) and every
// `nval` substring is absent among the value tokens. Empty lists pass.
func valConds(tokens string, vals, nvals []string) bool {
	for _, v := range vals {
		if !valContains(tokens, v) {
			return false
		}
	}
	for _, nv := range nvals {
		if valContains(tokens, nv) {
			return false
		}
	}
	return true
}

func detailWithPattern(detail map[string]string, pattern string) map[string]string {
	if len(detail) == 0 {
		return nil
	}
	out := make(map[string]string, len(detail)+1)
	for k, v := range detail {
		out[k] = v
	}
	if pattern != "" && out["pattern"] == "" {
		out["pattern"] = pattern
	}
	return out
}

func exploitDetail(concept, pattern string) (map[string]string, string) {
	detail := map[string]string{}
	conf := ""
	switch concept {
	case "code.UnboundedCopy":
		detail = map[string]string{
			"exploit_category":   "memory",
			"exploit_condition":  "attacker-controlled bytes reach an unbounded copy into a fixed-size destination",
			"exploit_evidence":   "unsafe copy primitive " + pattern + " receives tainted input",
			"exploit_assumption": "the destination capacity can be smaller than the copied bytes",
			"exploit_confidence": "high",
		}
	case "code.UnboundedCopySmell":
		detail = map[string]string{
			"exploit_category":   "memory",
			"exploit_condition":  "an unbounded copy can overflow its destination",
			"exploit_evidence":   "unsafe copy primitive " + pattern + " is present",
			"exploit_assumption": "an attacker can influence source length or destination capacity is insufficient",
			"exploit_confidence": "low",
		}
		conf = "low"
	case "code.RawMemoryCopySize":
		detail = map[string]string{
			"exploit_category":   "memory",
			"exploit_condition":  "attacker-controlled size reaches a raw memory copy",
			"exploit_evidence":   "copy-size argument to " + pattern + " is tainted",
			"exploit_assumption": "the size can exceed the destination object bounds",
			"exploit_confidence": "medium",
		}
	case "code.SizeComputation":
		detail = map[string]string{
			"exploit_category":   "numeric",
			"exploit_condition":  "attacker-controlled size feeds allocation or bounds-sensitive operation",
			"exploit_evidence":   "size argument to " + pattern + " is tainted",
			"exploit_assumption": "the value is not range-checked before memory use",
			"exploit_confidence": "medium",
		}
	case "code.StackAllocationSmell":
		detail = map[string]string{
			"exploit_category":   "memory",
			"exploit_condition":  "unbounded stack allocation can exhaust stack or corrupt nearby state",
			"exploit_evidence":   "stack allocation primitive " + pattern + " is present",
			"exploit_assumption": "the allocation size can be attacker-influenced or unexpectedly large",
			"exploit_confidence": "low",
		}
		conf = "low"
	case "code.FileCheck":
		detail = map[string]string{
			"exploit_category":   "race",
			"exploit_condition":  "filesystem state is checked before a later use",
			"exploit_evidence":   "check primitive " + pattern + " observes path state",
			"exploit_assumption": "an attacker can change the path target between check and use",
			"exploit_confidence": "medium",
		}
	case "code.FileUse":
		detail = map[string]string{
			"exploit_category":   "race",
			"exploit_condition":  "checked filesystem state is later used",
			"exploit_evidence":   "use primitive " + pattern + " acts on the path",
			"exploit_assumption": "the use is not protected by atomic open flags or symlink-safe handling",
			"exploit_confidence": "medium",
		}
	case "code.LockAcquire":
		detail = map[string]string{
			"exploit_category":   "lifecycle",
			"exploit_condition":  "a lock acquisition may not be released on every path",
			"exploit_evidence":   "lock primitive " + pattern + " is acquired",
			"exploit_assumption": "an unreleased lock can be triggered to deadlock or starve concurrent work",
			"exploit_confidence": "medium",
		}
	case "code.LocklessSharedMutation":
		detail = map[string]string{
			"exploit_category":   "race",
			"exploit_condition":  "shared state appears to be mutated without an observed lock or atomic guard",
			"exploit_evidence":   "concurrency-capable mutation primitive " + pattern + " is present",
			"exploit_assumption": "multiple attacker-triggerable executions can interleave on the same state",
			"exploit_confidence": "low",
		}
		conf = "low"
	case "code.IndexAccess":
		detail = map[string]string{
			"exploit_category":   "memory",
			"exploit_condition":  "attacker-controlled index reaches an array/subscript access",
			"exploit_evidence":   "subscript index flows into " + pattern,
			"exploit_assumption": "the index is not range-checked against the accessed object",
			"exploit_confidence": "medium",
		}
	case "code.DivisionDenominator":
		detail = map[string]string{
			"exploit_category":   "numeric",
			"exploit_condition":  "attacker-controlled denominator reaches division or modulo",
			"exploit_evidence":   "denominator operand for " + pattern + " is tainted",
			"exploit_assumption": "zero or unsafe divisor values are not excluded before the operation",
			"exploit_confidence": "medium",
		}
	case "code.IntegerSizeArithmetic":
		detail = map[string]string{
			"exploit_category":   "numeric",
			"exploit_condition":  "attacker-controlled value participates in size-sensitive arithmetic",
			"exploit_evidence":   "arithmetic operation " + pattern + " receives tainted input",
			"exploit_assumption": "the arithmetic result is later used for allocation, indexing, copy size, or bounds",
			"exploit_confidence": "low",
		}
		conf = "low"
	case "code.PointerFree":
		detail = map[string]string{
			"exploit_category":   "memory",
			"exploit_condition":  "a pointer is released and may be released or used again later",
			"exploit_evidence":   "release primitive " + pattern + " is observed",
			"exploit_assumption": "the same allocation or alias is involved and remains attacker-reachable",
			"exploit_confidence": "low",
		}
		conf = "low"
	case "code.PointerUse":
		detail = map[string]string{
			"exploit_category":   "memory",
			"exploit_condition":  "a pointer is dereferenced or otherwise used after a prior release",
			"exploit_evidence":   "pointer-use primitive " + pattern + " is observed",
			"exploit_assumption": "the pointer aliases the released allocation and no safe reinitialization occurs",
			"exploit_confidence": "low",
		}
		conf = "low"
	case "code.NullableDeref":
		detail = map[string]string{
			"exploit_category":   "memory",
			"exploit_condition":  "a pointer-like value is dereferenced without an observed null exclusion",
			"exploit_evidence":   "dereference primitive " + pattern + " is present",
			"exploit_assumption": "the dereferenced value may be null on an attacker-triggerable path",
			"exploit_confidence": "low",
		}
		conf = "low"
	case "code.AuthenticationRequiredOp":
		detail = map[string]string{
			"exploit_category":   "auth",
			"exploit_condition":  "security-sensitive operation is reachable without an observed authentication guard",
			"exploit_evidence":   "sensitive operation " + pattern + " is present",
			"exploit_assumption": "the enclosing endpoint or entry point can be reached by an unauthenticated actor",
			"exploit_confidence": "low",
		}
		conf = "low"
	case "code.ObjectLookupByUserInput":
		detail = map[string]string{
			"exploit_category":   "access_control",
			"exploit_condition":  "attacker-controlled object id reaches a direct object lookup",
			"exploit_evidence":   "lookup primitive " + pattern + " receives tainted input",
			"exploit_assumption": "the object is not constrained to the authenticated principal or tenant",
			"exploit_confidence": "medium",
		}
	case "code.ArchiveEntryWrite":
		detail = map[string]string{
			"exploit_category":   "path",
			"exploit_condition":  "attacker-controlled archive entry path reaches filesystem write/extraction",
			"exploit_evidence":   "archive extraction/write primitive " + pattern + " receives tainted input",
			"exploit_assumption": "the entry name is not normalized, confined, or symlink-safe before writing",
			"exploit_confidence": "medium",
		}
	case "code.StaticIv":
		detail = map[string]string{
			"exploit_category":   "crypto",
			"exploit_condition":  "cipher operation uses a static or predictable IV/nonce",
			"exploit_evidence":   "cipher primitive " + pattern + " is called with static-looking IV material",
			"exploit_assumption": "the mode requires nonce/IV uniqueness for confidentiality or integrity",
			"exploit_confidence": "low",
		}
		conf = "low"
	case "code.DynamicCodeLoad":
		detail = map[string]string{
			"exploit_category":   "code_loading",
			"exploit_condition":  "attacker-controlled module or library name reaches a dynamic code loader",
			"exploit_evidence":   "dynamic loader " + pattern + " receives tainted input",
			"exploit_assumption": "the resolved module/library path or search path can be influenced by the attacker",
			"exploit_confidence": "medium",
		}
	}
	return detailWithPattern(detail, pattern), conf
}

type filterSpec struct {
	Pattern  string
	ByMethod bool // match the bare method name (x.replace) vs the dotted path (re.sub)
	Global   bool // always-global replace (gsub/replaceAll/re.sub); else needs the /g flag
}

// assumeSpec is an UNSOUND neutralizer: a guard (dominance) or sanitizer (on-path) that
// *might* defuse a threat but cannot be proven to. Labelled core.Assumption; never kills a
// flow — the engine attaches an assumption note instead. (The regex-CharFilter pattern,
// generalized to arbitrary neutralizers via the `assume` directive.)
type assumeSpec struct {
	Pattern    string
	ByMethod   bool
	Mode       string // "guard" (must dominate the sink) | "sanitizer" (must lie on the path)
	About      string // the sink concept it purports to cover
	ValMatches []string
	ValAbsents []string
}

type adapterSpec struct {
	Name          string
	Technology    string
	containsMatch bool
	crossLang     bool // labels nodes in EVERY language (skips the per-tech filter)
	Inputs        []inputSpec
	Sinks         []sinkSpec
	Controls      []controlSpec
	Marks         []controlSpec // presence markers (label the call node with a concept)
	Filters       []filterSpec  // character-filtering replaces (core.CharFilter)
	Assumes       []assumeSpec  // unsound neutralizers (core.Assumption)
}

// AdaptersFor loads the framework adapters for a technology from
// vyql/adapters/<tech>.vyql and builds the input + sink + control adapters.
func AdaptersFor(tech string) []adapters.Adapter {
	spec := loadSpec(tech)
	var out []adapters.Adapter
	if len(spec.Inputs) > 0 {
		out = append(out, spec.inputAdapter())
	}
	if len(spec.Sinks) > 0 {
		out = append(out, spec.sinkAdapter())
	}
	if len(spec.Controls) > 0 {
		out = append(out, spec.controlAdapter())
	}
	if len(spec.Marks) > 0 {
		out = append(out, spec.markAdapter())
	}
	if len(spec.Filters) > 0 {
		out = append(out, spec.filterAdapter())
	}
	if len(spec.Assumes) > 0 {
		out = append(out, spec.assumeAdapter())
	}
	return out
}

// assumeAdapter labels unsound-neutralizer calls (guards/escapers that cannot be proven
// sound) with core.Assumption, recording the mode (guard|sanitizer) and the sink concept it
// purports to cover. The engine never suppresses a flow on this label; when such a node
// guards/sanitizes a finding it attaches an assumption note — generalizing the regex
// CharFilter mechanism to any neutralizer whose soundness vyql cannot establish.
func (spec adapterSpec) assumeAdapter() adapters.Adapter {
	return adapters.Adapter{
		Name: spec.Name + ".assumptions", Technology: spec.Technology, Specificity: 2,
		Fidelity: "syntactic", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			ids, _ := s.NodesOfType("code.Call")
			var out []adapters.Mapping
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if t := nodeTech(n.Prop("loc")); t != "" && t != spec.Technology {
					continue
				}
				method, path := n.Prop("method"), n.Prop("callee_path")
				for _, as := range spec.Assumes {
					if !(as.ByMethod && method == as.Pattern || !as.ByMethod && matchSinkPath(path, as.Pattern)) {
						continue
					}
					if !valConds(n.Prop("str_args"), as.ValMatches, as.ValAbsents) {
						continue
					}
					out = append(out, adapters.Mapping{NodeID: id, Concept: "core.Assumption",
						Detail: map[string]string{"mode": as.Mode, "about": as.About, "pattern": as.Pattern}})
					break
				}
			}
			return out
		},
	}
}

// filterAdapter labels character-filtering replace(pattern, repl) calls with
// core.CharFilter, recording the proven OUTPUT alphabet (or that it is unbounded) in
// the label Detail. The solver then treats it as a SOUND sanitizer for any sink whose
// dangerous chars the alphabet excludes, and the engine surfaces an unproven filter as
// an assumption note. The regex math is general (charfilter.go); WHICH methods filter
// is data (the `filter` directive).
func (spec adapterSpec) filterAdapter() adapters.Adapter {
	return adapters.Adapter{
		Name: spec.Name + ".filters", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			ids, _ := s.NodesOfType("code.Call")
			var out []adapters.Mapping
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if t := nodeTech(n.Prop("loc")); t != "" && t != spec.Technology {
					continue
				}
				method, path := n.Prop("method"), n.Prop("callee_path")
				matched, global := false, false
				for _, f := range spec.Filters {
					if f.ByMethod && method == f.Pattern || !f.ByMethod && matchSinkPath(path, f.Pattern) {
						matched, global = true, f.Global
						break
					}
				}
				if !matched {
					continue
				}
				pattern, repl := n.Prop("lit0"), n.Prop("lit1")
				alphabet, bounded := outputAlphabet(pattern, repl, global)
				detail := map[string]string{"bounded": "false", "pattern": pattern}
				if bounded {
					detail["bounded"] = "true"
					detail["alphabet"] = alphabet
				}
				out = append(out, adapters.Mapping{NodeID: id, Concept: "core.CharFilter", Detail: detail})
			}
			return out
		},
	}
}

// CtorTypesFor returns the constructor→type table declared in the adapter (the
// `type "sql.Open" -> sql.DB` mappings), used by the lowering to stamp recv_type.
func CtorTypesFor(tech string) map[string]string {
	out := map[string]string{}
	for _, mp := range loadDecl(tech).Mappings {
		if mp.Kind == "type" {
			out[mp.Pattern] = mp.Concept
		}
	}
	return out
}

func loadDecl(tech string) *parser.AdapterDecl {
	decls, err := parser.Parse(string(datadir.MustRead("adapters/" + tech + ".vyql")))
	if err != nil {
		panic("frontend: invalid adapters/" + tech + ".vyql: " + err.Error())
	}
	for _, d := range decls {
		if a, ok := d.(*parser.AdapterDecl); ok {
			return a
		}
	}
	panic("frontend: no adapter declaration in adapters/" + tech + ".vyql")
}

func loadSpec(tech string) adapterSpec {
	d := loadDecl(tech)
	s := adapterSpec{Name: d.Name, Technology: d.Name}
	if m, _ := d.Meta["match"].(string); m == "contains" {
		s.containsMatch = true
	}
	if cl, _ := d.Meta["cross_language"].(string); cl == "true" {
		s.crossLang = true
	}
	matchMode := "prefix"
	if s.containsMatch {
		matchMode = "contains"
	}
	srcByConcept := map[string]int{}
	for _, mp := range d.Mappings {
		switch mp.Kind {
		case "source":
			// a value-constrained source (e.g. getenv("HTTP_*")) gets its own spec so the
			// val/nval filter is not shared with other patterns mapping to the same concept.
			if len(mp.ValMatches) > 0 || len(mp.ValAbsents) > 0 {
				s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, Match: matchMode,
					Paths: []string{mp.Pattern}, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents})
				break
			}
			i, ok := srcByConcept[mp.Concept]
			if !ok {
				s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, Match: matchMode})
				i = len(s.Inputs) - 1
				srcByConcept[mp.Concept] = i
			}
			s.Inputs[i].Paths = append(s.Inputs[i].Paths, mp.Pattern)
		case "source_method":
			if len(mp.ValMatches) > 0 || len(mp.ValAbsents) > 0 {
				s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, Match: matchMode,
					Methods: []string{mp.Pattern}, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents})
				break
			}
			i, ok := srcByConcept[mp.Concept]
			if !ok {
				s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, Match: matchMode})
				i = len(s.Inputs) - 1
				srcByConcept[mp.Concept] = i
			}
			s.Inputs[i].Methods = append(s.Inputs[i].Methods, mp.Pattern)
		case "sink_method":
			s.Sinks = append(s.Sinks, sinkSpec{Concept: mp.Concept, Pattern: mp.Pattern, ByMethod: true, Constraint: mp.Constraint, ArgIndex: mp.ArgIndex, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Collection: mp.Collection})
		case "sink_path":
			s.Sinks = append(s.Sinks, sinkSpec{Concept: mp.Concept, Pattern: mp.Pattern, Constraint: mp.Constraint, ArgIndex: mp.ArgIndex, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Collection: mp.Collection})
		case "sink_receiver":
			// the tainted DATA is the receiver of a no-arg method (e.g. `URL(u).openConnection()`,
			// `u.toRegex()`); match the bare method name, label the call node itself.
			s.Sinks = append(s.Sinks, sinkSpec{Concept: mp.Concept, Pattern: mp.Pattern, ByMethod: true, Receiver: true, Constraint: mp.Constraint, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents})
		case "control":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, Pattern: mp.Pattern,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents})
		case "control_method":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, Pattern: mp.Pattern,
				ByMethod: true, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents})
		case "mark":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, Pattern: mp.Pattern, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents})
		case "filter_method":
			s.Filters = append(s.Filters, filterSpec{Pattern: mp.Pattern, ByMethod: true, Global: mp.Constraint == "global"})
		case "filter_path":
			s.Filters = append(s.Filters, filterSpec{Pattern: mp.Pattern, Global: mp.Constraint == "global"})
		case "assume_guard_method", "assume_guard_path", "assume_sanitizer_method", "assume_sanitizer_path":
			mode := "guard"
			if strings.Contains(mp.Kind, "sanitizer") {
				mode = "sanitizer"
			}
			s.Assumes = append(s.Assumes, assumeSpec{Pattern: mp.Pattern, ByMethod: strings.HasSuffix(mp.Kind, "_method"),
				Mode: mode, About: mp.About, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents})
		}
	}
	return s
}

// inputAdapter labels source reads. Prefix matching is `resolved`; `contains`
// matching (Go's varying receivers) is `syntactic` → lower confidence.
func (spec adapterSpec) inputAdapter() adapters.Adapter {
	fidelity := "resolved"
	if spec.containsMatch {
		fidelity = "syntactic"
	}
	return adapters.Adapter{
		Name: spec.Name + ".input", Technology: spec.Technology, Specificity: 2,
		Fidelity: fidelity, Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			nodes, _ := s.AllNodes()
			var out []adapters.Mapping
			for _, n := range nodes {
				path, method := n.Prop("callee_path"), n.Prop("method")
				if path == "" && method == "" {
					continue
				}
				if t := nodeTech(n.Prop("loc")); !spec.crossLang && t != "" && t != spec.Technology {
					continue // only label this language's nodes (cross-language adapters skip this)
				}
				for _, in := range spec.Inputs {
					if (path != "" && matchPath(path, in.Paths, in.Match)) ||
						(method != "" && containsStr(in.Methods, method)) {
						// value-constrained source: only a source when an arg literal matches
						// (e.g. getenv("HTTP_X_FORWARDED_FOR") yes, getenv("PATH") no).
						if (len(in.ValMatches) > 0 || len(in.ValAbsents) > 0) &&
							!valConds(n.Prop("str_args"), in.ValMatches, in.ValAbsents) {
							continue
						}
						// trust-boundary gating: an active profile restricts which
						// source families count as attacker-controlled.
						if activeSources == nil || activeSources[in.Concept] {
							out = append(out, adapters.Mapping{NodeID: n.ID, Concept: in.Concept})
						}
						break
					}
				}
			}
			return out
		},
	}
}

// sinkAdapter labels arg0 of matching calls with a PER-MAPPING fidelity:
//   - dotted-path match           → resolved (high)
//   - bare-method match, no `on`  → syntactic (medium — receiver type unknown)
//   - method match with `on T`:
//     recv_type == T              → resolved (high, type-verified)
//     recv_type unknown           → syntactic (medium, can't disprove)
//     recv_type != T              → SKIP (known wrong type — not a sink here)
//
// Collection-literal arg0s (vkind == Seq, e.g. Rails where(id: x)) are skipped.
func (spec adapterSpec) sinkAdapter() adapters.Adapter {
	return adapters.Adapter{
		Name: spec.Name + ".sinks", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			ids, _ := s.NodesOfType("code.Call")
			attrs, _ := s.NodesOfType("code.Attr")
			ids = append(ids, attrs...)
			binops, _ := s.NodesOfType("code.BinOp")
			ids = append(ids, binops...)
			var out []adapters.Mapping
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if t := nodeTech(n.Prop("loc")); t != "" && t != spec.Technology {
					continue // only label this language's nodes
				}
				isAttr := n.Type == "code.Attr"
				method, path, recvType := n.Prop("method"), n.Prop("callee_path"), n.Prop("recv_type")
				// Pick the MOST SPECIFIC matching sink (longest pattern) per concept, so
				// e.g. "re.compile" wins over "compile" for CodeEval/RegexCompile-style
				// overlaps, while one call can still carry genuinely distinct concepts
				// such as FilePathAccess and UnsafeUpload.
				bestByConcept := map[string]int{}
				strArgs := n.Prop("str_args")
				for i, sk := range spec.Sinks {
					if isAttr && sk.Concept != "code.ProtoPollute" {
						continue
					}
					hit := sk.ByMethod && method == sk.Pattern ||
						!sk.ByMethod && matchSinkPath(path, sk.Pattern)
					// value-matched sink: every `val` must be present and every `nval`
					// absent among the literal arg/option tokens (case-insensitive).
					if hit && !valConds(strArgs, sk.ValMatches, sk.ValAbsents) {
						hit = false
					}
					if !hit {
						continue
					}
					// Most specific wins: longer pattern, then more value constraints
					// (a `val`-matched sink like exec.Command arg2 val "-c" is more
					// specific than the plain exec.Command arg0 form).
					if curIdx, ok := bestByConcept[sk.Concept]; !ok {
						bestByConcept[sk.Concept] = i
					} else if cur := spec.Sinks[curIdx]; len(sk.Pattern) > len(cur.Pattern) ||
						(len(sk.Pattern) == len(cur.Pattern) && len(sk.ValMatches) > len(cur.ValMatches)) {
						bestByConcept[sk.Concept] = i
					}
				}
				for i, sk := range spec.Sinks {
					best, ok := bestByConcept[sk.Concept]
					if !ok || best != i {
						continue
					}
					if isAttr {
						if sk.ByMethod {
							detail, conf := exploitDetail(sk.Concept, sk.Pattern)
							out = append(out, adapters.Mapping{NodeID: id, Concept: sk.Concept, Fidelity: "syntactic", Confidence: conf, Detail: detail})
						} else {
							detail, conf := exploitDetail(sk.Concept, sk.Pattern)
							out = append(out, adapters.Mapping{NodeID: id, Concept: sk.Concept, Fidelity: "resolved", Confidence: conf, Detail: detail})
						}
						continue
					}
					// receiver-sink: the tainted data is the receiver; the call node
					// carries that taint, so label the node itself rather than an arg.
					if sk.Receiver {
						detail, conf := exploitDetail(sk.Concept, sk.Pattern)
						out = append(out, adapters.Mapping{NodeID: id, Concept: sk.Concept, Fidelity: "syntactic", Confidence: conf, Detail: detail})
						continue
					}
					fidelity := "resolved"
					if sk.ByMethod {
						fidelity = "syntactic"
					}
					if sk.Constraint != "" {
						switch {
						case recvType == "":
							// unknown type — can't disprove, keep syntactic
						case constraintAllows(sk.Constraint, recvType):
							fidelity = "resolved" // type-verified
						default:
							continue // known, conflicting type — not this sink
						}
					}
					// arg all (ArgIndex == -1): any tainted argument is the vuln (e.g. a
					// writer .format/.printf where the injectable value can be at any position).
					if sk.ArgIndex < 0 {
						for ai := 0; ; ai++ {
							arg := n.Prop("arg" + strconv.Itoa(ai))
							if arg == "" {
								break
							}
							if a, ok, _ := s.GetNode(arg); ok && !sk.Collection && a.Prop("vkind") == "Seq" {
								continue
							}
							detail, conf := exploitDetail(sk.Concept, sk.Pattern)
							out = append(out, adapters.Mapping{NodeID: arg, Concept: sk.Concept, Fidelity: fidelity, Confidence: conf, Detail: detail})
						}
						continue
					}
					arg := n.Prop("arg" + strconv.Itoa(sk.ArgIndex))
					if arg == "" {
						continue
					}
					if a, ok, _ := s.GetNode(arg); ok && !sk.Collection && a.Prop("vkind") == "Seq" {
						continue
					}
					detail, conf := exploitDetail(sk.Concept, sk.Pattern)
					out = append(out, adapters.Mapping{NodeID: arg, Concept: sk.Concept, Fidelity: fidelity, Confidence: conf, Detail: detail})
				}
			}
			return out
		},
	}
}

// controlAdapter labels control concepts (escapers/validators) on the calls that
// apply them, so `unless sanitized_by` can suppress a sanitized flow (docs/07).
func (spec adapterSpec) controlAdapter() adapters.Adapter {
	return adapters.Adapter{
		Name: spec.Name + ".controls", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			ids, _ := s.NodesOfType("code.Call")
			var out []adapters.Mapping
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if t := nodeTech(n.Prop("loc")); t != "" && t != spec.Technology {
					continue // only label this language's nodes
				}
				path, method := n.Prop("callee_path"), n.Prop("method")
				strArgs := n.Prop("str_args")
				for _, c := range spec.Controls {
					// no break: a single call can be MULTIPLE controls (e.g. numeric coercion
					// neutralizes HTML, SQL, AND trust-boundary), so attach every match.
					hit := c.ByMethod && method == c.Pattern || !c.ByMethod && matchPath(path, []string{c.Pattern}, "prefix")
					if hit && valConds(strArgs, c.ValMatches, c.ValAbsents) {
						out = append(out, adapters.Mapping{NodeID: id, Concept: c.Concept})
					}
				}
			}
			return out
		},
	}
}

// extTech maps a source file extension to its adapter technology, so an adapter
// only labels nodes from its own language (avoids cross-language FPs in polyglot
// repos — e.g. the JS `exec` sink matching a Bash `exec` command).
var extTech = map[string]string{
	".go": "go", ".py": "python",
	".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript",
	".rb": "ruby", ".java": "java", ".php": "php", ".phtml": "php", ".cs": "csharp",
	".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
	".rs": "rust", ".sh": "bash", ".bash": "bash", ".scala": "scala", ".sc": "scala", ".lua": "lua", ".kt": "kotlin", ".kts": "kotlin", ".ps1": "powershell", ".psm1": "powershell", ".swift": "swift", ".pl": "perl", ".pm": "perl", ".cgi": "perl", ".sol": "solidity", ".m": "objc",
	".xml": "config", ".plist": "config",
	".ex": "elixir", ".exs": "elixir",
	".dart":   "dart",
	".groovy": "groovy", ".gradle": "groovy",
}

// nodeTech returns the language technology of a node from its loc ("file.ext:line").
func nodeTech(loc string) string {
	if i := strings.LastIndexByte(loc, ':'); i >= 0 {
		loc = loc[:i]
	}
	if i := strings.LastIndexByte(loc, '.'); i >= 0 {
		return extTech[loc[i:]]
	}
	return ""
}

// markAdapter labels a CALL node with a presence concept (for `match`-style
// rules that flag a dangerous USE rather than a taint flow — e.g. weak crypto).
func (spec adapterSpec) markAdapter() adapters.Adapter {
	return adapters.Adapter{
		Name: spec.Name + ".marks", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			// Marks flag a dangerous USE. Most are calls (weak-crypto getInstance,
			// md5_hex…), but some are bare member accesses with no call — e.g.
			// Solidity `tx.origin` used for authorization — so scan Attr nodes too.
			var out []adapters.Mapping
			// cross-language adapters (secretscan, …) label nodes in source files of
			// every language, so the per-language tech filter doesn't apply.
			crossLang := spec.crossLang
			for _, nodeType := range []string{"code.Call", "code.Attr", "code.Seq", "code.Subscript", "code.BinOp", "code.Unary"} {
				ids, _ := s.NodesOfType(nodeType)
				for _, id := range ids {
					n, _, _ := s.GetNode(id)
					if t := nodeTech(n.Prop("loc")); !crossLang && t != "" && t != spec.Technology {
						continue
					}
					path := n.Prop("callee_path")
					strArgs := n.Prop("str_args")
					seenConcept := map[string]bool{}
					for _, m := range spec.Marks {
						if seenConcept[m.Concept] {
							continue
						}
						if !matchSinkPath(path, m.Pattern) {
							continue
						}
						if !valConds(strArgs, m.ValMatches, m.ValAbsents) {
							continue
						}
						detail, conf := exploitDetail(m.Concept, m.Pattern)
						out = append(out, adapters.Mapping{NodeID: id, Concept: m.Concept, Confidence: conf, Detail: detail})
						seenConcept[m.Concept] = true
					}
				}
			}
			return out
		},
	}
}

// matchSinkPath matches a sink pattern against a callee path with dotted-segment
// boundaries: exact, as a prefix (method chains after), or as a SUFFIX / interior
// segment (namespace or receiver before it, e.g. pattern "Process.Start" matches
// "System.Diagnostics.Process.Start"). Boundary-aware so "File" ≠ "FileInputStream".
func matchSinkPath(path, p string) bool {
	return path == p ||
		strings.HasPrefix(path, p+".") || strings.HasPrefix(path, p+"[") ||
		strings.HasSuffix(path, "."+p) ||
		strings.Contains(path, "."+p+".") || strings.Contains(path, "."+p+"[")
}

// constraintAllows reports whether recvType is in a sink's `on` constraint (a
// single type or a comma-separated list from `on [a, b]`).
func constraintAllows(constraint, recvType string) bool {
	for _, t := range strings.Split(constraint, ",") {
		if t == recvType {
			return true
		}
	}
	return false
}

// matchPath reports whether a callee_path matches any of the patterns. Default
// mode "prefix" matches exact / dotted / subscript continuations; "contains"
// matches any substring (for languages whose receiver name varies, e.g. Go r/req).
func matchPath(path string, patterns []string, mode string) bool {
	for _, p := range patterns {
		if mode == "contains" {
			if strings.Contains(path, p) {
				return true
			}
			continue
		}
		if path == p || strings.HasPrefix(path, p+".") || strings.HasPrefix(path, p+"[") {
			return true
		}
	}
	return false
}

// Per-language adapter sets (loaded from vyql/adapters/*.vyql).
func ConfigAdapters() []adapters.Adapter     { return AdaptersFor("config") }
func SecretscanAdapters() []adapters.Adapter { return AdaptersFor("secretscan") }

// PiiAdapters is the cross-language PII taxonomy (adapters/pii.vyql). It labels nodes
// in every language, so it is applied once per scan rather than per present frontend.
func PiiAdapters() []adapters.Adapter        { return AdaptersFor("pii") }
func ElixirAdapters() []adapters.Adapter     { return AdaptersFor("elixir") }
func DartAdapters() []adapters.Adapter       { return AdaptersFor("dart") }
func GroovyAdapters() []adapters.Adapter     { return AdaptersFor("groovy") }
func PythonAdapters() []adapters.Adapter     { return AdaptersFor("python") }
func JsAdapters() []adapters.Adapter         { return AdaptersFor("javascript") }
func RubyAdapters() []adapters.Adapter       { return AdaptersFor("ruby") }
func GoAdapters() []adapters.Adapter         { return AdaptersFor("go") }
func JavaAdapters() []adapters.Adapter       { return AdaptersFor("java") }
func PHPAdapters() []adapters.Adapter        { return AdaptersFor("php") }
func CSharpAdapters() []adapters.Adapter     { return AdaptersFor("csharp") }
func CAdapters() []adapters.Adapter          { return AdaptersFor("c") }
func CPPAdapters() []adapters.Adapter        { return AdaptersFor("cpp") }
func RustAdapters() []adapters.Adapter       { return AdaptersFor("rust") }
func BashAdapters() []adapters.Adapter       { return AdaptersFor("bash") }
func ScalaAdapters() []adapters.Adapter      { return AdaptersFor("scala") }
func LuaAdapters() []adapters.Adapter        { return AdaptersFor("lua") }
func KotlinAdapters() []adapters.Adapter     { return AdaptersFor("kotlin") }
func PowerShellAdapters() []adapters.Adapter { return AdaptersFor("powershell") }
func SwiftAdapters() []adapters.Adapter      { return AdaptersFor("swift") }
func PerlAdapters() []adapters.Adapter       { return AdaptersFor("perl") }
func SolidityAdapters() []adapters.Adapter   { return AdaptersFor("solidity") }
func ObjCAdapters() []adapters.Adapter       { return AdaptersFor("objc") }

// containsStr reports whether xs contains v.
func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
