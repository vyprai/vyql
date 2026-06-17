// Package frontend turns extracted code.* graphs into concept labels using
// framework adapters (docs/07). The adapter CONTENT — which framework calls
// are inputs, sinks, controls, and which constructors yield which types — is
// VyQL, authored in vyql/adapters/<tech>.vyql and loaded at runtime. Only the
// matching engine and the language parsers are Go code.
package frontend

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/extract/sca"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/usg"
)

type inputSpec struct {
	Concept    string
	Paths      []string
	Methods    []string // receiver-agnostic: match the call's `method` prop (last segment)
	Match      string   // "prefix" (default) | "contains"
	Receiver   bool     // match a receiver attribute/method with a recv_type constraint
	Constraint string   // optional `on <type>` receiver-type constraint
	ValMatches []string // `val "substr"` (AND) — only a source when an arg literal matches (e.g. getenv("HTTP_*"))
	ValAbsents []string // `nval "substr"` (AND) — not a source if any arg literal contains a substr
	Packages   []string // inherited from `package "name" { ... }` — require matching import/SBOM package evidence
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
	Packages   []string // inherited from `package "name" { ... }` — require matching import/SBOM package evidence
	Collection bool     // also flag a Seq/collection-literal arg (e.g. ldap options {filter})
}

type controlSpec struct {
	Concept    string
	Pattern    string
	ByMethod   bool     // match the call's `method` prop (receiver-agnostic, e.g. .close())
	Exact      bool     // exact path match instead of segment-prefix path matching
	ValMatches []string // `val "substr"` (AND — marks AND controls)
	ValAbsents []string // `nval "substr"` (AND — marks AND controls)
	Packages   []string // inherited from `package "name" { ... }` — require matching import/SBOM package evidence
}

// activeSources, when non-nil, restricts which source concepts the input adapters
// emit — i.e. the active profile's trust boundary. nil = every source active.
var activeSources map[string]bool

// SetActiveSources sets the trust-boundary filter for source labelling (the
// active application profile's entry-point families). Pass nil to disable.
func SetActiveSources(s map[string]bool) { activeSources = s }

// ActiveSourcesKey returns a deterministic fingerprint of the active source set (the profile's
// trust boundary), for the incremental adapter-label cache: changing the profile changes which
// source labels adapters emit, so cached labels from one profile must not be reused under
// another. "*" means no filter (every source active).
func ActiveSourcesKey() string {
	if activeSources == nil {
		return "*"
	}
	keys := make([]string, 0, len(activeSources))
	for k, on := range activeSources {
		if on {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

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

var (
	conceptDetailOnce sync.Once
	conceptDetails    map[string]map[string]string
)

func exploitDetail(concept, pattern string) (map[string]string, string) {
	template := ontologyConceptDetails()[concept]
	if len(template) == 0 {
		return nil, ""
	}
	detail := make(map[string]string, len(template))
	for k, v := range template {
		detail[k] = strings.ReplaceAll(v, "{pattern}", pattern)
	}
	conf := ""
	if detail["exploit_confidence"] == "low" {
		conf = "low"
	}
	return detailWithPattern(detail, pattern), conf
}

func ontologyConceptDetails() map[string]map[string]string {
	conceptDetailOnce.Do(func() {
		conceptDetails = map[string]map[string]string{}
		files, err := filepath.Glob(filepath.Join(datadir.Root(), "ontology", "*.vyql"))
		if err != nil {
			panic("frontend: glob ontology/*.vyql: " + err.Error())
		}
		for _, file := range files {
			raw, err := os.ReadFile(file)
			if err != nil {
				panic("frontend: read " + file + ": " + err.Error())
			}
			decls, err := parser.Parse(string(raw))
			if err != nil {
				panic("frontend: parse " + file + ": " + err.Error())
			}
			for _, d := range decls {
				cd, ok := d.(*parser.ConceptDecl)
				if !ok {
					continue
				}
				detail := map[string]string{}
				for k, v := range cd.Fields {
					if !strings.HasPrefix(k, "exploit_") {
						continue
					}
					if s, ok := v.(string); ok && s != "" {
						detail[k] = s
					}
				}
				if len(detail) > 0 {
					conceptDetails[cd.QualifiedName()] = detail
				}
			}
		}
	})
	return conceptDetails
}

type filterSpec struct {
	Pattern  string
	ByMethod bool // match the bare method name (x.replace) vs the dotted path (re.sub)
	Global   bool // always-global replace (gsub/replaceAll/re.sub); else needs the /g flag
	Packages []string
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
	Packages   []string
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
	ParamSources  []string      // `source param -> X`: concepts to label parameter nodes with
}

// AdaptersFor loads the framework adapters for a technology from
// vyql/adapters/<tech>.vyql and builds the input + sink + control adapters.
func AdaptersFor(tech string) []adapters.Adapter {
	return adaptersFromSpec(loadSpec(tech))
}

// adaptersFromSpec turns a built adapterSpec into the concrete adapter set (one adapter
// per mapping kind present). Shared by AdaptersFor and the dynamic package loader.
func adaptersFromSpec(spec adapterSpec) []adapters.Adapter {
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
	if len(spec.ParamSources) > 0 {
		out = append(out, spec.paramSourceAdapter())
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
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			allowed := make([]bool, len(spec.Assumes))
			for i := range spec.Assumes {
				allowed[i] = packageAllowed(spec.Assumes[i].Packages, pkgs)
			}
			var out []adapters.Mapping
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if t := nodeTech(n.Prop("loc")); !spec.crossLang && t != "" && t != spec.Technology {
					continue
				}
				method, path := n.Prop("method"), n.Prop("callee_path")
				for ai, as := range spec.Assumes {
					if !allowed[ai] {
						continue
					}
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
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			allowed := make([]bool, len(spec.Filters))
			for i := range spec.Filters {
				allowed[i] = packageAllowed(spec.Filters[i].Packages, pkgs)
			}
			var out []adapters.Mapping
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if t := nodeTech(n.Prop("loc")); t != "" && t != spec.Technology {
					continue
				}
				method, path := n.Prop("method"), n.Prop("callee_path")
				matched, global := false, false
				for fi, f := range spec.Filters {
					if !allowed[fi] {
						continue
					}
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
	src := string(datadir.MustRead("adapters/" + tech + ".vyql"))
	if extra, err := datadir.Read("adapters/packages/" + tech + ".vyql"); err == nil {
		src += "\n" + string(extra)
	}
	decls, err := parser.Parse(src)
	if err != nil {
		panic("frontend: invalid adapters/" + tech + ".vyql: " + err.Error())
	}
	var merged *parser.AdapterDecl
	for _, d := range decls {
		a, ok := d.(*parser.AdapterDecl)
		if !ok || a.Name != tech {
			continue
		}
		if merged == nil {
			merged = &parser.AdapterDecl{Name: a.Name, Meta: a.Meta}
		} else {
			for k, v := range a.Meta {
				merged.Meta[k] = v
			}
		}
		merged.Mappings = append(merged.Mappings, a.Mappings...)
	}
	if merged != nil {
		return merged
	}
	panic("frontend: no adapter declaration in adapters/" + tech + ".vyql")
}

func loadSpec(tech string) adapterSpec {
	return specFromDecl(loadDecl(tech))
}

// specFromDecl builds an adapterSpec from an already-parsed adapter declaration.
// Split out of loadSpec so the dynamic per-package adapter loader (packages.go) can
// reuse the exact same mapping→spec lowering for the generated catalog.
func specFromDecl(d *parser.AdapterDecl) adapterSpec {
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
			if len(mp.ValMatches) > 0 || len(mp.ValAbsents) > 0 || len(mp.Packages) > 0 {
				s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, Match: matchMode,
					Paths: []string{mp.Pattern}, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
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
			if len(mp.ValMatches) > 0 || len(mp.ValAbsents) > 0 || len(mp.Packages) > 0 {
				s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, Match: matchMode,
					Methods: []string{mp.Pattern}, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
				break
			}
			i, ok := srcByConcept[mp.Concept]
			if !ok {
				s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, Match: matchMode})
				i = len(s.Inputs) - 1
				srcByConcept[mp.Concept] = i
			}
			s.Inputs[i].Methods = append(s.Inputs[i].Methods, mp.Pattern)
		case "source_param":
			s.ParamSources = append(s.ParamSources, mp.Concept)
		case "source_receiver":
			s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, Match: matchMode,
				Methods: []string{mp.Pattern}, Receiver: true, Constraint: mp.Constraint,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
		case "sink_method":
			s.Sinks = append(s.Sinks, sinkSpec{Concept: mp.Concept, Pattern: mp.Pattern, ByMethod: true, Constraint: mp.Constraint, ArgIndex: mp.ArgIndex, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages, Collection: mp.Collection})
		case "sink_path":
			s.Sinks = append(s.Sinks, sinkSpec{Concept: mp.Concept, Pattern: mp.Pattern, Constraint: mp.Constraint, ArgIndex: mp.ArgIndex, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages, Collection: mp.Collection})
		case "sink_receiver":
			// the tainted DATA is the receiver of a no-arg method (e.g. `URL(u).openConnection()`,
			// `u.toRegex()`); match the bare method name, label the call node itself.
			s.Sinks = append(s.Sinks, sinkSpec{Concept: mp.Concept, Pattern: mp.Pattern, ByMethod: true, Receiver: true, Constraint: mp.Constraint, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
		case "control":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, Pattern: mp.Pattern,
				ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
		case "control_method":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, Pattern: mp.Pattern,
				ByMethod: true, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
		case "mark":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, Pattern: mp.Pattern, Exact: mp.Exact, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
		case "mark_method":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, Pattern: mp.Pattern,
				ByMethod: true, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
		case "filter_method":
			s.Filters = append(s.Filters, filterSpec{Pattern: mp.Pattern, ByMethod: true, Global: mp.Constraint == "global", Packages: mp.Packages})
		case "filter_path":
			s.Filters = append(s.Filters, filterSpec{Pattern: mp.Pattern, Global: mp.Constraint == "global", Packages: mp.Packages})
		case "assume_guard_method", "assume_guard_path", "assume_sanitizer_method", "assume_sanitizer_path":
			mode := "guard"
			if strings.Contains(mp.Kind, "sanitizer") {
				mode = "sanitizer"
			}
			s.Assumes = append(s.Assumes, assumeSpec{Pattern: mp.Pattern, ByMethod: strings.HasSuffix(mp.Kind, "_method"),
				Mode: mode, About: mp.About, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents, Packages: mp.Packages})
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
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			inIdx := buildSpecIndex(len(spec.Inputs), func(i int) (methods, paths []string, loose bool) {
				return spec.Inputs[i].Methods, spec.Inputs[i].Paths, spec.Inputs[i].Match == "contains"
			})
			// package gating is node-independent (pkgs is constant for this Apply), so
			// resolve it once per spec instead of re-running the costly evidence match per node.
			allowed := make([]bool, len(spec.Inputs))
			for i := range spec.Inputs {
				allowed[i] = packageAllowed(spec.Inputs[i].Packages, pkgs)
			}
			var out []adapters.Mapping
			rangeNodes(s, func(n usg.Node) bool {
				path, method := n.Prop("callee_path"), n.Prop("method")
				if path == "" && method == "" {
					return true
				}
				if t := nodeTech(n.Prop("loc")); !spec.crossLang && t != "" && t != spec.Technology {
					return true // only label this language's nodes (cross-language adapters skip this)
				}
				for _, ci := range inIdx.candidates(method, path) {
					in := spec.Inputs[ci]
					if !allowed[ci] {
						continue
					}
					matched := (path != "" && matchPath(path, in.Paths, in.Match)) ||
						(method != "" && containsStr(in.Methods, method))
					if in.Receiver {
						matched = method != "" && containsStr(in.Methods, method) &&
							constraintAllows(in.Constraint, n.Prop("recv_type"))
					}
					if matched {
						// value-constrained source: only a source when an arg literal matches
						// (e.g. getenv("HTTP_X_FORWARDED_FOR") yes, getenv("PATH") no).
						if (len(in.ValMatches) > 0 || len(in.ValAbsents) > 0) &&
							!valConds(n.Prop("str_args"), in.ValMatches, in.ValAbsents) {
							continue
						}
						// trust-boundary gating: an active profile restricts which
						// source families count as attacker-controlled.
						if activeSources == nil || activeSources[in.Concept] {
							spec := 0
							if len(in.Packages) > 0 {
								spec = 3 // package-specific source supersedes native/general
							}
							out = append(out, adapters.Mapping{NodeID: n.ID, Concept: in.Concept, Specificity: spec})
						}
						break
					}
				}
				return true
			})
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
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			sinkIdx := buildSpecIndex(len(spec.Sinks), func(i int) (methods, paths []string, loose bool) {
				if spec.Sinks[i].ByMethod {
					return []string{spec.Sinks[i].Pattern}, nil, false
				}
				return nil, []string{spec.Sinks[i].Pattern}, false
			})
			allowed := make([]bool, len(spec.Sinks))
			for i := range spec.Sinks {
				allowed[i] = packageAllowed(spec.Sinks[i].Packages, pkgs)
			}
			var out []adapters.Mapping
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if t := nodeTech(n.Prop("loc")); t != "" && t != spec.Technology {
					continue // only label this language's nodes
				}
				isAttr := n.Type == "code.Attr"
				method, path, recvType := n.Prop("method"), n.Prop("callee_path"), n.Prop("recv_type")
				cand := sinkIdx.candidates(method, path)
				// Pick the MOST SPECIFIC matching sink (longest pattern) per concept, so
				// e.g. "re.compile" wins over "compile" for CodeEval/RegexCompile-style
				// overlaps, while one call can still carry genuinely distinct concepts
				// such as FilePathAccess and UnsafeUpload.
				bestByConcept := map[string]int{}
				strArgs := n.Prop("str_args")
				for _, i := range cand {
					sk := spec.Sinks[i]
					if !allowed[i] {
						continue
					}
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
					// specific than the plain exec.Command arg0 form). Keyed by (concept,
					// ARG INDEX): the same concept can be injectable at MULTIPLE arg
					// positions of one call (e.g. execFile(shell, [tainted args]) — arg0 the
					// binary AND arg1 the args array), so those must not collapse together.
					bkey := sk.Concept + "\x00" + strconv.Itoa(sk.ArgIndex)
					if curIdx, ok := bestByConcept[bkey]; !ok {
						bestByConcept[bkey] = i
					} else if cur := spec.Sinks[curIdx]; len(sk.Pattern) > len(cur.Pattern) ||
						(len(sk.Pattern) == len(cur.Pattern) && len(sk.ValMatches) > len(cur.ValMatches)) {
						bestByConcept[bkey] = i
					}
				}
				for _, i := range cand {
					sk := spec.Sinks[i]
					best, ok := bestByConcept[sk.Concept+"\x00"+strconv.Itoa(sk.ArgIndex)]
					if !ok || best != i {
						continue
					}
					// tiering: a package-gated sink is the most specific match (tier 3) and
					// supersedes native path (resolved) and general method (syntactic) matches.
					pkgSpec := 0
					if len(sk.Packages) > 0 {
						pkgSpec = 3
					}
					if isAttr {
						if sk.ByMethod {
							detail, conf := exploitDetail(sk.Concept, sk.Pattern)
							out = append(out, adapters.Mapping{NodeID: id, Concept: sk.Concept, Fidelity: "syntactic", Confidence: conf, Specificity: pkgSpec, Detail: detail})
						} else {
							detail, conf := exploitDetail(sk.Concept, sk.Pattern)
							out = append(out, adapters.Mapping{NodeID: id, Concept: sk.Concept, Fidelity: "resolved", Confidence: conf, Specificity: pkgSpec, Detail: detail})
						}
						continue
					}
					// receiver-sink: the tainted data is the receiver; the call node
					// carries that taint, so label the node itself rather than an arg.
					if sk.Receiver {
						detail, conf := exploitDetail(sk.Concept, sk.Pattern)
						out = append(out, adapters.Mapping{NodeID: id, Concept: sk.Concept, Fidelity: "syntactic", Confidence: conf, Specificity: pkgSpec, Detail: detail})
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
							out = append(out, adapters.Mapping{NodeID: arg, Concept: sk.Concept, Fidelity: fidelity, Confidence: conf, Specificity: pkgSpec, Detail: detail})
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
					out = append(out, adapters.Mapping{NodeID: arg, Concept: sk.Concept, Fidelity: fidelity, Confidence: conf, Specificity: pkgSpec, Detail: detail})
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
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			ctrlIdx := buildSpecIndex(len(spec.Controls), func(i int) (methods, paths []string, loose bool) {
				if spec.Controls[i].ByMethod {
					return []string{spec.Controls[i].Pattern}, nil, false
				}
				return nil, []string{spec.Controls[i].Pattern}, false
			})
			allowed := make([]bool, len(spec.Controls))
			for i := range spec.Controls {
				allowed[i] = packageAllowed(spec.Controls[i].Packages, pkgs)
			}
			var out []adapters.Mapping
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if t := nodeTech(n.Prop("loc")); t != "" && t != spec.Technology {
					continue // only label this language's nodes
				}
				path, method := n.Prop("callee_path"), n.Prop("method")
				strArgs := n.Prop("str_args")
				for _, ci := range ctrlIdx.candidates(method, path) {
					c := spec.Controls[ci]
					if !allowed[ci] {
						continue
					}
					// no break: a single call can be MULTIPLE controls (e.g. numeric coercion
					// neutralizes HTML, SQL, AND trust-boundary), so attach every match.
					hit := c.ByMethod && method == c.Pattern || !c.ByMethod && matchPath(path, []string{c.Pattern}, "prefix")
					if hit && valConds(strArgs, c.ValMatches, c.ValAbsents) {
						spec := 0
						if len(c.Packages) > 0 {
							spec = 3 // package-specific control supersedes native/general
						}
						out = append(out, adapters.Mapping{NodeID: id, Concept: c.Concept, Specificity: spec})
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
	".xml": "config", ".plist": "config", ".jelly": "config", ".jsp": "config", ".tag": "config",
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

// rangeNodes streams every node to fn via the store's RangeNodes fast path (no full []Node copy)
// when available, else falls back to AllNodes. Adapter passes iterate every node once; the slice
// copy was a multi-GB transient on large graphs.
func rangeNodes(s usg.Store, fn func(usg.Node) bool) {
	if rs, ok := s.(interface{ RangeNodes(func(usg.Node) bool) }); ok {
		rs.RangeNodes(fn)
		return
	}
	nodes, _ := s.AllNodes()
	for _, n := range nodes {
		if !fn(n) {
			return
		}
	}
}

func packageEvidence(s usg.Store, tech string, crossLang bool) map[string]bool {
	out := map[string]bool{}
	add := func(v string) {
		v = sca.NormalizePackageName(v)
		if v == "" {
			return
		}
		out[v] = true
		if root := sca.PackageRoot(v); root != "" {
			out[root] = true
		}
		// expand import→distribution aliases (e.g. `import yaml` ⇒ pyyaml) so package-gated
		// adapters keyed by the distribution name activate from imports, not just manifests.
		for _, a := range sca.ImportAliases(v) {
			out[a] = true
		}
	}
	// only import/SBOM nodes carry package evidence — use the type index (O(result)) instead of
	// scanning every node, since this runs once per adapter spec.
	impIDs, _ := s.NodesOfType("code.Import")
	for _, id := range impIDs {
		n, ok, _ := s.GetNode(id)
		if !ok {
			continue
		}
		if !crossLang {
			if t := nodeTech(n.Prop("loc")); t != "" && t != tech {
				continue
			}
		}
		add(n.Prop("module"))
		add(n.Prop("symbol"))
		add(n.Prop("package"))
		add(n.Prop("root"))
	}
	sbomIDs, _ := s.NodesOfType("sbom.PackageVersion")
	for _, id := range sbomIDs {
		if n, ok, _ := s.GetNode(id); ok {
			add(n.Prop("name"))
		}
	}
	return out
}

func packageAllowed(want []string, have map[string]bool) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		if packageInEvidence(w, have) {
			return true
		}
	}
	return false
}

func packageInEvidence(want string, have map[string]bool) bool {
	want = sca.NormalizePackageName(want)
	if want == "" {
		return true
	}
	if have[want] {
		return true
	}
	if root := sca.PackageRoot(want); root != "" && have[root] {
		return true
	}
	for got := range have {
		if sca.PackageMatches(got, want) {
			return true
		}
	}
	return false
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
			pkgs := packageEvidence(s, spec.Technology, crossLang)
			markIdx := buildSpecIndex(len(spec.Marks), func(i int) (methods, paths []string, loose bool) {
				if spec.Marks[i].ByMethod {
					return []string{spec.Marks[i].Pattern}, nil, false
				}
				return nil, []string{spec.Marks[i].Pattern}, false
			})
			allowed := make([]bool, len(spec.Marks))
			for i := range spec.Marks {
				allowed[i] = packageAllowed(spec.Marks[i].Packages, pkgs)
			}
			for _, nodeType := range []string{"code.Call", "code.Attr", "code.Seq", "code.Subscript", "code.BinOp", "code.Unary"} {
				ids, _ := s.NodesOfType(nodeType)
				for _, id := range ids {
					n, _, _ := s.GetNode(id)
					if t := nodeTech(n.Prop("loc")); !crossLang && t != "" && t != spec.Technology {
						continue
					}
					path := n.Prop("callee_path")
					method := n.Prop("method")
					strArgs := n.Prop("str_args")
					seenConcept := map[string]bool{}
					for _, mi := range markIdx.candidates(method, path) {
						m := spec.Marks[mi]
						if !allowed[mi] {
							continue
						}
						if seenConcept[m.Concept] {
							continue
						}
						hit := m.ByMethod && method == m.Pattern ||
							!m.ByMethod && ((m.Exact && path == m.Pattern) || (!m.Exact && matchSinkPath(path, m.Pattern)))
						if !hit {
							continue
						}
						if !valConds(strArgs, m.ValMatches, m.ValAbsents) {
							continue
						}
						detail, conf := exploitDetail(m.Concept, m.Pattern)
						spec := 0
						if len(m.Packages) > 0 {
							spec = 3 // package-specific mark supersedes native/general
						}
						out = append(out, adapters.Mapping{NodeID: id, Concept: m.Concept, Confidence: conf, Specificity: spec, Detail: detail})
						seenConcept[m.Concept] = true
					}
				}
			}
			return out
		},
	}
}

// --- adapter spec indexing -------------------------------------------------
//
// Adapter matching is a search problem: for each graph node, find the specs whose
// pattern matches its method/callee_path. Done naively that is O(nodes × specs) —
// the dominant scan cost on large repos. Every matcher here (method exact, path
// prefix/suffix/segment) shares one invariant: a matching spec's pattern FIRST
// SEGMENT must appear as a dotted segment of the node path, OR the spec is a
// by-method spec whose name equals the node method. So we index specs by those
// keys once per Apply and, per node, consult only the candidate specs. Patterns
// that need unanchored substring matching (`contains` mode) can't be indexed and
// go into `loose`, always considered. Restricting the precise match loop to
// candidates is exactly equivalent to the full scan: a non-candidate spec always
// fails the precise check, so it could never have produced a mapping.

// firstSeg returns the leading dotted/bracket segment of a pattern or path
// ("requests.get" → "requests", "exec" → "exec").
func firstSeg(p string) string {
	if i := strings.IndexAny(p, ".["); i >= 0 {
		return p[:i]
	}
	return p
}

// specIndex maps node method names and path segments to candidate spec indices.
// visited/gen provide allocation-free dedup across the per-node candidate lookups
// (a generation stamp per spec instead of a fresh map each call); buf is the reused
// output. Not safe for concurrent use — adapters apply sequentially.
type specIndex struct {
	byMethod map[string][]int
	bySeg    map[string][]int
	loose    []int
	visited  []int32
	gen      int32
	buf      []int
}

// buildSpecIndex indexes n specs. keysOf reports, for spec i, its by-method keys
// (exact method names), its path patterns (indexed by first segment), and whether
// it needs unanchored matching (loose → always a candidate).
func buildSpecIndex(n int, keysOf func(i int) (methods, paths []string, loose bool)) *specIndex {
	idx := &specIndex{byMethod: map[string][]int{}, bySeg: map[string][]int{}, visited: make([]int32, n)}
	for i := 0; i < n; i++ {
		methods, paths, loose := keysOf(i)
		if loose {
			idx.loose = append(idx.loose, i)
			continue
		}
		for _, m := range methods {
			idx.byMethod[m] = append(idx.byMethod[m], i)
		}
		for _, p := range paths {
			idx.bySeg[firstSeg(p)] = append(idx.bySeg[firstSeg(p)], i)
		}
	}
	return idx
}

// candidates returns the sorted spec indices that could match a node with the
// given method/path (a superset filter; the caller still runs the precise check).
// The returned slice is reused on the next call — consume it before calling again.
func (idx *specIndex) candidates(method, path string) []int {
	idx.gen++
	g := idx.gen
	out := idx.buf[:0]
	add := func(is []int) {
		for _, i := range is {
			if idx.visited[i] != g {
				idx.visited[i] = g
				out = append(out, i)
			}
		}
	}
	if method != "" {
		add(idx.byMethod[method])
	}
	// walk path segments without allocating (substring map lookups don't copy).
	if path != "" && len(idx.bySeg) > 0 {
		start := 0
		for i := 0; i <= len(path); i++ {
			if i == len(path) || path[i] == '.' || path[i] == '[' || path[i] == ']' {
				if i > start {
					add(idx.bySeg[path[start:i]])
				}
				start = i + 1
			}
		}
	}
	add(idx.loose)
	sort.Ints(out)
	idx.buf = out
	return out
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
		t = strings.TrimSpace(t)
		recvType = strings.TrimSpace(recvType)
		if t == recvType ||
			strings.HasSuffix(t, "."+recvType) ||
			strings.HasSuffix(recvType, "."+t) ||
			strings.HasSuffix(t, "::"+recvType) ||
			strings.HasSuffix(recvType, "::"+t) {
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

// AutoAdapters returns adapter declarations that opt into whole-graph application through
// `meta { auto_apply: graph }`.
func AutoAdapters() []adapters.Adapter {
	files, err := filepath.Glob(filepath.Join(datadir.Root(), "adapters", "*.vyql"))
	if err != nil {
		panic("frontend: glob adapters/*.vyql: " + err.Error())
	}
	sort.Strings(files)
	var out []adapters.Adapter
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			panic("frontend: read " + file + ": " + err.Error())
		}
		decls, err := parser.Parse(string(raw))
		if err != nil {
			panic("frontend: parse " + file + ": " + err.Error())
		}
		for _, d := range decls {
			ad, ok := d.(*parser.AdapterDecl)
			if !ok {
				continue
			}
			if mode, _ := ad.Meta["auto_apply"].(string); mode == "graph" {
				out = append(out, adaptersFromSpec(specFromDecl(ad))...)
			}
		}
	}
	return out
}

// paramSourceAdapter labels function/method parameter nodes with the spec's
// `source param -> X` concept(s) — the library/SDK trust boundary (any caller may pass
// attacker data through a public API). The KNOWLEDGE (which concept) is the .vyql line;
// this is only the mechanism.
//
// Default-OFF, opt-in: unlike the pattern source adapter (where activeSources==nil means
// "no profile → every source on"), a parameter source fires ONLY when a profile is set AND
// explicitly lists the concept (i.e. the library profile). So application profiles, and the
// no-profile default, never taint parameters. Low confidence (syntactic): a finding
// surfaces only if a param actually reaches a sink.
func (spec adapterSpec) paramSourceAdapter() adapters.Adapter {
	concepts := spec.ParamSources
	return adapters.Adapter{
		Name: spec.Name + ".param-source", Technology: spec.Technology, Specificity: 0,
		Fidelity: "syntactic", Origin: "human",
		Apply: func(s usg.Store) []adapters.Mapping {
			if activeSources == nil {
				return nil // no trust boundary set → parameters are not sources
			}
			active := make([]string, 0, len(concepts))
			for _, c := range concepts {
				if activeSources[c] {
					active = append(active, c)
				}
			}
			if len(active) == 0 {
				return nil
			}
			ids, _ := s.NodesOfType("code.Param")
			out := make([]adapters.Mapping, 0, len(active))
			for _, id := range ids {
				n, ok, _ := s.GetNode(id)
				if !ok || n.Prop("exported") != "true" {
					continue // only PUBLIC-API params are entry points; internal helpers are
					// reached by ordinary interprocedural propagation (precision).
				}
				for _, c := range active {
					out = append(out, adapters.Mapping{NodeID: id, Concept: c, Specificity: 0})
				}
			}
			return out
		},
	}
}

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
