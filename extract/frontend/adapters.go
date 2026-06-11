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
	Concept string
	Paths   []string
	Match   string // "prefix" (default) | "contains"
}

type sinkSpec struct {
	Concept    string
	Pattern    string
	ByMethod   bool   // match the bare method name vs the dotted callee path
	Receiver   bool   // tainted data is the RECEIVER, not an arg — label the call node
	Constraint string // optional `on <type>` receiver-type constraint
	ArgIndex   int    // which argument is the dangerous one (default 0)
	ValMatches []string // `val "substr"` (AND) — every substr must be in some arg/option literal
	ValAbsents []string // `nval "substr"` (AND) — no arg/option literal may contain any substr
}

type controlSpec struct {
	Concept    string
	Pattern    string
	ValMatches []string // `val "substr"` (AND, marks)
	ValAbsents []string // `nval "substr"` (AND, marks)
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

type adapterSpec struct {
	Name          string
	Technology    string
	containsMatch bool
	Inputs        []inputSpec
	Sinks         []sinkSpec
	Controls      []controlSpec
	Marks         []controlSpec // presence markers (label the call node with a concept)
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
	return out
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
	matchMode := "prefix"
	if s.containsMatch {
		matchMode = "contains"
	}
	srcByConcept := map[string]int{}
	for _, mp := range d.Mappings {
		switch mp.Kind {
		case "source":
			i, ok := srcByConcept[mp.Concept]
			if !ok {
				s.Inputs = append(s.Inputs, inputSpec{Concept: mp.Concept, Match: matchMode})
				i = len(s.Inputs) - 1
				srcByConcept[mp.Concept] = i
			}
			s.Inputs[i].Paths = append(s.Inputs[i].Paths, mp.Pattern)
		case "sink_method":
			s.Sinks = append(s.Sinks, sinkSpec{Concept: mp.Concept, Pattern: mp.Pattern, ByMethod: true, Constraint: mp.Constraint, ArgIndex: mp.ArgIndex, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents})
		case "sink_path":
			s.Sinks = append(s.Sinks, sinkSpec{Concept: mp.Concept, Pattern: mp.Pattern, Constraint: mp.Constraint, ArgIndex: mp.ArgIndex, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents})
		case "sink_receiver":
			// the tainted DATA is the receiver of a no-arg method (e.g. `URL(u).openConnection()`,
			// `u.toRegex()`); match the bare method name, label the call node itself.
			s.Sinks = append(s.Sinks, sinkSpec{Concept: mp.Concept, Pattern: mp.Pattern, ByMethod: true, Receiver: true, Constraint: mp.Constraint, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents})
		case "control":
			s.Controls = append(s.Controls, controlSpec{Concept: mp.Concept, Pattern: mp.Pattern})
		case "mark":
			s.Marks = append(s.Marks, controlSpec{Concept: mp.Concept, Pattern: mp.Pattern, ValMatches: mp.ValMatches, ValAbsents: mp.ValAbsents})
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
				path := n.Prop("callee_path")
				if path == "" {
					continue
				}
				if t := nodeTech(n.Prop("loc")); t != "" && t != spec.Technology {
					continue // only label this language's nodes
				}
				for _, in := range spec.Inputs {
					if matchPath(path, in.Paths, in.Match) {
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
			var out []adapters.Mapping
			for _, id := range ids {
				n, _, _ := s.GetNode(id)
				if t := nodeTech(n.Prop("loc")); t != "" && t != spec.Technology {
					continue // only label this language's nodes
				}
				method, path, recvType := n.Prop("method"), n.Prop("callee_path"), n.Prop("recv_type")
				// Pick the MOST SPECIFIC matching sink (longest pattern) so e.g.
				// "re.compile" (RegexCompile) wins over "compile" (CodeEval) and a
				// node gets exactly one sink concept.
				best := -1
				strArgs := n.Prop("str_args")
				for i, sk := range spec.Sinks {
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
					if best < 0 || len(sk.Pattern) > len(spec.Sinks[best].Pattern) {
						best = i
					}
				}
				if best >= 0 {
					sk := spec.Sinks[best]
					// receiver-sink: the tainted data is the receiver; the call node
					// carries that taint, so label the node itself rather than an arg.
					if sk.Receiver {
						out = append(out, adapters.Mapping{NodeID: id, Concept: sk.Concept, Fidelity: "syntactic"})
						continue
					}
					arg := n.Prop("arg" + strconv.Itoa(sk.ArgIndex))
					if arg == "" {
						continue
					}
					if a, ok, _ := s.GetNode(arg); ok && a.Prop("vkind") == "Seq" {
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
					out = append(out, adapters.Mapping{NodeID: arg, Concept: sk.Concept, Fidelity: fidelity})
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
				path := n.Prop("callee_path")
				for _, c := range spec.Controls {
					if matchPath(path, []string{c.Pattern}, "prefix") {
						out = append(out, adapters.Mapping{NodeID: id, Concept: c.Concept})
						break
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
			for _, nodeType := range []string{"code.Call", "code.Attr"} {
				ids, _ := s.NodesOfType(nodeType)
				for _, id := range ids {
					n, _, _ := s.GetNode(id)
					if t := nodeTech(n.Prop("loc")); t != "" && t != spec.Technology {
						continue
					}
					path := n.Prop("callee_path")
					strArgs := n.Prop("str_args")
					for _, m := range spec.Marks {
						if !matchSinkPath(path, m.Pattern) {
							continue
						}
						if !valConds(strArgs, m.ValMatches, m.ValAbsents) {
							continue
						}
						out = append(out, adapters.Mapping{NodeID: id, Concept: m.Concept})
						break
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
func PythonAdapters() []adapters.Adapter { return AdaptersFor("python") }
func JsAdapters() []adapters.Adapter     { return AdaptersFor("javascript") }
func RubyAdapters() []adapters.Adapter   { return AdaptersFor("ruby") }
func GoAdapters() []adapters.Adapter     { return AdaptersFor("go") }
func JavaAdapters() []adapters.Adapter   { return AdaptersFor("java") }
func PHPAdapters() []adapters.Adapter    { return AdaptersFor("php") }
func CSharpAdapters() []adapters.Adapter { return AdaptersFor("csharp") }
func CAdapters() []adapters.Adapter      { return AdaptersFor("c") }
func CPPAdapters() []adapters.Adapter    { return AdaptersFor("cpp") }
func RustAdapters() []adapters.Adapter   { return AdaptersFor("rust") }
func BashAdapters() []adapters.Adapter   { return AdaptersFor("bash") }
func ScalaAdapters() []adapters.Adapter  { return AdaptersFor("scala") }
func LuaAdapters() []adapters.Adapter    { return AdaptersFor("lua") }
func KotlinAdapters() []adapters.Adapter { return AdaptersFor("kotlin") }
func PowerShellAdapters() []adapters.Adapter { return AdaptersFor("powershell") }
func SwiftAdapters() []adapters.Adapter  { return AdaptersFor("swift") }
func PerlAdapters() []adapters.Adapter    { return AdaptersFor("perl") }
func SolidityAdapters() []adapters.Adapter { return AdaptersFor("solidity") }
func ObjCAdapters() []adapters.Adapter    { return AdaptersFor("objc") }
