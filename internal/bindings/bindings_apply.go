// The applicator families. One constructor per action kind -- source, sink, check, presence,
// filter, advisory neutralizer -- plus the confidence a mapping carries.

package bindings

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/ontology"
	"github.com/vyprai/vyql/internal/resultpolicy"
	"github.com/vyprai/vyql/internal/usg"
)

func BindingsFor(tech string) []Applicator {
	out := bindingApplicatorsFromSpec(filterBindingSpecForActiveConcepts(loadSpec(tech)))
	if tech == "javascript" {
		out = append(out, jsDomValueInputApplicator())
		out = append(out, jsPathRegexGuardApplicator())
		out = append(out, jsSafePathResolverApplicator())
		out = append(out, jsModuleHelperLdapEscapeApplicator())
	}
	if tech == "ruby" {
		out = append(out, processArgVectorApplicator(tech))
	}
	return out
}

// OverlayBindings loads repo-local binding overlays from root. Files may live
// directly under root or under root/bindings. The overlay is intentionally
// explicit and opt-in; parse errors are returned so a bad generated file does
// not silently change scan behavior.

func OverlayBindings(root string, techs []string) ([]Applicator, error) {
	if strings.TrimSpace(root) == "" {
		return nil, nil
	}
	allowed := map[string]bool{}
	for _, tech := range techs {
		allowed[tech] = true
	}
	var files []string
	for _, dir := range []string{root, filepath.Join(root, "bindings")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".vyql") {
				continue
			}
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files)
	var out []Applicator
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		sets, err := compileV2BindingSources([]datadir.Source{{
			Name: filepath.ToSlash(file),
			Data: b,
		}})
		if err != nil {
			return nil, err
		}
		for _, ad := range sets {
			if len(allowed) > 0 && !allowed[ad.Name] {
				return nil, fmt.Errorf("overlay binding %s declares %q, which is not present in this scan", file, ad.Name)
			}
			spec := filterBindingSpecForActiveConcepts(specFromBindingSet(ad))
			spec.Name = "overlay." + spec.Name
			out = append(out, bindingApplicatorsFromSpec(spec)...)
		}
	}
	return out, nil
}

// bindingApplicatorsFromSpec turns a compiled binding spec into concrete
// graph-labeling applicators, one per action family present. Shared by
// BindingsFor and the dynamic package loader.

func (spec bindingSpec) advisoryNeutralizerApplicator() Applicator {
	concept := ontology.InternalNeutralizerAssumptionConcept
	return Applicator{
		Name: spec.Name + ".assumptions", Technology: spec.Technology, Specificity: 2,
		Fidelity: "syntactic", Origin: "human",
		Apply: func(s usg.Store) []Mapping {
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			effects := make([]requirementEffect, len(spec.AdvisoryNeutralizers))
			valMatchesLower := make([][]string, len(spec.AdvisoryNeutralizers))
			valAbsentsLower := make([][]string, len(spec.AdvisoryNeutralizers))
			for i := range spec.AdvisoryNeutralizers {
				effects[i] = reqGate.effect(spec.AdvisoryNeutralizers[i].Packages, spec.AdvisoryNeutralizers[i].Requirement)
				valMatchesLower[i] = lowerStrings(spec.AdvisoryNeutralizers[i].ValMatches)
				valAbsentsLower[i] = lowerStrings(spec.AdvisoryNeutralizers[i].ValAbsents)
			}
			var out []Mapping
			valCache := newValueTokenCache(s)
			scopeIdx := sharedFlagIndex(s)
			scopeIdx.rangeTechNodes(s, spec.Technology, spec.crossLang, func(n usg.Node) bool {
				id := n.ID
				method, path := n.Prop("method"), n.Prop("callee_path")
				for ai, as := range spec.AdvisoryNeutralizers {
					if !effects[ai].Allowed {
						continue
					}
					if !(as.ByMethod && method == as.Pattern || !as.ByMethod && matchSinkPath(path, as.Pattern)) {
						continue
					}
					if !callArgCountMatches(n, as.ArgCountSet, as.ArgCountMin, as.ArgCountMax) {
						continue
					}
					if !valCondsDirectForNodeCached(valCache, n, valMatchesLower[ai], valAbsentsLower[ai]) {
						continue
					}
					if !scopePredicatesMatch(s, scopeIdx, as.ScopePreds, n, spec.Technology, spec.crossLang) {
						continue
					}
					detail := cloneStringMap(as.Detail)
					if detail == nil {
						detail = map[string]string{}
					}
					detail["mode"] = as.Mode
					detail["about"] = as.About
					detail["pattern"] = as.Pattern
					conf, detail := effects[ai].apply(mappingConfidence(as.Confidence, ""), detail)
					out = append(out, Mapping{NodeID: id, Concept: concept,
						Fidelity: mappingFidelity(as.Fidelity, "syntactic"), Confidence: conf, Detail: detail})
					break
				}
				return true
			}, "code.Call")
			return out
		},
	}
}

// filterApplicator labels character-filtering replace(pattern, repl) calls with the
// ontology role concept, recording the proven OUTPUT alphabet (or that it is unbounded)
// in the label Detail. The solver then treats it as a SOUND sanitizer for any sink whose
// excluded chars the alphabet excludes, and the engine surfaces an unproven filter
// as an advisory note. The regex math is general (charfilter.go); WHICH methods
// filter is data (the `filter` directive).

func (spec bindingSpec) filterApplicator() Applicator {
	concept := singleOntologyRoleConcept(ontology.InternalConceptRoleCharFilter)
	return Applicator{
		Name: spec.Name + ".filters", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []Mapping {
			if concept == "" {
				return nil
			}
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			allowed := make([]bool, len(spec.Filters))
			for i := range spec.Filters {
				allowed[i] = reqGate.allowed(spec.Filters[i].Packages, spec.Filters[i].Requirement)
			}
			var out []Mapping
			sharedFlagIndex(s).rangeTechNodes(s, spec.Technology, false, func(n usg.Node) bool {
				id := n.ID
				method, path := n.Prop("method"), n.Prop("callee_path")
				matched, global := false, false
				for fi, f := range spec.Filters {
					if !allowed[fi] {
						continue
					}
					if (f.ByMethod && method == f.Pattern || !f.ByMethod && matchSinkPath(path, f.Pattern)) &&
						callArgCountMatches(n, f.ArgCountSet, f.ArgCountMin, f.ArgCountMax) {
						matched, global = true, f.Global
						break
					}
				}
				if !matched {
					return true
				}
				pattern, repl := n.Prop("lit0"), n.Prop("lit1")
				alphabet, bounded, removed := replaceCharEffects(pattern, repl, global)
				detail := map[string]string{"bounded": "false", "pattern": pattern}
				if bounded {
					detail["bounded"] = "true"
					detail["alphabet"] = alphabet
				}
				if removed != "" {
					detail["removed"] = removed
				}
				out = append(out, Mapping{NodeID: id, Concept: concept, Detail: detail})
				return true
			}, "code.Call")
			return out
		},
	}
}

// CtorTypesFor returns the constructor-to-type table declared by v2 bindings,
// used by lowering to stamp recv_type.

func CtorTypesFor(tech string) map[string]string {
	out := map[string]string{}
	for _, mp := range loadBindingSet(tech).Mappings {
		if mp.Kind == "type" {
			out[mp.Pattern] = mp.Concept
		}
	}
	return out
}

func (spec bindingSpec) sourceApplicator() Applicator {
	fidelity := "resolved"
	if spec.containsMatch {
		fidelity = "syntactic"
	}
	return Applicator{
		Name: spec.Name + ".input", Technology: spec.Technology, Specificity: 2,
		Fidelity: fidelity, Origin: "human",
		Apply: func(s usg.Store) []Mapping {
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			inIdx := buildSpecIndex(len(spec.Inputs), func(i int) (methods, paths []string, loose bool) {
				if spec.Inputs[i].NodeType != "" && len(spec.Inputs[i].Methods) == 0 && len(spec.Inputs[i].Paths) == 0 {
					return nil, nil, true
				}
				return spec.Inputs[i].Methods, spec.Inputs[i].Paths, spec.Inputs[i].Match == "contains"
			})
			// package gating is node-independent (pkgs is constant for this Apply), so
			// resolve it once per spec instead of re-running the costly evidence match per node.
			effects := make([]requirementEffect, len(spec.Inputs))
			valMatchesLower := make([][]string, len(spec.Inputs))
			valAbsentsLower := make([][]string, len(spec.Inputs))
			for i := range spec.Inputs {
				effects[i] = reqGate.effect(spec.Inputs[i].Packages, spec.Inputs[i].Requirement)
				valMatchesLower[i] = lowerStrings(spec.Inputs[i].ValMatches)
				valAbsentsLower[i] = lowerStrings(spec.Inputs[i].ValAbsents)
			}
			var out []Mapping
			valCache := newValueTokenCache(s)
			needsScope := inputSpecsNeedScope(spec.Inputs)
			var scopeIdx *flagMatchIndex
			if needsScope {
				scopeIdx = sharedFlagIndex(s)
			}
			rangeInputs := func(fn func(usg.Node) bool) {
				if needsScope {
					scopeIdx.rangeTechNodes(s, spec.Technology, spec.crossLang, fn, inputApplicatorNodeTypes(spec.Technology, spec.Inputs)...)
					return
				}
				rangeTechNodesDirect(s, spec.Technology, spec.crossLang, fn, inputApplicatorNodeTypes(spec.Technology, spec.Inputs)...)
			}
			rangeInputs(func(n usg.Node) bool {
				path, method := n.Prop("callee_path"), n.Prop("method")
				if path == "" && method == "" && len(inIdx.loose) == 0 {
					return true
				}
				for _, ci := range inIdx.candidates(method, path) {
					in := spec.Inputs[ci]
					if !nodeTypeAllowed(in.NodeType, n.Type) {
						continue
					}
					if !effects[ci].Allowed {
						continue
					}
					matched := (path != "" && matchPath(path, in.Paths, in.Match)) ||
						(method != "" && containsStr(in.Methods, method)) ||
						(in.NodeType != "" && len(in.Paths) == 0 && len(in.Methods) == 0)
					if in.Receiver {
						matched = method != "" && containsStr(in.Methods, method) &&
							constraintAllows(in.Constraint, n.Prop("recv_type"))
					}
					if matched {
						if !callArgCountMatches(n, in.ArgCountSet, in.ArgCountMin, in.ArgCountMax) {
							continue
						}
						// value-constrained source: only a source when configured literal
						// tokens are present or absent as declared by the binding.
						if (len(in.ValMatches) > 0 || len(in.ValAbsents) > 0) &&
							!valCondsDirectForNodeCached(valCache, n, valMatchesLower[ci], valAbsentsLower[ci]) {
							continue
						}
						if len(in.ScopePreds) > 0 && !scopePredicatesMatch(s, scopeIdx, in.ScopePreds, n, spec.Technology, spec.crossLang) {
							continue
						}
						// active-profile gating: a profile restricts which
						// source families are active for this profile.
						if activeSources == nil || activeSources[in.Concept] {
							spec := 0
							if len(in.Packages) > 0 {
								spec = 3 // package-specific source supersedes native/general
							}
							conf, detail := effects[ci].apply(mappingConfidence(in.Confidence, ""), nil)
							out = append(out, Mapping{NodeID: n.ID, Concept: in.Concept, Fidelity: mappingFidelity(in.Fidelity, fidelity), Confidence: conf, Specificity: spec, Detail: detail})
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

func inputApplicatorNodeTypes(_ string, inputs []inputSpec) []string {
	seen := map[string]bool{"code.Call": true}
	out := append([]string{}, callablePropTypes...)
	for _, typ := range out {
		seen[typ] = true
	}
	for _, in := range inputs {
		if in.NodeType != "" && !seen[in.NodeType] {
			seen[in.NodeType] = true
			out = append(out, in.NodeType)
		}
	}
	return out
}

// sinkApplicator labels arg0 of matching calls with a PER-MAPPING fidelity:
//   - dotted-path match           → resolved (high)
//   - bare-method match, no `on`  → syntactic (medium — receiver type unknown)
//   - method match with `on T`:
//     recv_type == T              → resolved (high, type-verified)
//     recv_type unknown           → syntactic (medium, can't disprove)
//     recv_type != T              → SKIP (known wrong type — not a sink here)
//
// Collection-literal arg0s (vkind == Seq) are skipped.

func (spec bindingSpec) sinkApplicator() Applicator {
	attributeSinks := ontologyRoleConcepts(ontology.InternalConceptRoleAttributeSink)
	return Applicator{
		Name: spec.Name + ".sinks", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []Mapping {
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			sinkIdx := buildSpecIndex(len(spec.Sinks), func(i int) (methods, paths []string, loose bool) {
				if spec.Sinks[i].ByMethod {
					return []string{spec.Sinks[i].Pattern}, nil, false
				}
				return nil, []string{spec.Sinks[i].Pattern}, false
			})
			effects := make([]requirementEffect, len(spec.Sinks))
			valMatchesLower := make([][]string, len(spec.Sinks))
			valAbsentsLower := make([][]string, len(spec.Sinks))
			for i := range spec.Sinks {
				effects[i] = reqGate.effect(spec.Sinks[i].Packages, spec.Sinks[i].Requirement)
				valMatchesLower[i] = lowerStrings(spec.Sinks[i].ValMatches)
				valAbsentsLower[i] = lowerStrings(spec.Sinks[i].ValAbsents)
			}
			var sinkStats []sinkSpecTiming
			var sinkProgress sinkApplicatorProgress
			if sinkTimingOn {
				sinkStats = make([]sinkSpecTiming, len(spec.Sinks))
				sinkProgress.Start = time.Now()
				sinkProgress.Last = sinkProgress.Start
			}
			var out []Mapping
			valCache := newValueTokenCache(s)
			flowIdx := sharedFlowIndex(s)
			var collectionIdx collectionFlowIndex
			needsScope := sinkSpecsNeedScope(spec.Sinks)
			var scopeIdx *flagMatchIndex
			if needsScope {
				scopeIdx = sharedFlagIndex(s)
			}
			rangeSinks := func(fn func(usg.Node) bool) {
				if needsScope {
					scopeIdx.rangeTechNodes(s, spec.Technology, false, fn, "code.Call", "code.Attr", "code.BinOp")
					return
				}
				rangeTechNodesDirect(s, spec.Technology, false, fn, "code.Call", "code.Attr", "code.BinOp")
			}
			rangeSinks(func(n usg.Node) bool {
				if sinkTimingOn {
					sinkProgress.Nodes++
				}
				id := n.ID
				isAttr := n.Type == "code.Attr"
				method, path, recvType := n.Prop("method"), n.Prop("callee_path"), n.Prop("recv_type")
				cand := sinkIdx.candidates(method, path)
				if sinkTimingOn {
					sinkProgress.Candidates += len(cand)
				}
				// Pick the MOST SPECIFIC matching sink (longest pattern) per concept, so
				// e.g. a qualified path wins over its short method for overlapping
				// mappings, while one call can still carry genuinely distinct concepts.
				bestByConcept := map[string]int{}
				for _, i := range cand {
					var statStart time.Time
					if sinkTimingOn {
						sinkStats[i].Candidates++
						statStart = time.Now()
					}
					sk := spec.Sinks[i]
					if !nodeTypeAllowed(sk.NodeType, n.Type) {
						continue
					}
					if !effects[i].Allowed {
						continue
					}
					if isAttr && !attributeSinks[sk.Concept] {
						continue
					}
					hit := sk.ByMethod && method == sk.Pattern ||
						!sk.ByMethod && ((sk.Exact && path == sk.Pattern) || (!sk.Exact && matchSinkPath(path, sk.Pattern)))
					if hit && sk.ByMethod && !receiverScopeSatisfied(n.Prop("recv_package"), path, sk.Packages, scopePolicy) {
						hit = false
					}
					if sinkTimingOn {
						sinkStats[i].MatchDuration += time.Since(statStart)
					}
					// value-matched sink: every `val` must be present and every `nval`
					// absent among the literal arg/option tokens (case-insensitive).
					if hit {
						if sinkTimingOn {
							statStart = time.Now()
						}
						if !valCondsForSinkCached(s, flowIdx, valCache, n, sk, valMatchesLower[i], valAbsentsLower[i]) {
							hit = false
						}
						if sinkTimingOn {
							sinkStats[i].ValueDuration += time.Since(statStart)
						}
					}
					if sinkTimingOn && hit {
						sinkStats[i].ValueHits++
					}
					if hit && !callArgCountMatches(n, sk.ArgCountSet, sk.ArgCountMin, sk.ArgCountMax) {
						hit = false
					}
					if sinkTimingOn && hit {
						sinkStats[i].ArgCountHits++
					}
					if hit && len(sk.ScopePreds) > 0 {
						if sinkTimingOn {
							statStart = time.Now()
						}
						if !scopePredicatesMatch(s, scopeIdx, sk.ScopePreds, n, spec.Technology, spec.crossLang) {
							hit = false
						}
						if sinkTimingOn {
							sinkStats[i].ScopeDuration += time.Since(statStart)
						}
					}
					if sinkTimingOn && hit {
						sinkStats[i].Hits++
					}
					if !hit {
						continue
					}
					// Most specific wins: longer pattern, then more value constraints
					// (a `val`-matched sink is more specific than the plain form).
					// Keyed by (concept,
					// ARG INDEX): the same concept can be injectable at MULTIPLE arg
					// positions of one call, so those must not collapse together.
					bkey := sinkBestKey(sk)
					if curIdx, ok := bestByConcept[bkey]; !ok {
						bestByConcept[bkey] = i
					} else if cur := spec.Sinks[curIdx]; len(sk.Pattern) > len(cur.Pattern) ||
						(len(sk.Pattern) == len(cur.Pattern) && len(sk.ValMatches) > len(cur.ValMatches)) {
						bestByConcept[bkey] = i
					}
				}
				for _, i := range cand {
					sk := spec.Sinks[i]
					best, ok := bestByConcept[sinkBestKey(sk)]
					if !ok || best != i {
						continue
					}
					// tiering: a package-scoped sink is the most specific match (tier 3) and
					// supersedes native path (resolved) and general method (syntactic) matches.
					pkgSpec := 0
					if len(sk.Packages) > 0 {
						pkgSpec = 3
					}
					if isAttr {
						if sk.ByMethod {
							detail, conf := reviewDetail(sk.Concept, sk.Pattern)
							conf = mappingConfidence(sk.Confidence, conf)
							conf, detail = effects[i].apply(conf, detail)
							out = append(out, Mapping{NodeID: id, Concept: sk.Concept, Fidelity: mappingFidelity(sk.Fidelity, "syntactic"), Confidence: conf, Specificity: pkgSpec, Detail: detail})
							if sinkTimingOn {
								sinkProgress.Mappings++
							}
						} else {
							detail, conf := reviewDetail(sk.Concept, sk.Pattern)
							conf = mappingConfidence(sk.Confidence, conf)
							conf, detail = effects[i].apply(conf, detail)
							out = append(out, Mapping{NodeID: id, Concept: sk.Concept, Fidelity: mappingFidelity(sk.Fidelity, "resolved"), Confidence: conf, Specificity: pkgSpec, Detail: detail})
							if sinkTimingOn {
								sinkProgress.Mappings++
							}
						}
						continue
					}
					// receiver-sink: the tainted data is the receiver; the call node
					// carries that taint, so label the node itself rather than an arg.
					if sk.Receiver {
						if sk.Constraint != "" && recvType != "" && !constraintAllows(sk.Constraint, recvType) {
							continue
						}
						detail, conf := reviewDetail(sk.Concept, sk.Pattern)
						conf = mappingConfidence(sk.Confidence, conf)
						conf, detail = effects[i].apply(conf, detail)
						out = append(out, Mapping{NodeID: id, Concept: sk.Concept, Fidelity: mappingFidelity(sk.Fidelity, "syntactic"), Confidence: conf, Specificity: pkgSpec, Detail: detail})
						if sinkTimingOn {
							sinkProgress.Mappings++
						}
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
					// arg all (ArgIndex == -1): any tainted argument may be relevant.
					if sk.ArgIndex < 0 {
						for ai := 0; ; ai++ {
							arg := n.Prop(usg.ArgPropKey(ai))
							if arg == "" {
								break
							}
							target := arg
							foundCollectionTarget := false
							if sk.CollectionFirst {
								if first := collectionElement(s, &collectionIdx, arg, sk.CollectionIndex); first != "" {
									target = first
									foundCollectionTarget = true
								}
							}
							if a, ok, _ := s.GetNode(arg); ok {
								vkind := a.Prop("vkind")
								if sk.Collection && !foundCollectionTarget && vkind != "Seq" &&
									(!collectionArgKindAllowsFlow(vkind) || !collectionArgument(s, &collectionIdx, arg)) {
									continue
								}
								if !sk.Collection && !sk.CollectionFirst && a.Prop("vkind") == "Seq" {
									continue
								}
							} else if sk.Collection {
								continue
							}
							detail, conf := reviewDetail(sk.Concept, sk.Pattern)
							conf = mappingConfidence(sk.Confidence, conf)
							conf, detail = effects[i].apply(conf, detail)
							out = append(out, Mapping{NodeID: target, Concept: sk.Concept, Fidelity: mappingFidelity(sk.Fidelity, fidelity), Confidence: conf, Specificity: pkgSpec, Detail: detail})
							if sinkTimingOn {
								sinkProgress.Mappings++
							}
						}
						continue
					}
					arg := n.Prop(usg.ArgPropKey(sk.ArgIndex))
					if arg == "" {
						continue
					}
					target := arg
					foundCollectionTarget := false
					if sk.CollectionFirst {
						if first := collectionElement(s, &collectionIdx, arg, sk.CollectionIndex); first != "" {
							target = first
							foundCollectionTarget = true
						}
					}
					if a, ok, _ := s.GetNode(arg); ok {
						vkind := a.Prop("vkind")
						if sk.Collection && !foundCollectionTarget && vkind != "Seq" &&
							(!collectionArgKindAllowsFlow(vkind) || !collectionArgument(s, &collectionIdx, arg)) {
							continue
						}
						if !sk.Collection && !sk.CollectionFirst && a.Prop("vkind") == "Seq" {
							continue
						}
					} else if sk.Collection {
						continue
					}
					detail, conf := reviewDetail(sk.Concept, sk.Pattern)
					conf = mappingConfidence(sk.Confidence, conf)
					conf, detail = effects[i].apply(conf, detail)
					out = append(out, Mapping{NodeID: target, Concept: sk.Concept, Fidelity: mappingFidelity(sk.Fidelity, fidelity), Confidence: conf, Specificity: pkgSpec, Detail: detail})
					if sinkTimingOn {
						sinkProgress.Mappings++
					}
				}
				if sinkTimingOn {
					now := time.Now()
					if now.Sub(sinkProgress.Last) >= 5*time.Second {
						fmt.Fprintf(os.Stderr, "[sink-progress] %-36s nodes=%-8d candidates=%-8d mappings=%-6d elapsed=%7.1fms\n",
							spec.Name+".sinks",
							sinkProgress.Nodes,
							sinkProgress.Candidates,
							sinkProgress.Mappings,
							float64(now.Sub(sinkProgress.Start))/1e6,
						)
						sinkProgress.Last = now
					}
				}
				return true
			})
			if sinkTimingOn {
				printSinkSpecTiming(spec.Name+".sinks", spec.Sinks, sinkStats)
			}
			return out
		},
	}
}

type sinkSpecTiming struct {
	Candidates    int
	ValueHits     int
	ArgCountHits  int
	Hits          int
	MatchDuration time.Duration
	ValueDuration time.Duration
	ScopeDuration time.Duration
}

type sinkApplicatorProgress struct {
	Start      time.Time
	Last       time.Time
	Nodes      int
	Candidates int
	Mappings   int
}

func printSinkSpecTiming(name string, sinks []sinkSpec, stats []sinkSpecTiming) {
	type row struct {
		idx  int
		stat sinkSpecTiming
	}
	rows := make([]row, 0, len(stats))
	for i, stat := range stats {
		if stat.Candidates == 0 && stat.Hits == 0 {
			continue
		}
		rows = append(rows, row{idx: i, stat: stat})
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		aDur := a.stat.MatchDuration + a.stat.ValueDuration + a.stat.ScopeDuration
		bDur := b.stat.MatchDuration + b.stat.ValueDuration + b.stat.ScopeDuration
		if aDur != bDur {
			return aDur > bDur
		}
		if a.stat.Candidates != b.stat.Candidates {
			return a.stat.Candidates > b.stat.Candidates
		}
		return a.idx < b.idx
	})
	limit := 20
	if len(rows) < limit {
		limit = len(rows)
	}
	for _, row := range rows[:limit] {
		sk := sinks[row.idx]
		mode := "path"
		if sk.ByMethod {
			mode = "method"
		}
		fmt.Fprintf(os.Stderr, "[sink] %-36s #%03d cand=%-8d val=%-6d argc=%-6d hits=%-6d match=%7.1fms value=%7.1fms scope=%7.1fms kind=%-6s concept=%s pattern=%s\n",
			name,
			row.idx,
			row.stat.Candidates,
			row.stat.ValueHits,
			row.stat.ArgCountHits,
			row.stat.Hits,
			float64(row.stat.MatchDuration)/1e6,
			float64(row.stat.ValueDuration)/1e6,
			float64(row.stat.ScopeDuration)/1e6,
			mode,
			sk.Concept,
			sk.Pattern,
		)
	}
}

func sinkBestKey(sk sinkSpec) string {
	return sk.Concept + "\x00" +
		strconv.Itoa(sk.ArgIndex) + "\x00" +
		strconv.FormatBool(sk.Collection) + "\x00" +
		strconv.FormatBool(sk.CollectionFirst) + "\x00" +
		strconv.Itoa(sk.CollectionIndex)
}

func (spec bindingSpec) checkApplicator() Applicator {
	return Applicator{
		Name: spec.Name + ".controls", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []Mapping {
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			ctrlIdx := buildSpecIndex(len(spec.Controls), func(i int) (methods, paths []string, loose bool) {
				if spec.Controls[i].ByMethod {
					return []string{spec.Controls[i].Pattern}, nil, false
				}
				return nil, []string{spec.Controls[i].Pattern}, false
			})
			effects := make([]requirementEffect, len(spec.Controls))
			valMatchesLower := make([][]string, len(spec.Controls))
			valAbsentsLower := make([][]string, len(spec.Controls))
			for i := range spec.Controls {
				effects[i] = reqGate.effect(spec.Controls[i].Packages, spec.Controls[i].Requirement)
				valMatchesLower[i] = lowerStrings(spec.Controls[i].ValMatches)
				valAbsentsLower[i] = lowerStrings(spec.Controls[i].ValAbsents)
			}
			var out []Mapping
			valCache := newValueTokenCache(s)
			var collectionIdx collectionFlowIndex
			needsScope := controlSpecsNeedScope(spec.Controls)
			var scopeIdx *flagMatchIndex
			if needsScope {
				scopeIdx = sharedFlagIndex(s)
			}
			rangeControls := func(fn func(usg.Node) bool) {
				if needsScope {
					scopeIdx.rangeTechNodes(s, spec.Technology, false, fn, "code.Call")
					return
				}
				rangeTechNodesDirect(s, spec.Technology, false, fn, "code.Call")
			}
			rangeControls(func(n usg.Node) bool {
				id := n.ID
				path, method := n.Prop("callee_path"), n.Prop("method")
				for _, ci := range ctrlIdx.candidates(method, path) {
					c := spec.Controls[ci]
					if !nodeTypeAllowed(c.NodeType, n.Type) {
						continue
					}
					if !effects[ci].Allowed {
						continue
					}
					// no break: a single call can be MULTIPLE controls, so attach every match.
					hit := c.ByMethod && method == c.Pattern ||
						!c.ByMethod && ((c.Exact && path == c.Pattern) || (!c.Exact && matchPath(path, []string{c.Pattern}, "prefix")))
					if hit && c.ByMethod && !receiverScopeSatisfied(n.Prop("recv_package"), path, c.Packages, scopePolicy) {
						hit = false
					}
					if hit && !callArgCountMatches(n, c.ArgCountSet, c.ArgCountMin, c.ArgCountMax) {
						hit = false
					}
					if hit && valCondsDirectForNodeCached(valCache, n, valMatchesLower[ci], valAbsentsLower[ci]) &&
						(len(c.ScopePreds) == 0 || scopePredicatesMatch(s, scopeIdx, c.ScopePreds, n, spec.Technology, spec.crossLang)) {
						nodeID := id
						if c.Receiver {
							nodeID = n.Prop("recv")
							if nodeID == "" {
								continue
							}
						}
						spec := 0
						if len(c.Packages) > 0 {
							spec = 3 // package-specific control supersedes native/general
						}
						conf, detail := effects[ci].apply(mappingConfidence(c.Confidence, ""), c.Detail)
						if c.ArgTarget {
							for _, target := range markTargets(s, &collectionIdx, n, c) {
								out = append(out, Mapping{NodeID: target, Concept: c.Concept, Fidelity: mappingFidelity(c.Fidelity, "resolved"), Confidence: conf, Specificity: spec, Detail: detail})
							}
							continue
						}
						out = append(out, Mapping{NodeID: nodeID, Concept: c.Concept, Fidelity: mappingFidelity(c.Fidelity, "resolved"), Confidence: conf, Specificity: spec, Detail: detail})
					}
				}
				return true
			})
			return out
		},
	}
}

// extTech maps a source file extension to its binding technology, so a binding
// only labels nodes from its own language (avoids cross-language FPs in polyglot
// repos — e.g. one language's binding matching another language's same-named call).

func downgradeConfidence(conf string, steps int) string {
	idx := resultpolicy.MaxConfidenceRank()
	if conf != "" {
		if rank := resultpolicy.ConfidenceRank(conf); rank > 0 {
			idx = rank
		}
	}
	idx -= steps
	if idx < 1 {
		idx = 1
	}
	return resultpolicy.ConfidenceName(idx)
}

func mappingFidelity(authored, fallback string) string {
	if authored != "" {
		return authored
	}
	return fallback
}

func mappingConfidence(authored, derived string) string {
	if authored == "" {
		return derived
	}
	if derived == "" {
		return authored
	}
	if confidenceRank(authored) <= confidenceRank(derived) {
		return authored
	}
	return derived
}

func confidenceRank(conf string) int {
	if rank := resultpolicy.ConfidenceRank(conf); rank > 0 {
		return rank
	}
	return resultpolicy.MaxConfidenceRank()
}

func (spec bindingSpec) presenceApplicator() Applicator {
	return Applicator{
		Name: spec.Name + ".flags", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []Mapping {
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			flagReqs := make([]*Requirement, 0, len(spec.Flags))
			for i := range spec.Flags {
				flagReqs = append(flagReqs, spec.Flags[i].Requirement)
			}
			prewarmContentRequirements(s, flagReqs...)
			effects := make([]requirementEffect, len(spec.Flags))
			anyAllowed := false
			for i := range spec.Flags {
				effects[i] = reqGate.effect(spec.Flags[i].Packages, spec.Flags[i].Requirement)
				if effects[i].Allowed {
					anyAllowed = true
				}
			}
			if !anyAllowed {
				return nil
			}
			fileTech := sharedFileContextTechs(s)
			flagIdx := buildSpecIndex(len(spec.Flags), func(i int) (methods, paths []string, loose bool) {
				if spec.Flags[i].Scope != "" {
					return nil, []string{"analysis." + lowerString(spec.Flags[i].Scope) + ".context"}, false
				}
				for _, pred := range spec.Flags[i].Predicates {
					if pred.Subject == "flow_to" {
						continue
					}
					switch pred.Property {
					case "path":
						paths = append(paths, pred.Values...)
					case "method":
						methods = append(methods, pred.Values...)
					}
				}
				return methods, paths, len(methods) == 0 && len(paths) == 0
			})
			var out []Mapping
			needsFullIndex := flagSpecsNeedFullIndex(spec.Flags)
			matchIdx := &flagMatchIndex{}
			if needsFullIndex {
				matchIdx = sharedFlagIndex(s)
			}
			contextOnlyPreds := make([]flagPredicate, len(spec.Flags))
			contextOnlyOK := make([]bool, len(spec.Flags))
			opPreds := make([]flagPredicate, len(spec.Flags))
			opOK := make([]bool, len(spec.Flags))
			for i := range spec.Flags {
				contextOnlyPreds[i], contextOnlyOK[i] = flagContextOnlyPredicate(spec.Flags[i], spec.Technology)
				opPreds[i], opOK[i] = flagPositiveOpPredicate(spec.Flags[i])
			}
			var flagStats []presenceFlagTiming
			if flagTimingOn {
				flagStats = make([]presenceFlagTiming, len(spec.Flags))
			}
			nodeTypes := flagApplicatorNodeTypes(spec.Flags, spec.crossLang)
			for _, nodeType := range nodeTypes {
				rangeFlagNodes := func(fn func(usg.Node) bool) {
					if needsFullIndex {
						matchIdx.rangeNodesOfTechType(s, spec.Technology, nodeType, spec.crossLang, fn)
						return
					}
					rangeTechNodesDirect(s, spec.Technology, spec.crossLang, fn, nodeType)
				}
				rangeFlagNodes(func(n usg.Node) bool {
					for _, i := range flagIdx.candidates(n.Prop("method"), n.Prop("callee_path")) {
						if !effects[i].Allowed {
							continue
						}
						fl := spec.Flags[i]
						if !flagNodeKindAllows(fl, n) {
							continue
						}
						if opOK[i] && !flagValuePredicate(opPreds[i], n.Prop("op")) {
							continue
						}
						if contextOnlyOK[i] {
							text := n.Prop("str_args")
							if !flagContextOnlyPredicateMaybePresent(contextOnlyPreds[i], text) {
								continue
							}
						}
						var matched bool
						if flagTimingOn {
							start := time.Now()
							matched = flagMatchesNode(s, matchIdx, fl, n, spec.Technology, spec.crossLang, fileTech)
							elapsed := time.Since(start)
							flagStats[i].Calls++
							flagStats[i].Duration += elapsed
							if matched {
								flagStats[i].Hits++
							}
						} else {
							matched = flagMatchesNode(s, matchIdx, fl, n, spec.Technology, spec.crossLang, fileTech)
						}
						if !matched {
							continue
						}
						detail, conf := reviewDetail(fl.Concept, flagPattern(fl))
						detail = mergeMappingDetail(detail, fl.Detail)
						conf = mappingConfidence(fl.Confidence, conf)
						conf, detail = effects[i].apply(conf, detail)
						specificity := 0
						if len(fl.Packages) > 0 {
							specificity = 3
						}
						out = append(out, Mapping{NodeID: n.ID, Concept: fl.Concept, Fidelity: mappingFidelity(fl.Fidelity, "resolved"), Confidence: conf, Specificity: specificity, Detail: detail})
					}
					return true
				})
			}
			if flagTimingOn {
				printPresenceFlagTiming(spec.Name+".flags", spec.Flags, flagStats)
			}
			return out
		},
	}
}

type presenceFlagTiming struct {
	Calls    int
	Hits     int
	Duration time.Duration
}

func printPresenceFlagTiming(name string, flags []flagSpec, stats []presenceFlagTiming) {
	type row struct {
		idx  int
		stat presenceFlagTiming
	}
	rows := make([]row, 0, len(stats))
	for i, stat := range stats {
		if stat.Calls == 0 && stat.Duration == 0 {
			continue
		}
		rows = append(rows, row{idx: i, stat: stat})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].stat.Duration == rows[j].stat.Duration {
			return rows[i].stat.Calls > rows[j].stat.Calls
		}
		return rows[i].stat.Duration > rows[j].stat.Duration
	})
	limit := 12
	if len(rows) < limit {
		limit = len(rows)
	}
	for _, row := range rows[:limit] {
		fl := flags[row.idx]
		fmt.Fprintf(os.Stderr, "[flag] %-36s #%03d %7.1fms calls=%-7d hits=%-4d scope=%-8s kind=%-8s concept=%s pattern=%s\n",
			name,
			row.idx,
			float64(row.stat.Duration)/1e6,
			row.stat.Calls,
			row.stat.Hits,
			fl.Scope,
			fl.NodeKind,
			fl.Concept,
			flagPattern(fl),
		)
	}
}

func flagApplicatorNodeTypes(flags []flagSpec, crossLang bool) []string {
	base := []string{"code.Call", "code.Attr", "code.Seq", "code.Subscript", "code.BinOp", "code.Unary", "code.Name"}
	all := func() []string {
		out := append([]string{}, base...)
		if crossLang {
			out = append(out, "sbom.PackageVersion")
		}
		return out
	}
	if len(flags) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(typ string) {
		if typ == "" || seen[typ] {
			return
		}
		seen[typ] = true
		out = append(out, typ)
	}
	for _, fl := range flags {
		switch lowerString(fl.Scope) {
		case "function", "module", "class":
			add("code.Call")
			continue
		}
		switch lowerString(fl.NodeKind) {
		case "", "any":
			return all()
		case "call":
			add("code.Call")
		case "attr", "attribute":
			add("code.Attr")
		case "seq", "collection", "object":
			add("code.Seq")
		case "subscript", "index":
			add("code.Subscript")
		case "binop", "binary":
			add("code.BinOp")
		case "unary":
			add("code.Unary")
		case "name", "identifier":
			add("code.Name")
		default:
			add("code." + titleNodeKind(fl.NodeKind))
		}
	}
	if crossLang {
		add("sbom.PackageVersion")
	}
	return out
}

func (spec bindingSpec) matchPresenceApplicator() Applicator {
	return Applicator{
		Name: spec.Name + ".marks", Technology: spec.Technology, Specificity: 2,
		Fidelity: "resolved", Origin: "human",
		Apply: func(s usg.Store) []Mapping {
			// Most presence events are calls, but some are bare member accesses with
			// no call, so scan Attr nodes too.
			var out []Mapping
			// cross-language binding applicators label nodes in source files of
			// every language, so the per-language tech filter doesn't apply.
			crossLang := spec.crossLang
			pkgs := packageEvidence(s, spec.Technology, crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			markIdx := buildSpecIndex(len(spec.Marks), func(i int) (methods, paths []string, loose bool) {
				if spec.Marks[i].NodeType != "" && spec.Marks[i].Pattern == "" {
					return nil, nil, true
				}
				if spec.Marks[i].ByMethod {
					return []string{spec.Marks[i].Pattern}, nil, false
				}
				return nil, []string{spec.Marks[i].Pattern}, false
			})
			effects := make([]requirementEffect, len(spec.Marks))
			valMatchesLower := make([][]string, len(spec.Marks))
			valAbsentsLower := make([][]string, len(spec.Marks))
			for i := range spec.Marks {
				effects[i] = reqGate.effect(spec.Marks[i].Packages, spec.Marks[i].Requirement)
				valMatchesLower[i] = lowerStrings(spec.Marks[i].ValMatches)
				valAbsentsLower[i] = lowerStrings(spec.Marks[i].ValAbsents)
			}
			nodeTypes := []string{"code.Call", "code.Attr", "code.Seq", "code.Subscript", "code.BinOp", "code.Unary", "code.Literal", "code.Const", "code.Function", "code.Class", "code.Import"}
			if crossLang {
				nodeTypes = append(nodeTypes, "sbom.PackageVersion")
			}
			var collectionIdx collectionFlowIndex
			needsScope := controlSpecsNeedScope(spec.Marks)
			var scopeIdx *flagMatchIndex
			if needsScope {
				scopeIdx = sharedFlagIndex(s)
			}
			valCache := newValueTokenCache(s)
			rangeMarks := func(fn func(usg.Node) bool) {
				if needsScope {
					scopeIdx.rangeTechNodes(s, spec.Technology, crossLang, fn, nodeTypes...)
					return
				}
				rangeTechNodesDirect(s, spec.Technology, crossLang, fn, nodeTypes...)
			}
			rangeMarks(func(n usg.Node) bool {
				path := n.Prop("callee_path")
				method := n.Prop("method")
				seenMapping := map[string]bool{}
				for _, mi := range markIdx.candidates(method, path) {
					m := spec.Marks[mi]
					if !nodeTypeAllowed(m.NodeType, n.Type) {
						continue
					}
					if !effects[mi].Allowed {
						continue
					}
					hit := m.ByMethod && method == m.Pattern ||
						!m.ByMethod && ((m.Pattern == "" && m.NodeType != "") || (m.Exact && path == m.Pattern) || (!m.Exact && matchSinkPath(path, m.Pattern)))
					if hit && m.ByMethod && !receiverScopeSatisfied(n.Prop("recv_package"), path, m.Packages, scopePolicy) {
						hit = false
					}
					if !hit {
						continue
					}
					if !callArgCountMatches(n, m.ArgCountSet, m.ArgCountMin, m.ArgCountMax) {
						continue
					}
					if !valCondsDirectForNodeCached(valCache, n, valMatchesLower[mi], valAbsentsLower[mi]) {
						continue
					}
					if len(m.ScopePreds) > 0 && !scopePredicatesMatch(s, scopeIdx, m.ScopePreds, n, spec.Technology, crossLang) {
						continue
					}
					detail, conf := reviewDetail(m.Concept, m.Pattern)
					detail = mergeMappingDetail(detail, m.Detail)
					conf = mappingConfidence(m.Confidence, conf)
					conf, detail = effects[mi].apply(conf, detail)
					spec := 0
					if len(m.Packages) > 0 {
						spec = 3 // package-specific direct label supersedes native/general
					}
					for _, target := range markTargets(s, &collectionIdx, n, m) {
						key := m.Concept + "\x00" + target
						if seenMapping[key] {
							continue
						}
						out = append(out, Mapping{NodeID: target, Concept: m.Concept, Fidelity: mappingFidelity(m.Fidelity, "resolved"), Confidence: conf, Specificity: spec, Detail: detail})
						seenMapping[key] = true
					}
				}
				return true
			})
			return out
		},
	}
}

func AutoBindings() []Applicator {
	key := "v2\x00" + ActiveBindingConceptsKey()
	if cached, ok := autoBindingsCache.Load(key); ok {
		res := cached.(cachedAutoBindings)
		if res.err != nil {
			panic(res.err.Error())
		}
		return res.data
	}
	data, err := loadAutoBindingApplicators()
	res := cachedAutoBindings{data: data, err: err}
	actual, _ := autoBindingsCache.LoadOrStore(key, res)
	actualRes := actual.(cachedAutoBindings)
	if actualRes.err != nil {
		panic(actualRes.err.Error())
	}
	return actualRes.data
}

func loadAutoBindingApplicators() ([]Applicator, error) {
	sources, err := autoBindingSources()
	if err != nil {
		return nil, fmt.Errorf("frontend: read auto bindings: %w", err)
	}
	byName := map[string]*Set{}
	var order []string
	sets, err := compileV2BindingSources(sources)
	if err != nil {
		return nil, fmt.Errorf("frontend: parse auto binding corpus: %w", err)
	}
	for _, ad := range sets {
		merged := byName[ad.Name]
		if merged == nil {
			merged = &Set{Name: ad.Name, Meta: map[string]any{}}
			byName[ad.Name] = merged
			order = append(order, ad.Name)
		}
		for k, v := range ad.Meta {
			merged.Meta[k] = v
		}
		merged.Mappings = append(merged.Mappings, ad.Mappings...)
	}
	var out []Applicator
	for _, name := range order {
		ad := byName[name]
		if mode, _ := ad.Meta["auto_apply"].(string); mode == "graph" {
			out = append(out, bindingApplicatorsFromSpec(filterBindingSpecForActiveConcepts(specFromBindingSet(ad)))...)
		}
	}
	return out, nil
}

func autoBindingSources() ([]datadir.Source, error) {
	root := filepath.Join(datadir.Root(), "bindings")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []datadir.Source
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			if name == "packages" {
				continue
			}
			sources, err := datadir.ReadVYQLDir(filepath.ToSlash(filepath.Join("bindings", name)))
			if err != nil {
				return nil, err
			}
			out = append(out, sources...)
			continue
		}
		if !strings.HasSuffix(name, ".vyql") {
			continue
		}
		rel := filepath.ToSlash(filepath.Join("bindings", name))
		raw, err := datadir.Read(rel)
		if err != nil {
			return nil, err
		}
		out = append(out, datadir.Source{Name: rel, Data: raw})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// paramSourceApplicator labels function/method parameter nodes with the spec's
// `source param -> X` concept(s) for profiles that opt into parameter entrypoints.
// The concrete concept is declared by the .vyql line; this is only the mechanism.
//
// Default-OFF, opt-in: unlike the pattern source binding (where activeSources==nil means
// "no profile → every source on"), a parameter source fires ONLY when a profile is set AND
// explicitly lists the concept (i.e. the library profile). So application profiles, and the
// no-profile default, never taint parameters. Low confidence (syntactic): a finding
// surfaces only if a param actually reaches a sink.

func (spec bindingSpec) paramSourceApplicator() Applicator {
	sources := spec.ParamSources
	return Applicator{
		Name: spec.Name + ".param-source", Technology: spec.Technology, Specificity: 0,
		Fidelity: "syntactic", Origin: "human",
		Apply: func(s usg.Store) []Mapping {
			if activeSources == nil {
				return nil // no active source set -> parameters are not sources
			}
			pkgs := packageEvidence(s, spec.Technology, spec.crossLang)
			reqGate := newRequirementGate(s, spec.Technology, spec.crossLang, pkgs)
			type activeParamSource struct {
				spec   paramSourceSpec
				effect requirementEffect
			}
			active := make([]activeParamSource, 0, len(sources))
			for _, src := range sources {
				eff := reqGate.effect(src.Packages, src.Requirement)
				if activeSources[src.Concept] && eff.Allowed {
					active = append(active, activeParamSource{spec: src, effect: eff})
				}
			}
			if len(active) == 0 {
				return nil
			}
			ids, _ := s.NodesOfType("code.Param")
			out := make([]Mapping, 0, len(active))
			for _, id := range ids {
				n, ok, _ := s.GetNode(id)
				if !ok || n.Prop("exported") != "true" {
					continue // only PUBLIC-API params are entry points; internal helpers are
					// reached by ordinary interprocedural propagation (precision).
				}
				for _, activeSrc := range active {
					src := activeSrc.spec
					spec := 0
					if len(src.Packages) > 0 {
						spec = 3
					}
					conf, detail := activeSrc.effect.apply(mappingConfidence(src.Confidence, ""), nil)
					out = append(out, Mapping{NodeID: id, Concept: src.Concept, Fidelity: mappingFidelity(src.Fidelity, "syntactic"), Confidence: conf, Specificity: spec, Detail: detail})
				}
			}
			return out
		},
	}
}

func processArgVectorApplicator(tech string) Applicator {
	concept := singleOntologyRoleConcept(ontology.InternalConceptRoleProcessArgVector)
	return Applicator{
		Name: "process-arg-vector.controls", Technology: tech, Specificity: 1,
		Fidelity: "semantic", Origin: "human",
		Apply: func(s usg.Store) []Mapping {
			if concept == "" {
				return nil
			}
			ids, _ := s.NodesOfType("code.Seq")
			var idx collectionFlowIndex
			var out []Mapping
			for _, id := range ids {
				n, ok, err := s.GetNode(id)
				if err != nil || !ok {
					continue
				}
				if t := nodeTechFromNode(n); t != "" && tech != "" && t != tech {
					continue
				}
				if !safeProcessArgVectorSeq(s, &idx, id) {
					continue
				}
				out = append(out, Mapping{NodeID: id, Concept: concept, Specificity: 1})
			}
			return out
		},
	}
}
