// Per-pass indexes shared by every applicator, keyed on the store's structural epoch so one index
// is built per pass rather than one per applicator.

package bindings

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vyprai/vyql/internal/usg"
)

type flowTokenIndex struct {
	once sync.Once
	rev  map[string][]string
	fwd  map[string][]string
}

// Per-Apply shared node indexes. Apply runs every applicator sequentially
// against one immutable store (binding application only adds concept labels, never
// nodes/edges), so the whole-store flagMatchIndex / flowTokenIndex / fileTech map can
// be built ONCE and reused by all applicators instead of rebuilt per applicator. On a
// large tree with hundreds of (mostly CVE-specific) presence bindings, the per-applicator
// rebuild was hundreds of full RangeNodes scans and the dominant GC source. Keyed by store
// identity so distinct in-process scans (e.g. parallel tests) never share an index.

type sharedStoreIndexes struct {
	flagOnce  sync.Once
	flag      *flagMatchIndex
	flowOnce  sync.Once
	flow      *flowTokenIndex
	techOnce  sync.Once
	fileTech  map[string]string
	contentMu sync.Mutex
	content   map[string]bool
	gramOnce  sync.Once
	grams     map[uint32]struct{}
}

var sharedStoreIndexCache sync.Map // structural epoch (uint64) -> *sharedStoreIndexes

func storeIndexes(s usg.Store) *sharedStoreIndexes {
	// Key by the store's structural epoch, not its pointer: the epoch is globally
	// monotonic (no reuse across store lifetimes) and changes on any node/edge
	// mutation, so a store re-applied after a structural change (e.g. a unit test that
	// adds nodes between two Apply calls) gets a fresh index instead of a stale one.
	es, ok := s.(interface{ StructEpoch() uint64 })
	if !ok {
		return &sharedStoreIndexes{} // un-epoched store: no cross-applicator sharing (still correct)
	}
	epoch := es.StructEpoch()
	if v, ok := sharedStoreIndexCache.Load(epoch); ok {
		return v.(*sharedStoreIndexes)
	}
	v, _ := sharedStoreIndexCache.LoadOrStore(epoch, &sharedStoreIndexes{})
	return v.(*sharedStoreIndexes)
}

func sharedFlagIndex(s usg.Store) *flagMatchIndex {
	si := storeIndexes(s)
	si.flagOnce.Do(func() { si.flag = &flagMatchIndex{} })
	return si.flag
}

func sharedFlowIndex(s usg.Store) *flowTokenIndex {
	si := storeIndexes(s)
	si.flowOnce.Do(func() { si.flow = &flowTokenIndex{} })
	return si.flow
}

func sharedFileContextTechs(s usg.Store) map[string]string {
	si := storeIndexes(s)
	si.techOnce.Do(func() { si.fileTech = fileContextTechs(s) })
	return si.fileTech
}

// sharedContentContains reports whether the store text may contain a lowercased literal. On large
// repositories it is used as a recall-safe presence gate: a false result means at least one
// required trigram is absent from the whole graph, so an exact match is impossible; a true result
// means "maybe" and lets the normal binding matcher decide.
// presenceGateMinNodes is the graph size above which the content() presence gate is worth its
// check. Normal repos fall below it and run unchanged; only very large trees cross it, where
// skipping CVE pattern bindings that target other projects saves far more than the gate costs.

var presenceGateMinNodes = configuredPresenceGateMinNodes()

func configuredPresenceGateMinNodes() int {
	if v := strings.TrimSpace(os.Getenv("VYQL_PRESENCE_GATE_MIN_NODES")); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil && n >= 0 {
			return n
		}
	}
	return 1 << 60
}

func storeNodeCount(s usg.Store) int {
	if c, ok := s.(interface{ NodeCount() int }); ok {
		return c.NodeCount()
	}
	return 0
}

func sharedContentContains(s usg.Store, lowerNeedle string) bool {
	if lowerNeedle == "" {
		return true
	}
	si := storeIndexes(s)
	si.contentMu.Lock()
	if si.content == nil {
		si.content = map[string]bool{}
	}
	if hit, ok := si.content[lowerNeedle]; ok {
		si.contentMu.Unlock()
		return hit
	}
	si.contentMu.Unlock()

	hit := storeTextMayContainLower(s, lowerNeedle)

	si.contentMu.Lock()
	si.content[lowerNeedle] = hit
	si.contentMu.Unlock()
	return hit
}

func prewarmContentRequirements(s usg.Store, reqs ...*Requirement) {
	if storeNodeCount(s) < presenceGateMinNodes {
		return
	}
	needles := map[string]bool{}
	var walk func(*Requirement)
	walk = func(req *Requirement) {
		if req == nil {
			return
		}
		if req.Op == "content" && req.Value != "" {
			needles[lowerString(req.Value)] = true
		}
		for i := range req.Args {
			walk(&req.Args[i])
		}
	}
	for _, req := range reqs {
		walk(req)
	}
	if len(needles) == 0 {
		return
	}
	sharedContentContainsAny(s, needles)
}

func sharedContentContainsAny(s usg.Store, lowerNeedles map[string]bool) {
	si := storeIndexes(s)
	si.contentMu.Lock()
	if si.content == nil {
		si.content = map[string]bool{}
	}
	missing := map[string]bool{}
	for needle := range lowerNeedles {
		if needle == "" {
			continue
		}
		if _, ok := si.content[needle]; !ok {
			missing[needle] = false
		}
	}
	si.contentMu.Unlock()
	if len(missing) == 0 {
		return
	}

	storeTextMayContainAnyLower(s, missing)

	si.contentMu.Lock()
	for needle, hit := range missing {
		si.content[needle] = hit
	}
	si.contentMu.Unlock()
}

func storeTextMayContainLower(s usg.Store, lowerNeedle string) bool {
	if len(lowerNeedle) < 3 {
		return true
	}
	grams := sharedContentGrams(s)
	for i := 0; i+3 <= len(lowerNeedle); i++ {
		if _, ok := grams[contentGram(lowerNeedle[i:i+3])]; !ok {
			return false
		}
	}
	return true
}

func storeTextMayContainAnyLower(s usg.Store, missing map[string]bool) {
	grams := sharedContentGrams(s)
	for needle := range missing {
		if len(needle) < 3 {
			missing[needle] = true
			continue
		}
		missing[needle] = true
		for i := 0; i+3 <= len(needle); i++ {
			if _, ok := grams[contentGram(needle[i:i+3])]; !ok {
				missing[needle] = false
				break
			}
		}
	}
}

func sharedContentGrams(s usg.Store) map[uint32]struct{} {
	si := storeIndexes(s)
	si.gramOnce.Do(func() {
		grams := map[uint32]struct{}{}
		add := func(v string) {
			if len(v) < 3 {
				return
			}
			addContentGrams(grams, lowerString(v))
		}
		rangeNodes(s, func(n usg.Node) bool {
			add(n.ID)
			add(n.Type)
			add(n.Loc)
			add(n.Region)
			add(n.Scope)
			for _, v := range n.Props {
				add(v)
			}
			return true
		})
		si.grams = grams
	})
	return si.grams
}

func addContentGrams(grams map[uint32]struct{}, lower string) {
	for i := 0; i+3 <= len(lower); i++ {
		grams[contentGram(lower[i:i+3])] = struct{}{}
	}
}

func contentGram(s string) uint32 {
	if len(s) < 3 {
		return 0
	}
	return uint32(s[0])<<16 | uint32(s[1])<<8 | uint32(s[2])
}

type flagMatchIndex struct {
	once            sync.Once // guards the read-only index build (ensure)
	built           atomic.Bool
	flow            flowTokenIndex
	types           map[string][]string
	typesByTech     map[string]map[string][]string // tech -> type -> node IDs ("" tech = unknown, kept by every language)
	typesByFile     map[string]map[string][]string
	binopsByFile    map[string]map[string][]string
	callsByFileTerm map[string]map[string][]string
	paramsByLine    map[string]map[int][]string
	intNodes        bool
	typesI          map[string][]int32
	typesByTechI    map[string]map[string][]int32 // tech -> type -> node indexes
	typesByFileI    map[string]map[string][]int32
	binopsByFileI   map[string]map[string][]int32
	paramsByLineI   map[string]map[int][]int32
	// Lazy memoization caches written during matching. They hold pure-function results
	// (lowering/parsing/scope of a node or text), so concurrent racing producers compute
	// the same value; sync.Map only has to keep the map itself race-free under the parallel
	// binding phase, without serializing the hot read path the way an RWMutex would.
	scopes       sync.Map // nodeID -> string
	lowerText    sync.Map // text -> string
	tokenFacts   sync.Map // text -> *contextTokenFacts
	callArgFacts sync.Map // callArgCacheKey -> *callArgContextFacts
	operands     sync.Map // nodeID/includeFlow -> [][]usg.Node
	predHitSets  sync.Map // key -> scopedPredicateHitSet
}

func (idx *flagMatchIndex) rangeTechNodes(s usg.Store, tech string, crossLang bool, fn func(usg.Node) bool, types ...string) {
	for _, t := range types {
		if !idx.rangeNodesOfTechType(s, tech, t, crossLang, fn) {
			return
		}
	}
}

func (idx *flagMatchIndex) rangeNodesOfTechType(s usg.Store, tech, nodeType string, crossLang bool, fn func(usg.Node) bool) bool {
	idx.ensure(s)
	if idx.intNodes {
		is := s.(interface {
			NodeAtIndex(int32) (usg.Node, bool)
		})
		if crossLang || tech == "" {
			return rangeNodeIndexes(is, idx.typesI[nodeType], fn)
		}
		if !rangeNodeIndexes(is, idx.typesByTechI[tech][nodeType], fn) {
			return false
		}
		return rangeNodeIndexes(is, idx.typesByTechI[""][nodeType], fn)
	}
	if crossLang || tech == "" {
		return rangeNodeIDs(s, idx.types[nodeType], fn)
	}
	if !rangeNodeIDs(s, idx.typesByTech[tech][nodeType], fn) {
		return false
	}
	return rangeNodeIDs(s, idx.typesByTech[""][nodeType], fn)
}

func (idx *flagMatchIndex) ensure(s usg.Store) {
	idx.once.Do(func() {
		idx.build(s)
		idx.built.Store(true)
	})
}

func (idx *flagMatchIndex) build(s usg.Store) {
	start := time.Now()
	count := 0
	techCounts := map[string]int{}
	defer func() {
		if indexTimingOn {
			var parts []string
			for tech, n := range techCounts {
				label := tech
				if label == "" {
					label = "<unknown>"
				}
				parts = append(parts, fmt.Sprintf("%s=%d", label, n))
			}
			sort.Strings(parts)
			fmt.Fprintf(os.Stderr, "[index] flagMatchIndex build %7.1fms nodes=%d int=%v tech=%s\n", float64(time.Since(start))/1e6, count, idx.intNodes, strings.Join(parts, ","))
		}
	}()
	if is, ok := s.(interface {
		RangeNodeIndexes(func(int32, usg.Node) bool)
		NodeAtIndex(int32) (usg.Node, bool)
	}); ok {
		count, techCounts = idx.buildInt(s, is)
		return
	}
	idx.types = map[string][]string{}
	idx.typesByTech = map[string]map[string][]string{}
	idx.typesByFile = map[string]map[string][]string{}
	idx.binopsByFile = map[string]map[string][]string{}
	idx.callsByFileTerm = map[string]map[string][]string{}
	idx.paramsByLine = map[string]map[int][]string{}
	fileTech := sharedFileContextTechs(s)
	rangeNodes(s, func(n usg.Node) bool {
		count++
		idx.types[n.Type] = append(idx.types[n.Type], n.ID)
		tech := nodeTechFromNodeWithFileContext(n, fileTech)
		techCounts[tech]++
		if idx.typesByTech[tech] == nil {
			idx.typesByTech[tech] = map[string][]string{}
		}
		idx.typesByTech[tech][n.Type] = append(idx.typesByTech[tech][n.Type], n.ID)
		if file := locFile(n.Prop("loc")); file != "" {
			if idx.typesByFile[n.Type] == nil {
				idx.typesByFile[n.Type] = map[string][]string{}
			}
			idx.typesByFile[n.Type][file] = append(idx.typesByFile[n.Type][file], n.ID)
			if n.Type == "code.BinOp" {
				if idx.binopsByFile[file] == nil {
					idx.binopsByFile[file] = map[string][]string{}
				}
				idx.binopsByFile[file][n.Prop("op")] = append(idx.binopsByFile[file][n.Prop("op")], n.ID)
			}
			if n.Type == "code.Call" {
				idx.addCallTerms(file, n)
			}
			if n.Type == "code.Param" {
				_, line := splitLocFileLine(n.Prop("loc"))
				if line != 0 {
					if idx.paramsByLine[file] == nil {
						idx.paramsByLine[file] = map[int][]string{}
					}
					idx.paramsByLine[file][line] = append(idx.paramsByLine[file][line], n.ID)
				}
			}
		}
		return true
	})
}

func (idx *flagMatchIndex) buildInt(s usg.Store, is interface {
	RangeNodeIndexes(func(int32, usg.Node) bool)
	NodeAtIndex(int32) (usg.Node, bool)
}) (int, map[string]int) {
	idx.intNodes = true
	idx.typesI = map[string][]int32{}
	idx.typesByTechI = map[string]map[string][]int32{}
	idx.typesByFileI = map[string]map[string][]int32{}
	idx.binopsByFileI = map[string]map[string][]int32{}
	idx.callsByFileTerm = map[string]map[string][]string{}
	idx.paramsByLineI = map[string]map[int][]int32{}
	fileTech := sharedFileContextTechs(s)
	typeIndexes, _ := s.(interface {
		TypeNodeIndexes(string) []int32
	})
	count := 0
	techCounts := map[string]int{}
	is.RangeNodeIndexes(func(i int32, n usg.Node) bool {
		count++
		if _, ok := idx.typesI[n.Type]; !ok {
			if typeIndexes != nil {
				idx.typesI[n.Type] = typeIndexes.TypeNodeIndexes(n.Type)
			} else {
				idx.typesI[n.Type] = append(idx.typesI[n.Type], i)
			}
		} else if typeIndexes == nil {
			idx.typesI[n.Type] = append(idx.typesI[n.Type], i)
		}
		tech := nodeTechFromNodeWithFileContext(n, fileTech)
		techCounts[tech]++
		if idx.typesByTechI[tech] == nil {
			idx.typesByTechI[tech] = map[string][]int32{}
		}
		idx.typesByTechI[tech][n.Type] = append(idx.typesByTechI[tech][n.Type], i)
		if file := locFile(n.Prop("loc")); file != "" {
			if idx.typesByFileI[n.Type] == nil {
				idx.typesByFileI[n.Type] = map[string][]int32{}
			}
			idx.typesByFileI[n.Type][file] = append(idx.typesByFileI[n.Type][file], i)
			if n.Type == "code.BinOp" {
				if idx.binopsByFileI[file] == nil {
					idx.binopsByFileI[file] = map[string][]int32{}
				}
				idx.binopsByFileI[file][n.Prop("op")] = append(idx.binopsByFileI[file][n.Prop("op")], i)
			}
			if n.Type == "code.Call" {
				idx.addCallTerms(file, n)
			}
			if n.Type == "code.Param" {
				_, line := splitLocFileLine(n.Prop("loc"))
				if line != 0 {
					if idx.paramsByLineI[file] == nil {
						idx.paramsByLineI[file] = map[int][]int32{}
					}
					idx.paramsByLineI[file][line] = append(idx.paramsByLineI[file][line], i)
				}
			}
		}
		return true
	})
	return count, techCounts
}

func (idx *flagMatchIndex) addCallTerms(file string, n usg.Node) {
	terms := callIndexTerms(n)
	if len(terms) == 0 {
		return
	}
	byTerm := idx.callsByFileTerm[file]
	if byTerm == nil {
		byTerm = map[string][]string{}
		idx.callsByFileTerm[file] = byTerm
	}
	for _, term := range terms {
		byTerm[term] = append(byTerm[term], n.ID)
	}
}

func (idx *flagMatchIndex) rangeNodesOfTypeInFile(s usg.Store, typ, file string, fn func(usg.Node) bool) bool {
	idx.ensure(s)
	if idx.intNodes {
		is := s.(interface {
			NodeAtIndex(int32) (usg.Node, bool)
		})
		if file == "" {
			return rangeNodeIndexes(is, idx.typesI[typ], fn)
		}
		return rangeNodeIndexes(is, idx.typesByFileI[typ][file], fn)
	}
	if file == "" {
		return rangeNodeIDs(s, idx.types[typ], fn)
	}
	return rangeNodeIDs(s, idx.typesByFile[typ][file], fn)
}

func (idx *flagMatchIndex) rangeBinopsInFileForValues(s usg.Store, file string, values []string, fn func(usg.Node) bool) bool {
	idx.ensure(s)
	ops, ok := binaryPredicateOps(values)
	if !ok {
		return idx.rangeNodesOfTypeInFile(s, "code.BinOp", file, fn)
	}
	if idx.intNodes {
		is := s.(interface {
			NodeAtIndex(int32) (usg.Node, bool)
		})
		if file == "" {
			for _, op := range ops {
				for _, byOp := range idx.binopsByFileI {
					if !rangeNodeIndexes(is, byOp[op], fn) {
						return false
					}
				}
			}
			return true
		}
		byOp := idx.binopsByFileI[file]
		for _, op := range ops {
			if !rangeNodeIndexes(is, byOp[op], fn) {
				return false
			}
		}
		return true
	}
	if file == "" {
		for _, op := range ops {
			for _, byOp := range idx.binopsByFile {
				if !rangeNodeIDs(s, byOp[op], fn) {
					return false
				}
			}
		}
		return true
	}
	byOp := idx.binopsByFile[file]
	for _, op := range ops {
		if !rangeNodeIDs(s, byOp[op], fn) {
			return false
		}
	}
	return true
}

func (idx *flagMatchIndex) node(s usg.Store, id string) (usg.Node, bool) {
	n, ok, err := s.GetNode(id)
	if err != nil {
		return usg.Node{}, false
	}
	return n, ok
}

func (idx *flagMatchIndex) normalizedScope(n usg.Node) string {
	if n.ID == "" {
		return scopeWithoutOrder(nodeLexicalScope(n))
	}
	if scope, ok := idx.scopes.Load(n.ID); ok {
		return scope.(string)
	}
	scope := scopeWithoutOrder(nodeLexicalScope(n))
	idx.scopes.Store(n.ID, scope)
	return scope
}

func (idx *flagMatchIndex) lowerTextValue(text string) string {
	if text == "" {
		return ""
	}
	if len(text) > lowerTextCacheMaxBytes {
		return lowerString(text)
	}
	if lower, ok := idx.lowerText.Load(text); ok {
		return lower.(string)
	}
	lower := lowerString(text)
	idx.lowerText.Store(text, lower)
	return lower
}

var lowerTextCacheMaxBytes = configuredLowerTextCacheMaxBytes()

func configuredLowerTextCacheMaxBytes() int {
	if v := strings.TrimSpace(os.Getenv("VYQL_LOWER_TEXT_CACHE_MAX_BYTES")); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil && n >= 0 {
			return n
		}
	}
	return 64 * 1024
}

func (idx *flagMatchIndex) contextFacts(text string) *contextTokenFacts {
	if facts, ok := idx.tokenFacts.Load(text); ok {
		return facts.(*contextTokenFacts)
	}
	facts := &contextTokenFacts{
		byPrefix: map[string][]string{},
	}
	for start := 0; start <= len(text); {
		end := strings.IndexByte(text[start:], '\x00')
		var tok string
		if end < 0 {
			tok = text[start:]
			start = len(text) + 1
		} else {
			tok = text[start : start+end]
			start += end + 1
		}
		if tok == "" {
			continue
		}
		prefix, value, ok := splitContextTokenPredicateValue(tok)
		if !ok {
			continue
		}
		facts.byPrefix[prefix] = append(facts.byPrefix[prefix], value)
	}
	idx.tokenFacts.Store(text, facts)
	return facts
}

func (idx *flagMatchIndex) scopedHit(s usg.Store, kind string, pred flagPredicate, values []string, nodeTypes []string, n usg.Node, tech string, crossLang bool, allowUnscoped bool, match func(usg.Node) bool) bool {
	idx.ensure(s)
	file := locFile(n.Prop("loc"))
	scope := idx.normalizedScope(n)
	hits := idx.scopedPredicateHits(s, kind, pred, values, nodeTypes, file, tech, crossLang, match)
	return hits.matches(scope, n.ID, allowUnscoped)
}

func (idx *flagMatchIndex) scopedPredicateHits(s usg.Store, kind string, pred flagPredicate, values []string, nodeTypes []string, file string, tech string, crossLang bool, match func(usg.Node) bool) scopedPredicateHitSet {
	key := strings.Join([]string{
		kind,
		flagPredicateCacheKey(pred),
		strings.Join(values, "\x1f"),
		strings.Join(nodeTypes, "\x1f"),
		file,
		tech,
		strconv.FormatBool(crossLang),
	}, "\x1e")
	if cached, ok := idx.predHitSets.Load(key); ok {
		return cached.(scopedPredicateHitSet)
	}
	var out scopedPredicateHitSet
	addCandidate := func(cand usg.Node) {
		candScope := idx.normalizedScope(cand)
		out.totalCount++
		out.singleID = cand.ID
		if candScope == "" {
			out.unscopedCount++
			out.unscopedID = cand.ID
			return
		}
		if out.exactCounts == nil {
			out.exactCounts = map[string]scopeHitCount{}
		}
		count := out.exactCounts[candScope]
		if count.count == 0 {
			out.scopes = append(out.scopes, candScope)
		}
		count.count++
		count.singleID = cand.ID
		out.exactCounts[candScope] = count
	}
	if ids, ok := idx.scopeCallCandidateIDs(file, pred, nodeTypes); ok {
		for _, id := range ids {
			cand, ok := idx.node(s, id)
			if !ok {
				continue
			}
			if t := nodeTechFromNode(cand); !crossLang && t != "" && t != tech {
				continue
			}
			if match(cand) {
				addCandidate(cand)
			}
		}
		sort.Strings(out.scopes)
		idx.predHitSets.Store(key, out)
		return out
	}
	for _, nodeType := range nodeTypes {
		if kind == "binop" && nodeType == "code.BinOp" {
			idx.rangeBinopsInFileForValues(s, file, values, func(cand usg.Node) bool {
				if t := nodeTechFromNode(cand); !crossLang && t != "" && t != tech {
					return true
				}
				if !match(cand) {
					return true
				}
				addCandidate(cand)
				return true
			})
			continue
		}
		idx.rangeNodesOfTypeInFile(s, nodeType, file, func(cand usg.Node) bool {
			if t := nodeTechFromNode(cand); !crossLang && t != "" && t != tech {
				return true
			}
			if !match(cand) {
				return true
			}
			addCandidate(cand)
			return true
		})
	}
	sort.Strings(out.scopes)
	idx.predHitSets.Store(key, out)
	return out
}

func (idx *flagMatchIndex) scopeCallCandidateIDs(file string, pred flagPredicate, nodeTypes []string) ([]string, bool) {
	if len(nodeTypes) != 1 || nodeTypes[0] != "code.Call" || !scopeCallPredicateIndexable(pred) {
		return nil, false
	}
	byTerm := idx.callsByFileTerm[file]
	if len(byTerm) == 0 {
		return nil, true
	}
	seen := map[string]bool{}
	var out []string
	for _, value := range pred.Values {
		term := lowerString(strings.TrimSpace(value))
		for _, id := range byTerm[term] {
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
		if len(byTerm[term]) > 0 {
			continue
		}
		for got, ids := range byTerm {
			if !strings.Contains(got, term) {
				continue
			}
			for _, id := range ids {
				if seen[id] {
					continue
				}
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out, true
}

func (idx *flowTokenIndex) ensure(s usg.Store) {
	idx.once.Do(func() { idx.build(s) })
}

func (idx *flowTokenIndex) build(s usg.Store) {
	idx.rev = map[string][]string{}
	idx.fwd = map[string][]string{}
	rangeNodes(s, func(n usg.Node) bool {
		if rg, ok := s.(interface {
			RangeOutEdges(string, string, func(string) bool)
		}); ok {
			rg.RangeOutEdges(n.ID, "FLOWS", func(dst string) bool {
				idx.rev[dst] = append(idx.rev[dst], n.ID)
				idx.fwd[n.ID] = append(idx.fwd[n.ID], dst)
				return true
			})
			return true
		}
		edges, _ := s.OutEdges(n.ID, "FLOWS")
		for _, edge := range edges {
			idx.rev[edge.Dst] = append(idx.rev[edge.Dst], edge.Src)
			idx.fwd[n.ID] = append(idx.fwd[n.ID], edge.Dst)
		}
		return true
	})
}

type collectionFlowIndex struct {
	reachesSeq  map[string][]string
	reachesDone map[string]bool
	seqElements map[string]map[int]string
}

func (idx *collectionFlowIndex) seqsForArg(s usg.Store, argID string) []string {
	if argID == "" {
		return nil
	}
	if idx.reachesSeq == nil {
		idx.reachesSeq = map[string][]string{}
		idx.reachesDone = map[string]bool{}
	}
	if idx.reachesDone[argID] {
		return idx.reachesSeq[argID]
	}
	idx.reachesDone[argID] = true
	type item struct {
		id    string
		depth int
	}
	seen := map[string]bool{argID: true}
	q := []item{{id: argID}}
	for head := 0; head < len(q) && len(seen) < 64; head++ {
		cur := q[head]
		n, ok, err := s.GetNode(cur.id)
		if err == nil && ok && n.Type == "code.Seq" {
			idx.reachesSeq[argID] = append(idx.reachesSeq[argID], cur.id)
		}
		if cur.depth >= 4 {
			continue
		}
		rangeFlowIn(s, nil, cur.id, func(srcID string) bool {
			if seen[srcID] {
				return true
			}
			seen[srcID] = true
			q = append(q, item{id: srcID, depth: cur.depth + 1})
			return true
		})
	}
	return idx.reachesSeq[argID]
}

func (idx *collectionFlowIndex) elementForSeq(s usg.Store, seqID string, elemIndex int) string {
	if idx.seqElements == nil {
		idx.seqElements = map[string]map[int]string{}
	}
	if elems, ok := idx.seqElements[seqID]; ok {
		return elems[elemIndex]
	}
	elems := map[int]string{}
	rangeFlowIn(s, nil, seqID, func(srcID string) bool {
		elem, ok, err := s.GetNode(srcID)
		if err != nil || !ok || elem.Type != "code.CollectionElement" {
			return true
		}
		i, err := strconv.Atoi(elem.Prop("collection_index"))
		if err != nil {
			return true
		}
		elems[i] = srcID
		return true
	})
	idx.seqElements[seqID] = elems
	return elems[elemIndex]
}

func (idx *flagMatchIndex) scopedCallArgCandidate(cand, anchor usg.Node, tech string, crossLang bool) bool {
	scope := idx.normalizedScope(anchor)
	candScope := idx.normalizedScope(cand)
	if scope != "" && candScope != "" && !sameOrNestedNormalizedScope(candScope, scope) {
		return false
	}
	if prefix := locFile(anchor.Prop("loc")); prefix != "" && locFile(cand.Prop("loc")) != prefix {
		return false
	}
	if t := nodeTechFromNode(cand); !crossLang && t != "" && t != tech {
		return false
	}
	return true
}
