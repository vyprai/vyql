package main

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/usg"
)

// graph-json is VyQL's structured CODE_MAPPER export: one cross-referenced document
// carrying functions[], call_edges[], findings[] (with ordered function-granular
// paths), and a concept→operation legend. It exposes what graph/resolve/trace already
// compute as text, in the shape VyPr's six CodeMapper tables ingest. Function/node ids
// are RUN-LOCAL (unique within one document); only finding.fp is stable across runs.

const gjSchemaVersion = "vyql.codemap/v1"

type gjDocument struct {
	SchemaVersion string       `json:"schema_version"`
	Tool          gjTool       `json:"tool"`
	CodeMap       gjCodeMap    `json:"code_map"`
	Functions     []gjFunction `json:"functions"`
	CallEdges     []gjCallEdge `json:"call_edges"`
	Findings      []gjFinding  `json:"findings"`
	Concepts      []gjConcept  `json:"concepts"`
}

type gjTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type gjCodeMap struct {
	Root          string   `json:"root"`
	Languages     []string `json:"languages"`
	FunctionCount int      `json:"function_count"`
	FindingCount  int      `json:"finding_count"`
}

// gjFunction is CodeFunction identity ONLY — no bodies (VyPr pulls source text from its
// own structural_functions after reconciling by file+line range).
type gjFunction struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	File        string  `json:"file"`
	LineStart   int     `json:"line_start"`
	LineEnd     *int    `json:"line_end"`
	Module      string  `json:"module"`
	Class       *string `json:"class"`
	IsRoute     bool    `json:"is_route"`
	IsValidator bool    `json:"is_validator"`
	HTTPMethod  *string `json:"http_method"` // null until route-extraction (#2) lands
	HTTPPath    *string `json:"http_path"`
}

// gjCallEdge is CodeCallEdge: resolved internal→internal only (both ends NOT NULL FKs).
type gjCallEdge struct {
	FromFunction string `json:"from_function"`
	ToFunction   string `json:"to_function"`
	CallLine     *int   `json:"call_line"`
	CalleePath   string `json:"callee_path"`
}

type gjFinding struct {
	Rule          string     `json:"rule"`
	Kind          string     `json:"kind"`  // taint | reach | assume | presence
	Scope         string     `json:"scope"` // function | module | unresolved (docs/21 §4)
	Severity      string     `json:"severity"`
	CWE           []string   `json:"cwe"`
	FP            string     `json:"fp"` // stable across runs — VyPr dedup + diff key
	Source        *gjSource  `json:"source"`
	Sink          *gjSink    `json:"sink"`
	PathFunctions []gjPathFn `json:"path_functions"`
	PathLength    int        `json:"path_length"`
	Confidence    string     `json:"confidence"`
	Witness       []gjHop    `json:"witness,omitempty"`
}

type gjSource struct {
	File            string  `json:"file"`
	Line            int     `json:"line"`
	FuncID          *string `json:"func_id"` // the entrypoint function
	Concept         string  `json:"concept"`
	SourceParamName *string `json:"source_param_name"`
	SourceType      *string `json:"source_type"`
	SourcePattern   *string `json:"source_pattern"`
}

type gjSink struct {
	File            string  `json:"file"`
	Line            int     `json:"line"`
	FuncID          *string `json:"func_id"` // sink_function = ENCLOSING fn, not the callee
	Concept         string  `json:"concept"`
	Operation       *string `json:"operation"` // VyPr SinkType enum, verbatim
	SinkDescription *string `json:"sink_description"`
}

type gjPathFn struct {
	FunctionID string `json:"function_id"`
	Position   int    `json:"position"`
}

type gjHop struct {
	Node    string  `json:"node"`
	File    string  `json:"file"`
	Line    int     `json:"line"`
	FuncID  *string `json:"func_id"`
	Concept string  `json:"concept,omitempty"`
}

type gjConcept struct {
	Concept   string  `json:"concept"`
	Operation *string `json:"operation"`
	Role      string  `json:"role"` // sink | source | presence
}

// buildGraphJSON assembles the export document from the lowered graph, the findings,
// and the per-rule meta (for CWE).
func buildGraphJSON(g usg.Store, all []*findings.Finding, ruleMeta map[string]map[string]any, root string) gjDocument {
	doc := gjDocument{
		SchemaVersion: gjSchemaVersion,
		Tool:          gjTool{Name: "VyQL", Version: version},
		Concepts:      conceptLegend(),
	}
	doc.Functions = exportFunctions(g)
	doc.CallEdges = exportCallEdges(g)
	doc.Findings = exportFindings(g, all, ruleMeta)
	doc.CodeMap = gjCodeMap{
		Root:          root,
		Languages:     exportLanguages(doc.Functions, all),
		FunctionCount: len(doc.Functions),
		FindingCount:  len(doc.Findings),
	}
	return doc
}

func exportFunctions(g usg.Store) []gjFunction {
	ids, _ := g.NodesOfType("code.Function")
	out := make([]gjFunction, 0, len(ids))
	for _, id := range ids {
		n, ok, _ := g.GetNode(id)
		if !ok {
			continue
		}
		file, line := splitLoc(n.Prop("loc"))
		fn := gjFunction{
			ID:          id,
			Name:        n.Prop("name"),
			File:        file,
			LineStart:   line,
			LineEnd:     endLine(n.Prop("end_loc")),
			Module:      n.Prop("module"),
			Class:       nilIfEmpty(n.Prop("class")),
			IsRoute:     n.Prop("is_route") == "true",
			IsValidator: n.Prop("is_validator") == "true",
			HTTPMethod:  nilIfEmpty(n.Prop("http_method")),
			HTTPPath:    nilIfEmpty(n.Prop("http_path")),
		}
		out = append(out, fn)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].LineStart < out[j].LineStart
	})
	return out
}

// exportCallEdges emits one edge per resolved caller→callee pair. A call is resolved
// (internal) when its arguments flow into a callee's Param nodes, or the callee's Return
// flows back into the call. External/unresolved calls (os.system, cur.execute) have
// neither and become sink_description strings, never edges.
func exportCallEdges(g usg.Store) []gjCallEdge {
	ids, _ := g.NodesOfType("code.Call")
	seen := map[string]bool{}
	out := []gjCallEdge{}
	for _, id := range ids {
		c, ok, _ := g.GetNode(id)
		if !ok {
			continue
		}
		from := c.Prop("func_id")
		if from == "" {
			continue // caller is module-level, not an internal function
		}
		callees := map[string]bool{}
		// callee Return flows back into this call
		for _, e := range inEdges(g, id) {
			if src, ok, _ := g.GetNode(e.Src); ok && src.Type == "code.Return" {
				if f := src.Prop("func_id"); f != "" {
					callees[f] = true
				}
			}
		}
		// this call's args flow into callee Params
		for i := 0; ; i++ {
			argID := c.Prop("arg" + strconv.Itoa(i))
			if argID == "" {
				break
			}
			for _, e := range outEdges(g, argID) {
				if dst, ok, _ := g.GetNode(e.Dst); ok && dst.Type == "code.Param" {
					if f := dst.Prop("func_id"); f != "" {
						callees[f] = true
					}
				}
			}
		}
		_, callLine := splitLoc(c.Prop("loc"))
		for to := range callees {
			key := from + "\x00" + to
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, gjCallEdge{
				FromFunction: from,
				ToFunction:   to,
				CallLine:     intPtr(callLine),
				CalleePath:   c.Prop("callee_path"),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FromFunction != out[j].FromFunction {
			return out[i].FromFunction < out[j].FromFunction
		}
		return out[i].ToFunction < out[j].ToFunction
	})
	return out
}

func exportFindings(g usg.Store, all []*findings.Finding, ruleMeta map[string]map[string]any) []gjFinding {
	out := make([]gjFinding, 0, len(all))
	for _, f := range all {
		gf := gjFinding{
			Rule:       f.RuleID,
			Kind:       mapKind(f.WitnessKind),
			Severity:   f.Severity,
			CWE:        cweOf(ruleMeta[f.RuleID]),
			FP:         f.Fingerprint(),
			Confidence: f.Confidence,
		}
		srcB, sinkB := sourceAndSink(f)
		if srcB != nil {
			file, line := splitLoc(srcB.Loc)
			gf.Source = &gjSource{
				File:          file,
				Line:          line,
				FuncID:        funcOf(g, srcB.NodeID),
				Concept:       srcB.Concept,
				SourceType:    nilIfEmpty(conceptSnake(srcB.Concept)),
				SourcePattern: calleePathOf(g, srcB.NodeID),
			}
		}
		if sinkB != nil {
			file, line := splitLoc(sinkB.Loc)
			gf.Sink = &gjSink{
				File:            file,
				Line:            line,
				FuncID:          funcOf(g, sinkB.NodeID),
				Concept:         sinkB.Concept,
				Operation:       sinkOperation(sinkB.Concept),
				SinkDescription: sinkDescription(g, sinkB.NodeID),
			}
		}
		gf.Witness, gf.PathFunctions = buildPath(g, f, sinkB)
		if gf.PathFunctions == nil {
			gf.PathFunctions = []gjPathFn{} // never null — VyPr path_length = len(path_functions), NOT NULL
		}
		gf.PathLength = len(gf.PathFunctions)
		// scope (docs/21 §4): the routing anchor has an enclosing function?
		// taint anchors on the source (→ entrypoint); presence/reach on the sink.
		// invariant: scope=="function" ⟺ anchor func_id != null. `unresolved` is
		// not yet distinguished from `module` (deferred — inline-handler modeling).
		gf.Scope = "module"
		switch gf.Kind {
		case "taint", "reach", "assume":
			if gf.Source != nil && gf.Source.FuncID != nil {
				gf.Scope = "function"
			}
		default: // presence
			if gf.Sink != nil && gf.Sink.FuncID != nil {
				gf.Scope = "function"
			}
		}
		out = append(out, gf)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FP < out[j].FP })
	return out
}

// buildPath produces the NIR-granular witness (run-local, for PoC) and the collapsed
// function-granular path (CodeDataflowFunction). For non-taint findings the witness
// holds step descriptions, not node ids, so the path is just the sink's function.
func buildPath(g usg.Store, f *findings.Finding, sinkB *findings.Binding) ([]gjHop, []gjPathFn) {
	if f.WitnessKind == "taint" && len(f.Witness) > 0 {
		var hops []gjHop
		var fnSeq []string
		for _, nid := range f.Witness {
			n, ok, _ := g.GetNode(nid)
			if !ok {
				continue
			}
			file, line := splitLoc(n.Prop("loc"))
			fid := funcOf(g, nid)
			hops = append(hops, gjHop{
				Node:    nid,
				File:    file,
				Line:    line,
				FuncID:  fid,
				Concept: firstConcept(g, nid),
			})
			if fid != nil {
				fnSeq = append(fnSeq, *fid)
			}
		}
		return hops, collapse(fnSeq)
	}
	// presence/reach/assume: function-granular path is just the sink's enclosing function
	if sinkB != nil {
		if fid := funcOf(g, sinkB.NodeID); fid != nil {
			return nil, []gjPathFn{{FunctionID: *fid, Position: 0}}
		}
	}
	return nil, nil
}

// collapse drops consecutive-duplicate function ids and numbers the result from 0.
func collapse(seq []string) []gjPathFn {
	var out []gjPathFn
	prev := ""
	for _, fid := range seq {
		if fid == prev {
			continue
		}
		out = append(out, gjPathFn{FunctionID: fid, Position: len(out)})
		prev = fid
	}
	return out
}

// --- small helpers -------------------------------------------------------

func sourceAndSink(f *findings.Finding) (src, sink *findings.Binding) {
	for i := range f.Bindings {
		b := &f.Bindings[i]
		switch b.Name {
		case "source":
			src = b
		case "sink":
			sink = b
		}
	}
	// presence/match rules name their single binding after the rule var, not "sink":
	// fall back to the last binding as the sink site.
	if sink == nil && len(f.Bindings) > 0 {
		sink = &f.Bindings[len(f.Bindings)-1]
	}
	return src, sink
}

func mapKind(witnessKind string) string {
	switch witnessKind {
	case "taint", "reach", "assume":
		return witnessKind
	default: // match, order
		return "presence"
	}
}

func funcOf(g usg.Store, nodeID string) *string {
	n, ok, _ := g.GetNode(nodeID)
	if !ok {
		return nil
	}
	return nilIfEmpty(n.Prop("func_id"))
}

func calleePathOf(g usg.Store, nodeID string) *string {
	n, ok, _ := g.GetNode(nodeID)
	if !ok {
		return nil
	}
	return nilIfEmpty(n.Prop("callee_path"))
}

// sinkDescription is the external callee at the sink site: either the sink node's own
// callee_path (when the sink IS the call) or the path of the Call its value flows into.
func sinkDescription(g usg.Store, nodeID string) *string {
	if p := calleePathOf(g, nodeID); p != nil {
		return p
	}
	for _, e := range outEdges(g, nodeID) {
		if dst, ok, _ := g.GetNode(e.Dst); ok && dst.Type == "code.Call" {
			if p := nilIfEmpty(dst.Prop("callee_path")); p != nil {
				return p
			}
		}
	}
	return nil
}

func firstConcept(g usg.Store, nodeID string) string {
	ls, _ := g.Labels(nodeID)
	if len(ls) > 0 {
		return ls[0].Concept
	}
	return ""
}

func outEdges(g usg.Store, src string) []usg.Edge {
	es, _ := g.OutEdges(src, "FLOWS")
	return es
}

func inEdges(g usg.Store, dst string) []usg.Edge {
	es, _ := g.InEdges(dst, "FLOWS")
	return es
}

func splitLoc(loc string) (string, int) {
	i := strings.LastIndex(loc, ":")
	if i < 0 {
		return loc, 0
	}
	line, _ := strconv.Atoi(loc[i+1:])
	return loc[:i], line
}

func endLine(endLoc string) *int {
	if endLoc == "" {
		return nil
	}
	_, line := splitLoc(endLoc)
	return intPtr(line)
}

// conceptSnake turns a "code.PascalName" concept into "pascal_name" snake_case for the
// best-effort source_type (strips the package prefix; pure string transform, no concept table).
func conceptSnake(concept string) string {
	s := strings.TrimPrefix(concept, "code.")
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func cweOf(m map[string]any) []string {
	if m == nil {
		return nil
	}
	switch v := m["cwe"].(type) {
	case []string:
		return v
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func exportLanguages(fns []gjFunction, all []*findings.Finding) []string {
	seen := map[string]bool{}
	var out []string
	add := func(file string) {
		if i := strings.LastIndex(file, "."); i >= 0 {
			ext := file[i+1:]
			if ext != "" && !seen[ext] {
				seen[ext] = true
				out = append(out, ext)
			}
		}
	}
	for _, fn := range fns {
		add(fn.File)
	}
	for _, f := range all {
		for _, b := range f.Bindings {
			file, _ := splitLoc(b.Loc)
			add(file)
		}
	}
	sort.Strings(out)
	return out
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func intPtr(i int) *int { return &i }

func sinkOperation(concept string) *string {
	if op, ok := sinkOps()[strings.TrimPrefix(concept, "code.")]; ok && op != "" {
		opCopy := op
		return &opCopy
	}
	return nil
}

// sinkOps maps a sink concept (short name) to its VyPr SinkType enum value. This is the
// VyQL↔VyPr export contract (docs/21), kept as DATA (vyql/exports/sink_operations.tsv) and
// loaded at runtime so the cmd binary hardcodes no ontology/domain knowledge. Loaded once.
var (
	sinkOpsOnce sync.Once
	sinkOpsData map[string]string
)

func sinkOps() map[string]string {
	sinkOpsOnce.Do(func() {
		sinkOpsData = map[string]string{}
		data, err := os.ReadFile(filepath.Join(datadir.Root(), "exports", "sink_operations.tsv"))
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if k, v, ok := strings.Cut(line, "\t"); ok {
				sinkOpsData[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	})
	return sinkOpsData
}

// conceptLegend enumerates the operational (code.*) concepts with their export role and,
// for sinks, the VyPr SinkType operation. Built from the live ontology plus the sink-operation
// data, so no concept names are hardcoded in the cmd runtime.
func conceptLegend() []gjConcept {
	ops := sinkOps()
	concepts := ontology.Seed().AllConcepts()
	out := make([]gjConcept, 0, len(concepts))
	for _, c := range concepts {
		if c.Package != "code" {
			continue
		}
		gc := gjConcept{Concept: c.QualifiedName(), Role: "presence"}
		if op, ok := ops[c.Name]; ok && op != "" {
			opCopy := op
			gc.Role = "sink"
			gc.Operation = &opCopy
		} else if c.Kind == "source" {
			gc.Role = "source"
		}
		out = append(out, gc)
	}
	return out
}
