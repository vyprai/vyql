// Package graphjson renders a scan as the graph-json export document: the functions and
// call edges the scan resolved, each finding's source, sink and witness path, and the
// concept legend that explains the labels.
//
// It is graph-query work -- collapsing a witness path into the functions it crosses,
// inferring a scope, extracting call edges -- and it lived in package main, where none of
// it could be exercised without the command.
package graphjson

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/findings"
	"github.com/vyprai/vyql/internal/ontology"
	"github.com/vyprai/vyql/internal/resultpolicy"
	"github.com/vyprai/vyql/internal/usg"
)

// graph-json is VyQL's structured CODE_MAPPER export: one cross-referenced document
// carrying functions[], call_edges[], findings[] (with ordered function-granular
// paths), and a concept→operation legend. It exposes what graph/resolve/trace already
// compute as text, in the shape VyPr's six CodeMapper tables ingest. Function/node ids
// are RUN-LOCAL (unique within one document); only finding.fp is stable across runs.

const SchemaVersion = "vyql.codemap/v1"

type Document struct {
	SchemaVersion string     `json:"schema_version"`
	Tool          Tool       `json:"tool"`
	CodeMap       CodeMap    `json:"code_map"`
	Functions     []Function `json:"functions"`
	CallEdges     []CallEdge `json:"call_edges"`
	Findings      []Finding  `json:"findings"`
	Concepts      []Concept  `json:"concepts"`
}

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CodeMap struct {
	Root          string   `json:"root"`
	Languages     []string `json:"languages"`
	FunctionCount int      `json:"function_count"`
	FindingCount  int      `json:"finding_count"`
}

// Function is CodeFunction identity ONLY — no bodies (VyPr pulls source text from its
// own structural_functions after reconciling by file+line range).
type Function struct {
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

// CallEdge is CodeCallEdge: resolved internal→internal only (both ends NOT NULL FKs).
type CallEdge struct {
	FromFunction string `json:"from_function"`
	ToFunction   string `json:"to_function"`
	CallLine     *int   `json:"call_line"`
	CalleePath   string `json:"callee_path"`
}

type Finding struct {
	Rule          string   `json:"rule"`
	Kind          string   `json:"kind"`  // taint | reach | assume | presence
	Scope         string   `json:"scope"` // function | module | unresolved
	Severity      string   `json:"severity"`
	CWE           []string `json:"cwe"`
	FP            string   `json:"fp"` // stable across runs — VyPr dedup + diff key
	Source        *Source  `json:"source"`
	Sink          *Sink    `json:"sink"`
	PathFunctions []PathFn `json:"path_functions"`
	PathLength    int      `json:"path_length"`
	Confidence    string   `json:"confidence"`
	Witness       []Hop    `json:"witness,omitempty"`
}

type Source struct {
	File            string  `json:"file"`
	Line            int     `json:"line"`
	FuncID          *string `json:"func_id"` // the entrypoint function
	Concept         string  `json:"concept"`
	SourceParamName *string `json:"source_param_name"`
	SourceType      *string `json:"source_type"`
	SourcePattern   *string `json:"source_pattern"`
}

type Sink struct {
	File            string  `json:"file"`
	Line            int     `json:"line"`
	FuncID          *string `json:"func_id"` // sink_function = ENCLOSING fn, not the callee
	Concept         string  `json:"concept"`
	Operation       *string `json:"operation"` // VyPr SinkType enum, verbatim
	SinkDescription *string `json:"sink_description"`
}

type PathFn struct {
	FunctionID string `json:"function_id"`
	Position   int    `json:"position"`
}

type Hop struct {
	Node    string  `json:"node"`
	File    string  `json:"file"`
	Line    int     `json:"line"`
	FuncID  *string `json:"func_id"`
	Concept string  `json:"concept,omitempty"`
}

type Concept struct {
	Concept   string  `json:"concept"`
	Operation *string `json:"operation"`
	Role      string  `json:"role"` // sink | source | presence
}

// Build assembles the export document from the lowered graph, the findings,
// and the per-rule meta (for CWE).
func Build(g usg.Store, all []*findings.Finding, ruleMeta map[string]map[string]any, root, toolVersion string) Document {
	doc := Document{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: "VyQL", Version: toolVersion},
		Concepts:      ConceptLegend(),
	}
	doc.Functions = exportFunctions(g)
	doc.CallEdges = exportCallEdges(g)
	doc.Findings = exportFindings(g, all, ruleMeta)
	doc.CodeMap = CodeMap{
		Root:          root,
		Languages:     exportLanguages(doc.Functions, all),
		FunctionCount: len(doc.Functions),
		FindingCount:  len(doc.Findings),
	}
	return doc
}

// boundary is what lowering records about a function beyond its region: the
// declaration line and the authored name.
//
// A function's entry and exit are nodes whose ids encode the name --
// "<module><name>#ret#" and "<module><name>#param#<arg>" -- and whose loc is the
// declaration line. They carry no region themselves, so each is attributed to the
// function through a neighbour that does: a Return is fed from inside the
// function, and a Param feeds into it.
type boundary struct {
	name string
	line int
}

// functionBoundaries returns what each function's boundary nodes say about it,
// and which function each boundary node belongs to. Both come from the same walk:
// the second is what lets a call edge name a region at both ends.
func functionBoundaries(g usg.Store, nodes []usg.Node) (map[string]boundary, map[string]string) {
	out := map[string]boundary{}
	ownerOf := map[string]string{}
	note := func(region, id, loc string) {
		if region == "" {
			return
		}
		name := boundaryName(region, id)
		if name == "" {
			return
		}
		ownerOf[id] = region
		_, line := splitLoc(loc)
		// A Return names the function and sits on its declaration line. Prefer it
		// over a Param, which names the same function but may be one of several.
		if prev, ok := out[region]; ok && prev.line != 0 && line == 0 {
			return
		}
		out[region] = boundary{name: name, line: line}
	}
	for _, n := range nodes {
		if n.Prop("region") != "" {
			continue // inside a function, not one of its boundaries
		}
		switch n.Type {
		case "code.Return":
			for _, e := range inEdges(g, n.ID) {
				if src, ok, _ := g.GetNode(e.Src); ok {
					note(src.Prop("region"), n.ID, n.Prop("loc"))
				}
			}
		case "code.Param":
			for _, e := range outEdges(g, n.ID) {
				if dst, ok, _ := g.GetNode(e.Dst); ok {
					note(dst.Prop("region"), n.ID, n.Prop("loc"))
				}
			}
		}
	}
	return out, ownerOf
}

// boundaryName recovers the authored name from a boundary node id. The id is the
// module, a unit separator, the name, then a "#ret#" or "#param#<arg>" marker; the
// module is the half of the region before the slash.
func boundaryName(region, id string) string {
	module, _, ok := strings.Cut(region, "/")
	if !ok {
		return ""
	}
	rest, ok := strings.CutPrefix(id, module)
	if !ok {
		return ""
	}
	rest = strings.TrimPrefix(rest, idSeparator)
	if i := strings.Index(rest, "#"); i >= 0 {
		return rest[:i]
	}
	return ""
}

// idSeparator divides the module from the rest of a node id.
const idSeparator = "\x1f"

// exportFunctions derives the function inventory from the region every node
// carries, because lowering does not emit a function node.
//
// A region is "<module>/<function>" and is the only representation of a function
// that every frontend produces: Python emits no function node at all, and the
// JavaScript frontend emits code.Func only for a function expression. Asking for a
// node type reported no functions for any scan, in every language.
//
// The line span runs from the declaration, which a boundary node carries, to the
// last line of the body. Lowering records no end line.
func exportFunctions(g usg.Store) []Function {
	nodes, err := g.AllNodes()
	if err != nil {
		return []Function{}
	}
	bounds, _ := functionBoundaries(g, nodes)
	type span struct {
		file, module, class string
		first, last         int
		haveFirst           bool
	}
	spans := map[string]*span{}
	for _, n := range nodes {
		region := n.Prop("region")
		if region == "" {
			continue // module level, not inside a function
		}
		sp := spans[region]
		if sp == nil {
			sp = &span{}
			spans[region] = sp
		}
		if m := n.Prop("module"); m != "" && sp.module == "" {
			sp.module = m
		}
		if c := n.Prop("class"); c != "" && sp.class == "" {
			sp.class = c
		}
		file, line := splitLoc(n.Prop("loc"))
		if file != "" && sp.file == "" {
			sp.file = file
		}
		if line == 0 {
			continue
		}
		if !sp.haveFirst || line < sp.first {
			sp.first, sp.haveFirst = line, true
		}
		if line > sp.last {
			sp.last = line
		}
	}
	out := make([]Function, 0, len(spans))
	for region, sp := range spans {
		name, start := functionName(region), sp.first
		if b, ok := bounds[region]; ok {
			// The authored name, and the declaration line rather than the first
			// line of the body.
			name = b.name
			if b.line != 0 && b.line < start {
				start = b.line
			}
		}
		// Without a boundary node the name falls back to the region's own segment,
		// which is an ordinal rather than what the source calls it. A function
		// listed under a synthetic name is still located correctly by file and
		// line; one left out of the list is invisible.
		module := sp.module
		if module == "" {
			// Nodes carry no module property, so it is the half of the region
			// before the slash -- which is where the region gets it.
			module, _, _ = strings.Cut(region, "/")
		}
		out = append(out, Function{
			ID:        region,
			Name:      name,
			File:      sp.file,
			LineStart: start,
			LineEnd:   spanEnd(start, sp.last),
			Module:    module,
			Class:     nilIfEmpty(sp.class),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].LineStart != out[j].LineStart {
			return out[i].LineStart < out[j].LineStart
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// functionName is the last segment of a region. A region is "<module>/<function>",
// and the module half travels in its own field.
func functionName(region string) string {
	if i := strings.LastIndex(region, "/"); i >= 0 {
		return region[i+1:]
	}
	return region
}

// spanEnd omits the end of a single-line span, which says nothing the start does
// not.
func spanEnd(first, last int) *int {
	if last <= first {
		return nil
	}
	return intPtr(last)
}

// exportCallEdges emits one edge per resolved caller→callee pair. A call is resolved
// (internal) when its arguments flow into a callee's Param nodes, or the callee's Return
// flows back into the call. External/unresolved calls (os.system, cur.execute) have
// neither and become sink_description strings, never edges.
func exportCallEdges(g usg.Store) []CallEdge {
	ids, _ := g.NodesOfType("code.Call")
	seen := map[string]bool{}
	out := []CallEdge{}
	// A boundary node carries no region of its own, so the function it belongs to
	// is found the same way exportFunctions finds it. Both ends of an edge are
	// then regions, which is what the function list is keyed by -- an edge naming
	// anything else would point at a function the document does not contain.
	regionOf := map[string]string{}
	if nodes, err := g.AllNodes(); err == nil {
		_, regionOf = functionBoundaries(g, nodes)
	}
	owner := func(n usg.Node) string {
		if r := n.Prop("region"); r != "" {
			return r
		}
		return regionOf[n.ID]
	}
	for _, id := range ids {
		c, ok, _ := g.GetNode(id)
		if !ok {
			continue
		}
		// The caller is the region the call sits in. Nothing sets a func_id
		// property, so reading one skipped every call and emitted no edges at all.
		from := c.Prop("region")
		if from == "" {
			continue // caller is module-level, not an internal function
		}
		callees := map[string]bool{}
		// callee Return flows back into this call
		for _, e := range inEdges(g, id) {
			if src, ok, _ := g.GetNode(e.Src); ok && src.Type == "code.Return" {
				if f := owner(src); f != "" && f != from {
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
					if f := owner(dst); f != "" && f != from {
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
			out = append(out, CallEdge{
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

func exportFindings(g usg.Store, all []*findings.Finding, ruleMeta map[string]map[string]any) []Finding {
	out := make([]Finding, 0, len(all))
	for _, f := range all {
		gf := Finding{
			Rule:       f.RuleID,
			Kind:       mapKind(f.WitnessKind),
			Severity:   f.Severity,
			CWE:        cweOf(ruleMeta[f.RuleID]),
			FP:         resultpolicy.Fingerprint(f),
			Confidence: f.Confidence,
		}
		srcB, sinkB := sourceAndSink(f)
		if srcB != nil {
			file, line := splitLoc(srcB.Loc)
			gf.Source = &Source{
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
			gf.Sink = &Sink{
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
			gf.PathFunctions = []PathFn{} // never null — VyPr path_length = len(path_functions), NOT NULL
		}
		gf.PathLength = len(gf.PathFunctions)
		// scope: the routing anchor has an enclosing function?
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
func buildPath(g usg.Store, f *findings.Finding, sinkB *findings.Binding) ([]Hop, []PathFn) {
	if f.WitnessKind == "taint" && len(f.Witness) > 0 {
		var hops []Hop
		var fnSeq []string
		for _, nid := range f.Witness {
			n, ok, _ := g.GetNode(nid)
			if !ok {
				continue
			}
			file, line := splitLoc(n.Prop("loc"))
			fid := funcOf(g, nid)
			hops = append(hops, Hop{
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
			return nil, []PathFn{{FunctionID: *fid, Position: 0}}
		}
	}
	return nil, nil
}

// collapse drops consecutive-duplicate function ids and numbers the result from 0.
func collapse(seq []string) []PathFn {
	var out []PathFn
	prev := ""
	for _, fid := range seq {
		if fid == prev {
			continue
		}
		out = append(out, PathFn{FunctionID: fid, Position: len(out)})
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

func exportLanguages(fns []Function, all []*findings.Finding) []string {
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

// sinkOps maps a sink concept (short name) to its downstream SinkType enum value. The
// mapping is kept as DATA (the data directory's exports/sink_operations.tsv) and loaded
// at runtime, so this binary hardcodes no ontology or domain knowledge. Loaded once; an
// absent file leaves the mapping empty.
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

// ConceptLegend enumerates the operational (code.*) concepts with their export role and,
// for sinks, the VyPr SinkType operation. Built from the live ontology plus the sink-operation
// data, so no concept names are hardcoded in the cmd runtime.
func ConceptLegend() []Concept {
	ops := sinkOps()
	concepts := ontology.Seed().AllConcepts()
	out := make([]Concept, 0, len(concepts))
	for _, c := range concepts {
		if c.Package != "code" {
			continue
		}
		gc := Concept{Concept: c.QualifiedName(), Role: "presence"}
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
