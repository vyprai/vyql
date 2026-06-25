package lowering

import (
	"errors"

	"github.com/vyprai/vyql/extract/nir"
	"github.com/vyprai/vyql/usg"
)

// Compact binary codec for the per-module lowering deltas. These are written to and read from
// the cache thousands of times per warm scan; gob's reflection + per-blob decoder setup made
// decoding the dominant cost of incremental lowering. The structs are all strings, string maps,
// bools, and small ints, so a length-prefixed encoding decodes several times faster and with far
// fewer allocations. The bytes are a cache VALUE (never hashed — the key is content+sigFP), so
// encoding order need not be deterministic, and a binary rebuild (execSalt) invalidates any
// older format automatically. Round-trip fidelity is gated by the graph-snapshot equivalence
// harness.

var errCorruptDelta = errors.New("lowering: corrupt cache delta")

// --- writer ---------------------------------------------------------------------------------

type bufWriter struct{ b []byte }

func (w *bufWriter) uvar(n int) {
	for n >= 0x80 {
		w.b = append(w.b, byte(n)|0x80)
		n >>= 7
	}
	w.b = append(w.b, byte(n))
}
func (w *bufWriter) str(s string) { w.uvar(len(s)); w.b = append(w.b, s...) }
func (w *bufWriter) smap(m map[string]string) {
	w.uvar(len(m))
	for k, v := range m {
		w.str(k)
		w.str(v)
	}
}
func (w *bufWriter) boolean(v bool) {
	if v {
		w.b = append(w.b, 1)
	} else {
		w.b = append(w.b, 0)
	}
}
func (w *bufWriter) strs(ss []string) {
	w.uvar(len(ss))
	for _, s := range ss {
		w.str(s)
	}
}
func (w *bufWriter) resultEntries(entries []nir.ResultEntry) {
	w.uvar(len(entries))
	for _, entry := range entries {
		w.strs(entry.Tokens)
	}
}
func (w *bufWriter) paramEntries(entries []nir.ParamEntry) {
	w.uvar(len(entries))
	for _, entry := range entries {
		w.str(entry.Param)
		w.strs(entry.Tokens)
	}
}

// --- reader (panics on overrun; callers recover into errCorruptDelta) -----------------------

type bufReader struct {
	b []byte
	i int
}

func (r *bufReader) uvar() int {
	var x int
	var s uint
	for {
		c := r.b[r.i]
		r.i++
		x |= int(c&0x7f) << s
		if c < 0x80 {
			return x
		}
		s += 7
	}
}
func (r *bufReader) str() string {
	n := r.uvar()
	s := string(r.b[r.i : r.i+n])
	r.i += n
	return s
}
func (r *bufReader) smap() map[string]string {
	n := r.uvar()
	if n == 0 {
		return nil
	}
	m := make(map[string]string, n)
	for j := 0; j < n; j++ {
		k := r.str()
		m[k] = r.str()
	}
	return m
}
func (r *bufReader) boolean() bool { v := r.b[r.i] == 1; r.i++; return v }

// writeNode/readNode (de)serialize a usg.Node including its inline loc/region/order fields.
func (w *bufWriter) node(n usg.Node) {
	w.str(n.ID)
	w.str(n.Type)
	w.str(n.Loc)
	w.str(n.Region)
	w.uvar(int(n.Order))
	w.boolean(n.HasOrder)
	w.str(n.Scope)
	w.smap(n.Props)
}

func (r *bufReader) node() usg.Node {
	return usg.Node{
		ID: r.str(), Type: r.str(), Loc: r.str(), Region: r.str(),
		Order: int32(r.uvar()), HasOrder: r.boolean(), Scope: r.str(), Props: r.smap(),
	}
}
func (r *bufReader) strs() []string {
	n := r.uvar()
	if n == 0 {
		return nil
	}
	out := make([]string, n)
	for j := 0; j < n; j++ {
		out[j] = r.str()
	}
	return out
}
func (r *bufReader) resultEntries() []nir.ResultEntry {
	n := r.uvar()
	if n == 0 {
		return nil
	}
	out := make([]nir.ResultEntry, n)
	for i := range out {
		out[i] = nir.ResultEntry{Tokens: r.strs()}
	}
	return out
}
func (r *bufReader) paramEntries() []nir.ParamEntry {
	n := r.uvar()
	if n == 0 {
		return nil
	}
	out := make([]nir.ParamEntry, n)
	for i := range out {
		out[i] = nir.ParamEntry{Param: r.str(), Tokens: r.strs()}
	}
	return out
}

// --- moduleDelta (pass 2 body sub-graph) ----------------------------------------------------

func encodeDelta(d *moduleDelta) []byte {
	w := &bufWriter{b: make([]byte, 0, 256)}
	w.uvar(len(d.Nodes))
	for _, n := range d.Nodes {
		w.node(n)
	}
	w.uvar(len(d.Edges))
	for _, e := range d.Edges {
		w.str(e.Type)
		w.str(e.Src)
		w.str(e.Dst)
		w.smap(e.Props)
	}
	w.uvar(len(d.Labels))
	for _, l := range d.Labels {
		w.str(l.NodeID)
		w.str(l.Label.Concept)
		p := l.Label.Provenance
		w.str(p.Extractor)
		w.str(p.Adapter)
		w.str(p.SourceRef)
		w.str(p.Confidence)
		w.str(p.Fidelity)
		w.smap(l.Label.Detail)
	}
	return w.b
}

func decodeDelta(raw []byte) (d *moduleDelta, err error) {
	defer func() {
		if recover() != nil {
			d, err = nil, errCorruptDelta
		}
	}()
	r := &bufReader{b: raw}
	d = &moduleDelta{}
	if n := r.uvar(); n > 0 {
		d.Nodes = make([]usg.Node, n)
		for i := range d.Nodes {
			d.Nodes[i] = r.node()
		}
	}
	if n := r.uvar(); n > 0 {
		d.Edges = make([]usg.Edge, n)
		for i := range d.Edges {
			d.Edges[i] = usg.Edge{Type: r.str(), Src: r.str(), Dst: r.str(), Props: r.smap()}
		}
	}
	if n := r.uvar(); n > 0 {
		d.Labels = make([]deltaLabel, n)
		for i := range d.Labels {
			nodeID := r.str()
			lbl := usg.Label{Concept: r.str()}
			lbl.Provenance = usg.Provenance{
				Extractor: r.str(), Adapter: r.str(), SourceRef: r.str(),
				Confidence: r.str(), Fidelity: r.str(),
			}
			lbl.Detail = r.smap()
			d.Labels[i] = deltaLabel{NodeID: nodeID, Label: lbl}
		}
	}
	return d, nil
}

// --- pass1Delta (signatures / symbol table) -------------------------------------------------

func encodePass1(d *pass1Delta) []byte {
	w := &bufWriter{b: make([]byte, 0, 256)}
	w.uvar(len(d.Nodes))
	for _, n := range d.Nodes {
		w.node(n)
	}
	w.uvar(len(d.Imports))
	for _, ie := range d.Imports {
		w.str(ie.Local)
		w.boolean(ie.IsModule)
		w.str(ie.Module)
		w.str(ie.Symbol)
	}
	w.uvar(len(d.Funcs))
	for _, f := range d.Funcs {
		w.str(f.Qual)
		w.str(f.Short)
		w.strs(f.ParamNames)
		w.smap(f.Params)
		w.smap(f.ParamTypes)
		w.str(f.Ret)
		w.str(f.Module)
		w.str(f.Cls)
		w.str(f.Name)
		w.paramEntries(f.ParamEntries)
		w.resultEntries(f.ResultEntries)
		w.boolean(f.Abstract)
	}
	w.strs(d.ClassQual)
	w.strs(d.ClassDefs)
	w.uvar(len(d.ClassFields))
	for _, cf := range d.ClassFields {
		w.str(cf.Key)
		w.str(cf.Field)
		w.str(cf.Type)
	}
	w.uvar(d.Counter)
	w.uvar(d.Order)
	return w.b
}

func decodePass1(raw []byte) (d *pass1Delta, err error) {
	defer func() {
		if recover() != nil {
			d, err = nil, errCorruptDelta
		}
	}()
	r := &bufReader{b: raw}
	d = &pass1Delta{}
	if n := r.uvar(); n > 0 {
		d.Nodes = make([]usg.Node, n)
		for i := range d.Nodes {
			d.Nodes[i] = r.node()
		}
	}
	if n := r.uvar(); n > 0 {
		d.Imports = make([]ieGob, n)
		for i := range d.Imports {
			d.Imports[i] = ieGob{Local: r.str(), IsModule: r.boolean(), Module: r.str(), Symbol: r.str()}
		}
	}
	if n := r.uvar(); n > 0 {
		d.Funcs = make([]fiGob, n)
		for i := range d.Funcs {
			d.Funcs[i] = fiGob{
				Qual: r.str(), Short: r.str(), ParamNames: r.strs(),
				Params: r.smap(), ParamTypes: r.smap(),
				Ret: r.str(), Module: r.str(), Cls: r.str(), Name: r.str(),
				ParamEntries: r.paramEntries(), ResultEntries: r.resultEntries(), Abstract: r.boolean(),
			}
		}
	}
	d.ClassQual = r.strs()
	d.ClassDefs = r.strs()
	if n := r.uvar(); n > 0 {
		d.ClassFields = make([]cfGob, n)
		for i := range d.ClassFields {
			d.ClassFields[i] = cfGob{Key: r.str(), Field: r.str(), Type: r.str()}
		}
	}
	d.Counter = r.uvar()
	d.Order = r.uvar()
	return d, nil
}
