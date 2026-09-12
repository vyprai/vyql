package solvers

import (
	"strings"

	"github.com/vyprai/vyql/internal/usg"
)

// StorageJoin answers "do these two operations act on one storage location?" for the
// pairs Reaches cannot decide.
//
// Reaches is the structured-CFG relation: region comparability plus program order. Every
// function has its own region root, so it is intraprocedural by construction — two
// operations in two functions are never on a path, whatever they do. That is the right
// answer when the pair is two unrelated operations, and the wrong one for the shape a
// double free actually takes: a function publishes an allocation into a caller-visible
// field and still releases its own alias of it, and a second function releases that
// field. The two releases name one pointer. Their regions say nothing about it, so a
// join computed from region order can never select the pair.
//
// This is the join by pointer identity. It reads the identity off the graph and admits a
// pair only with all of this evidence:
//
//   - the two nodes are in DIFFERENT functions — inside one function Reaches already
//     decides, including the disjoint-branch case this must not reopen;
//   - b acts on a FIELD READ: some code.Attr `o.f` reaches b through value flow;
//   - a's own function contains a field STORE writing the same field name f of an object
//     whose value-flow origin is shared with the object b read, so `o` is one object and
//     not merely two structs that happen to declare a field of that name;
//   - the store published a value, not a constant;
//   - and the value a acts on does not contradict that store (see mayBeStoredValue).
//
// It deliberately does not order the two: saying which function runs first needs a call
// graph the USG does not carry, and for a release-to-release pair the pair is the
// evidence on its own. Nor does it judge whether the alias is still live at the release —
// a field cleared before the release is a covering fact the rule layer already has
// vocabulary for (code.OwnerFieldClear sits on the `o->f = NULL` the frontend emits).
type StorageJoin struct {
	store usg.Store
	// storesByField indexes every field store in the graph by the field name it writes
	// and then by the function it is written in, so a lookup reaches one function's
	// stores directly instead of walking every store of that field name.
	storesByField map[string]map[string][]fieldStore
	built         bool
	back          map[string]map[string]bool
	origins       map[string]map[string]bool
	reads         map[string][]fieldRead
}

// fieldStore is one `base.field = value` write: the object written and the argument
// nodes carrying the values written. The function it is written in is the key it is
// indexed under, so it is not repeated here.
type fieldStore struct {
	base   string
	values []string
}

// storageJoinHops bounds every backward walk. Value flow reaches its origin in a handful
// of Arg/Call hops (`p = malloc(n); o->f = p; free(p)` is three), and a wider window buys
// only the accidental origins that unrelated values share.
const storageJoinHops = 8

// NewStorageJoin returns a join over store. The index is built on first use, so a scan
// whose order-rule pairs are all decided by region order pays nothing for it.
func NewStorageJoin(store usg.Store) *StorageJoin {
	return &StorageJoin{
		store:   store,
		back:    map[string]map[string]bool{},
		origins: map[string]map[string]bool{},
		reads:   map[string][]fieldRead{},
	}
}

// Joins reports whether a and b act on one storage location, in the direction "a acts on
// a value its function published into a field, b acts on a read of that field".
func (j *StorageJoin) Joins(aID, bID string) bool {
	if j == nil || aID == "" || bID == "" || aID == bID {
		return false
	}
	an, ok1, _ := j.store.GetNode(aID)
	bn, ok2, _ := j.store.GetNode(bID)
	if !ok1 || !ok2 {
		return false
	}
	aFunc, bFunc := funcRegion(an.Prop("region")), funcRegion(bn.Prop("region"))
	if aFunc == "" || bFunc == "" || aFunc == bFunc {
		return false
	}
	reads := j.fieldReads(bID)
	if len(reads) == 0 {
		return false
	}
	j.build()
	for _, read := range reads {
		for _, st := range j.storesByField[read.field][aFunc] {
			if !j.sameObject(st.base, read.bases) {
				continue
			}
			if j.mayBeStoredValue(aID, st) {
				return true
			}
		}
	}
	return false
}

// fieldRead is a `o.f` read whose value reaches the node being joined: the field name and
// the object nodes it was read from.
type fieldRead struct {
	field string
	bases []string
}

// fieldReads returns the field reads whose value flows into id.
func (j *StorageJoin) fieldReads(id string) []fieldRead {
	if r, ok := j.reads[id]; ok {
		return r
	}
	out := []fieldRead{}
	for src := range j.backward(id) {
		n, ok, err := j.store.GetNode(src)
		if err != nil || !ok || n.Type != "code.Attr" {
			continue
		}
		// the lowerer carries the attribute NAME on an Attr node's method property.
		field := n.Prop("method")
		if field == "" {
			continue
		}
		bases := j.operands(src, false)
		if len(bases) == 0 {
			continue
		}
		out = append(out, fieldRead{field: field, bases: bases})
	}
	j.reads[id] = out
	return out
}

// build indexes every field store in the graph. A field store is the Method-less call on
// a member that the frontends emit for `base.field = value`: its callee path names the
// field, its base flows in as the receiver and the written value as an argument.
//
// The index is built by streaming the store's nodes, not by materialising them: this
// runs mid-scan on a store that may be disk-backed under a memory ceiling, and every
// materialised node decodes its detail back into RAM beside the resident graph.
func (j *StorageJoin) build() {
	if j.built {
		return
	}
	j.built = true
	j.storesByField = map[string]map[string][]fieldStore{}
	note := func(n usg.Node) {
		if n.Type != "code.Call" || n.Prop("method") != "" {
			return
		}
		path := n.Prop("callee_path")
		i := strings.LastIndexByte(path, '.')
		if i <= 0 || i == len(path)-1 {
			return
		}
		values := j.operands(n.ID, true)
		bases := j.operands(n.ID, false)
		if len(values) == 0 || len(bases) != 1 {
			return
		}
		field := path[i+1:]
		byFunc := j.storesByField[field]
		if byFunc == nil {
			byFunc = map[string][]fieldStore{}
			j.storesByField[field] = byFunc
		}
		fn := funcRegion(n.Prop("region"))
		byFunc[fn] = append(byFunc[fn], fieldStore{base: bases[0], values: values})
	}
	if rs, ok := j.store.(interface{ RangeNodes(func(usg.Node) bool) }); ok {
		rs.RangeNodes(func(n usg.Node) bool { note(n); return true })
		return
	}
	nodes, err := j.store.AllNodes()
	if err != nil {
		return
	}
	for _, n := range nodes {
		note(n)
	}
}

// operands splits a node's incoming value flow: the code.Arg sources carry the operands,
// everything else is the receiver/base the expression was taken from.
func (j *StorageJoin) operands(id string, args bool) []string {
	edges, err := j.store.InEdges(id, "FLOWS")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range edges {
		n, ok, err := j.store.GetNode(e.Src)
		if err != nil || !ok {
			continue
		}
		if (n.Type == "code.Arg") == args {
			out = append(out, e.Src)
		}
	}
	return out
}

// sameObject reports whether the store's base and any of the read's bases are one object:
// the same node, or two nodes whose value flow meets at a common origin — which is what a
// caller handing the same `&sud` to a producer and to a destructor looks like.
func (j *StorageJoin) sameObject(base string, others []string) bool {
	origins := j.valueOrigins(base)
	for _, o := range others {
		if o == base {
			return true
		}
		if j.meets(o, origins) {
			return true
		}
	}
	return false
}

// mayBeStoredValue reports whether the value a acts on may be the value the store
// published. The store must have published a value rather than a constant; then either
// a's value shares an origin with it, or a has no value origin of its own at all.
//
// The second case is a deliberate may-alias, and it is the common one: the release of a
// published buffer is usually written at a shared cleanup label, and the success path
// nulls the local before jumping past it, so at the release the only origin left is that
// constant. An operand with no origin cannot contradict the store; an operand with a
// DIFFERENT origin does, and is rejected — which is what keeps a function that publishes
// one allocation and releases an unrelated second one out of the join.
func (j *StorageJoin) mayBeStoredValue(aID string, st fieldStore) bool {
	published := false
	for _, v := range st.values {
		if len(j.valueOrigins(v)) > 0 {
			published = true
			if j.meets(aID, j.valueOrigins(v)) {
				return true
			}
		}
	}
	return published && len(j.valueOrigins(aID)) == 0
}

// valueOrigins returns the nodes within reach of id that name a value: the plumbing
// (argument nodes) and the constants are dropped, because every zero-initialised struct
// and every size argument shares those and they name no allocation.
func (j *StorageJoin) valueOrigins(id string) map[string]bool {
	if o, ok := j.origins[id]; ok {
		return o
	}
	out := map[string]bool{}
	for o := range j.backward(id) {
		if o == id {
			continue
		}
		n, ok, err := j.store.GetNode(o)
		if err != nil || !ok || n.Type == "code.Const" || n.Type == "code.Arg" {
			continue
		}
		out[o] = true
	}
	j.origins[id] = out
	return out
}

// meets reports whether id's value origins intersect the given set.
func (j *StorageJoin) meets(id string, origins map[string]bool) bool {
	if len(origins) == 0 {
		return false
	}
	for o := range j.valueOrigins(id) {
		if origins[o] {
			return true
		}
	}
	return false
}

// backward returns id plus the nodes whose value reaches it within storageJoinHops.
func (j *StorageJoin) backward(id string) map[string]bool {
	if s, ok := j.back[id]; ok {
		return s
	}
	seen := map[string]bool{id: true}
	frontier := []string{id}
	for hop := 0; hop < storageJoinHops && len(frontier) > 0; hop++ {
		var next []string
		for _, cur := range frontier {
			edges, err := j.store.InEdges(cur, "FLOWS")
			if err != nil {
				continue
			}
			for _, e := range edges {
				if seen[e.Src] {
					continue
				}
				seen[e.Src] = true
				next = append(next, e.Src)
			}
		}
		frontier = next
	}
	j.back[id] = seen
	return seen
}

// funcRegion is the region of the enclosing function: the module segment plus the
// function segment, with any nested control regions dropped.
func funcRegion(region string) string {
	if region == "" {
		return ""
	}
	i := strings.IndexByte(region, '/')
	if i < 0 {
		return region
	}
	if k := strings.IndexByte(region[i+1:], '/'); k >= 0 {
		return region[:i+1+k]
	}
	return region
}
