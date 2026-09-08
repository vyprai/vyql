package lowering

import (
	"strconv"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// Uncontrolled recursion is a shape nothing in the graph states. A function that re-enters
// itself -- directly, or through a sibling that calls it back -- descends once per level of
// whatever it is reading, and when the bytes come from a peer the peer chooses the depth. The
// two facts that decide whether that is a defect are the cycle itself and the budget that
// bounds it, and neither exists anywhere: a call to a function already on the stack is lowered
// like any other call, and the counter a guard compares against a ceiling is three statements
// the graph relates to nothing.
//
// This records both, per module, at the call sites that close a cycle:
//
//	analysis.recursion.cycle(cycle=mutual, depth_budget=absent, function=skip_group,
//	                         callee=skip_field, cycle_length=2)
//
// What the observation means is a rule's decision, as with every other analysis event. It
// states what was found and nothing more: a cycle among the module's own functions, and
// whether anything on that cycle -- or in a helper the cycle calls, which is where a budget
// usually lives -- tests a stored value against a ceiling.
//
// Three deliberate limits, each of which reads a shape as BOUNDED rather than inventing a
// finding:
//
//   - Cycles are found among the functions of ONE module. A cycle spanning files needs a
//     whole-program call graph the lowering does not keep, and incremental lowering caches
//     each module's nodes against that module's own content, so a fact derived from another
//     file's body would go stale without anything invalidating it.
//   - A budget is read from an `if`, never from a loop condition: `for (i = 0; i < n; i++)`
//     bounds an iteration, not a descent, and reading it as a budget would silence every
//     recursive walk written over a loop.
//   - The ceiling must be a stored value or a literal. `pos >= buf.len()` compares the input
//     against itself and is what an unbounded reader looks like, so a comparison against a
//     call result is not a budget.
const (
	analysisRecursionCyclePath   = "analysis.recursion.cycle"
	analysisRecursionCycleMethod = "cycle"
)

// maxRecursionCallees caps the callees recorded per function. A cycle is closed by one edge;
// a function with hundreds of distinct callees is a dispatch table, not a recursion, and the
// cap keeps the per-module state proportional to the module rather than to its call sites.
const maxRecursionCallees = 64

// recursionScan is the module-local call graph over the module's own functions, plus the
// depth-budget evidence each function carries. It lives for one module's pass 2 and is
// consumed at the end of it.
type recursionScan struct {
	fns   map[string]*recursionFunc
	order []string // insertion order, so the emitted observations are deterministic
}

type recursionFunc struct {
	// budget is the stored value an `if` in this function tests against a ceiling
	// ("self.recursion_level"), or "" when it tests none.
	budget  string
	callees []recursionCall
}

// recursionCall is the FIRST call site from one function to another in the same module. One
// site per pair is enough: the pair is what closes a cycle, and a second call to the same
// callee closes the same one.
type recursionCall struct {
	callee string // qual key of the callee
	node   string // the call node, so taint reaching the call reaches the observation
	loc    string
}

func (l *lowerer) recursionFacts(qual string) *recursionFunc {
	if l.recursion == nil {
		l.recursion = &recursionScan{fns: map[string]*recursionFunc{}}
	}
	f := l.recursion.fns[qual]
	if f == nil {
		f = &recursionFunc{}
		l.recursion.fns[qual] = f
		l.recursion.order = append(l.recursion.order, qual)
	}
	return f
}

// noteRecursionCall records a resolved call from the function being lowered to another
// function of the same module. Cross-module targets are dropped: see the file comment.
func (l *lowerer) noteRecursionCall(target *funcInfo, node, loc string) {
	if l.curFunc == "" || target == nil || node == "" || target.module != l.curModule {
		return
	}
	if target.name == "" {
		return
	}
	callee := funcQualKey(target)
	// A key more than one declaration registers under names none of them: an edge recorded
	// against it would claim a cycle through whichever was registered last. Both ends have to
	// be a single declaration for the edge to mean what it says.
	if len(l.funcOverloads[callee]) > 1 || len(l.funcOverloads[l.curFunc]) > 1 {
		return
	}
	f := l.recursionFacts(l.curFunc)
	if len(f.callees) >= maxRecursionCallees {
		return
	}
	for _, c := range f.callees {
		if c.callee == callee {
			return
		}
	}
	f.callees = append(f.callees, recursionCall{callee: callee, node: node, loc: loc})
}

// noteModuleLocalRecursionCall records the edge of a call the resolver could not settle but this
// module can: a call written on the enclosing object (or on nothing at all) naming a function
// this module declares exactly once. Resolution needs a name to be unique across the whole
// scan before it routes taint through a body, which is right for taint and too strict here --
// a crate with two `skip_group`s in different files leaves the recursive one unresolved, and
// the cycle it closes is inside one impl block either way. Nothing but this observation reads
// the edge, so no flow is created from a name-keyed guess.
func (l *lowerer) noteModuleLocalRecursionCall(callee nir.Expr, node, loc string) {
	if l.curFunc == "" || node == "" {
		return
	}
	name := ""
	switch c := callee.(type) {
	case nir.Name:
		name = c.ID
	case nir.Attr:
		if base, ok := c.Base.(nir.Name); ok && (base.ID == l.selfName || base.ID == "self" || base.ID == "this") {
			name = c.Attr
		}
	}
	if name == "" {
		return
	}
	if l.curClass != "" {
		if f := l.funcQual[l.curModule+"::"+l.curClass+"."+name]; f != nil {
			l.noteRecursionCall(f, node, loc)
			return
		}
	}
	if f := l.funcQual[l.curModule+"::"+name]; f != nil {
		l.noteRecursionCall(f, node, loc)
	}
}

// noteDepthBudgetCondition records that the function being lowered tests a stored value
// against a ceiling. One per function is all the cycle needs.
func (l *lowerer) noteDepthBudgetCondition(cond nir.Expr) {
	if l.curFunc == "" || cond == nil {
		return
	}
	if l.recursion != nil {
		if f := l.recursion.fns[l.curFunc]; f != nil && f.budget != "" {
			return
		}
	}
	if v, ok := thresholdCompare(cond); ok {
		l.recursionFacts(l.curFunc).budget = v
	}
}

// thresholdCompare answers whether an `if` condition tests a stored value against a ceiling,
// and names the value it tests. `depth > MAX_DEPTH`, `level >= 100` and
// `self.recursion_level >= self.recursion_limit` all are; `wire_type == EndGroup` is not (an
// equality is a case label, not a threshold) and neither is `pos < buf.len()` (a call result
// is whatever the input says, so comparing against it bounds nothing).
func thresholdCompare(e nir.Expr) (string, bool) {
	switch ex := e.(type) {
	case nir.Thru:
		return thresholdCompare(ex.Inner)
	case nir.Unary:
		return thresholdCompare(ex.Operand)
	case nir.BinOp:
		switch ex.Op {
		case "&&", "||", "and", "or":
			if v, ok := thresholdCompare(ex.Left); ok {
				return v, true
			}
			return thresholdCompare(ex.Right)
		case "<", "<=", ">", ">=":
			left, leftStored := storedValueName(ex.Left)
			right, rightStored := storedValueName(ex.Right)
			switch {
			case leftStored && (rightStored || isCeilingLiteral(ex.Right)):
				return left, true
			case rightStored && isCeilingLiteral(ex.Left):
				return right, true
			}
		}
	}
	return "", false
}

// storedValueName names a value held somewhere -- a variable, a parameter, a field -- as
// opposed to one a call computes.
func storedValueName(e nir.Expr) (string, bool) {
	switch ex := e.(type) {
	case nir.Thru:
		return storedValueName(ex.Inner)
	case nir.Name:
		return ex.ID, ex.ID != ""
	case nir.Attr:
		if ex.Path != "" {
			return ex.Path, true
		}
		return ex.Attr, ex.Attr != ""
	}
	return "", false
}

func isCeilingLiteral(e nir.Expr) bool {
	switch ex := e.(type) {
	case nir.Thru:
		return isCeilingLiteral(ex.Inner)
	case nir.Const:
		return true
	case nir.Unary: // a negative literal
		return isCeilingLiteral(ex.Operand)
	}
	return false
}

func shortFuncName(qual string) string {
	for i := len(qual) - 1; i >= 1; i-- {
		if qual[i] == ':' && qual[i-1] == ':' {
			return qual[i+1:]
		}
	}
	return qual
}

// emitRecursionCycles closes the module: every recorded call whose callee reaches the caller
// back lies on a cycle, and each such call site gets one observation. Called once per module,
// after its body is lowered and while its node-id namespace is still current.
func (l *lowerer) emitRecursionCycles() {
	scan := l.recursion
	l.recursion = nil
	if scan == nil {
		return
	}
	comp := scan.components()
	members := map[int][]string{}
	for _, qual := range scan.order {
		members[comp[qual]] = append(members[comp[qual]], qual)
	}
	budgets := map[int]string{}
	budgetKnown := map[int]bool{}
	for _, qual := range scan.order {
		f := scan.fns[qual]
		for _, c := range f.callees {
			if comp[c.callee] != comp[qual] {
				continue
			}
			id := comp[qual]
			if !budgetKnown[id] {
				budgets[id] = scan.budgetOf(members[id])
				budgetKnown[id] = true
			}
			kind := "mutual"
			if c.callee == qual {
				kind = "self"
			}
			state := "absent"
			if budgets[id] != "" {
				state = "present"
			}
			tokens := []string{
				"cycle=" + kind,
				"depth_budget=" + state,
				"function=" + shortFuncName(qual),
				"callee=" + shortFuncName(c.callee),
				"cycle_length=" + strconv.Itoa(len(members[id])),
			}
			if budgets[id] != "" {
				tokens = append(tokens, "budget="+budgets[id])
			}
			l.syntheticCall(analysisRecursionCyclePath, analysisRecursionCycleMethod, c.node, c.loc, tokens...)
		}
	}
}

// budgetOf answers what bounds a cycle: a threshold test written in one of its own functions,
// or one in a helper a member calls. The delegated form is the common one -- the counter and
// its ceiling live on the object, and the member calls the helper that compares them -- so a
// budget search that stopped at the cycle's own bodies would read every delegated guard as
// missing.
func (s *recursionScan) budgetOf(members []string) string {
	for _, qual := range members {
		if f := s.fns[qual]; f != nil && f.budget != "" {
			return f.budget
		}
	}
	for _, qual := range members {
		f := s.fns[qual]
		if f == nil {
			continue
		}
		for _, c := range f.callees {
			if callee := s.fns[c.callee]; callee != nil && callee.budget != "" {
				return callee.budget
			}
		}
	}
	return ""
}

// components assigns each function its strongly connected component (Tarjan, iterative: a
// module's call chains are as deep as its author wrote them, and the walk must not be).
func (s *recursionScan) components() map[string]int {
	const unvisited = -1
	index := map[string]int{}
	low := map[string]int{}
	onStack := map[string]bool{}
	comp := map[string]int{}
	var stack []string
	next, nComp := 0, 0

	type frame struct {
		node string
		edge int
	}
	for _, root := range s.order {
		if _, seen := index[root]; seen {
			continue
		}
		work := []frame{{node: root}}
		index[root], low[root] = next, next
		next++
		stack = append(stack, root)
		onStack[root] = true
		for len(work) > 0 {
			top := &work[len(work)-1]
			f := s.fns[top.node]
			advanced := false
			for f != nil && top.edge < len(f.callees) {
				callee := f.callees[top.edge].callee
				top.edge++
				if _, seen := index[callee]; !seen {
					if s.fns[callee] == nil { // a leaf: nothing leaves it, so no cycle runs through it
						index[callee], low[callee], comp[callee] = next, next, unvisited
						next++
						continue
					}
					index[callee], low[callee] = next, next
					next++
					stack = append(stack, callee)
					onStack[callee] = true
					work = append(work, frame{node: callee})
					advanced = true
					break
				}
				if onStack[callee] && low[top.node] > index[callee] {
					low[top.node] = index[callee]
				}
			}
			if advanced {
				continue
			}
			node := top.node
			work = work[:len(work)-1]
			if len(work) > 0 {
				parent := work[len(work)-1].node
				if low[parent] > low[node] {
					low[parent] = low[node]
				}
			}
			if low[node] == index[node] {
				for {
					m := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					onStack[m] = false
					comp[m] = nComp
					if m == node {
						break
					}
				}
				nComp++
			}
		}
	}
	// A function nothing recorded facts for gets a component of its own, so an edge into it
	// is never read as closing a cycle.
	for node, id := range comp {
		if id == unvisited {
			comp[node] = nComp
			nComp++
		}
	}
	return comp
}
