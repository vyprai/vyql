package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

// Reaching definitions for the pointer cursors a C/C++ function walks its loops with.
const (
	ccCursorDefStraight    = "straight"
	ccCursorDefLoopCarried = "loop_carried"
	ccMaxLoopCursorTokens  = 256
)

func ccIsLoopKind(kind string) bool {
	switch kind {
	case "for_statement", "while_statement", "do_statement", "for_range_loop":
		return true
	}
	return false
}

// Reaching definitions for the pointer cursors a C/C++ function walks its loops
// with, emitted into the function-scope context.
//
// The context is a deduplicated, unordered token set, so `assign:p=base` says only
// that the function resets `p` somewhere — not whether that reset is the definition
// the loop reading through `p` actually sees. A cursor an earlier walk over the same
// range left one element past the end therefore spells exactly like one reset right
// before the loop that dereferences it, and the other half of the difference, a
// `for` header's own update clause, was not tokenized at all.
//
// ccLoopCursorTokens closes both, one token per (loop, cursor) pair:
//
//	loop_cursor:<var>:def=<straight|loop_carried>:step=<yes|no>
//
// `def` is where the definition of <var> reaching this loop's header comes from — a
// straight-line assignment on the path into the loop, or an earlier loop that
// assigned or advanced it. `step` is whether this loop assigns or advances <var>
// itself, in its own header or its body. `def=loop_carried:step=no` is the stale
// cursor: the loop reads through a pointer some earlier loop left it at and never
// re-establishes it. Because the pair rides in one token, the dedup that collapses
// two textually identical resets cannot collapse the two loops that see them.
//
// Each loop also emits `loop_update:<clause>` for its own `for` update clause, which
// no token previously recorded at all.
//
// The analysis is a source-order walk with a may-join: a definition a loop makes is
// loop-carried afterwards whether or not the loop was entered, and a branch that
// resets a cursor on one arm only does not clear that. It is deliberately not a
// fixpoint — a loop body is walked with the state at its header plus every cursor a
// loop nested inside it defines already marked loop-carried, which is the back edge's
// effect without iterating to reach it.
func (c *ccConv) ccLoopCursorTokens(body *tree_sitter.Node) []string {
	if body == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(tok string) {
		if tok == "" || seen[tok] || len(out) >= ccMaxLoopCursorTokens {
			return
		}
		seen[tok] = true
		out = append(out, tok)
	}
	var walk func(*tree_sitter.Node, map[string]string)
	walk = func(n *tree_sitter.Node, state map[string]string) {
		if n == nil || len(out) >= ccMaxLoopCursorTokens {
			return
		}
		kind := c.kind(n)
		switch {
		case ccIsLoopKind(kind):
			c.ccLoopCursorVisitLoop(n, state, add, walk)
			return
		case kind == "if_statement":
			walk(c.field(n, "condition"), state)
			then := ccCloneCursorState(state)
			walk(c.field(n, "consequence"), then)
			other := ccCloneCursorState(state)
			walk(c.field(n, "alternative"), other)
			ccJoinCursorStates(state, then, other)
			return
		case kind == "assignment_expression":
			walk(c.field(n, "right"), state)
			if name := c.ccCursorIdentifier(c.field(n, "left")); name != "" {
				state[name] = ccCursorDefStraight
				return
			}
			walk(c.field(n, "left"), state)
			return
		case kind == "init_declarator":
			walk(c.field(n, "value"), state)
			if name := c.declName(c.field(n, "declarator")); name != "" {
				state[name] = ccCursorDefStraight
			}
			return
		case kind == "update_expression":
			if name := c.ccCursorIdentifier(c.field(n, "argument")); name != "" {
				state[name] = ccCursorDefStraight
			}
			return
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch, state)
		}
	}
	walk(body, map[string]string{})
	return out
}

// ccLoopCursorVisitLoop emits this loop's facts, then walks its body under the state
// the back edge leaves, then applies the loop's definitions to the enclosing state.
func (c *ccConv) ccLoopCursorVisitLoop(n *tree_sitter.Node, state map[string]string,
	add func(string), walk func(*tree_sitter.Node, map[string]string)) {
	facts := c.ccLoopFacts(n)
	for _, name := range facts.derefs {
		kind, tracked := state[name]
		if !tracked {
			continue
		}
		step := "no"
		if facts.defined[name] {
			step = "yes"
		}
		add("loop_cursor:" + name + ":def=" + kind + ":step=" + step)
	}
	if update := c.field(n, "update"); update != nil {
		if text := compactCExprText(c.text(update)); text != "" {
			add("loop_update:" + text)
		}
	}
	// The back edge. Only a loop nested inside this one leaves a cursor behind: this
	// loop's own step, and any assignment its body makes, define the element the body
	// is meant to be looking at, not a leftover.
	inner := ccCloneCursorState(state)
	for name := range facts.nested {
		inner[name] = ccCursorDefLoopCarried
	}
	if body := c.field(n, "body"); body != nil {
		walk(body, inner)
	} else {
		for _, ch := range c.namedChildren(n) {
			walk(ch, inner)
		}
	}
	for name := range facts.defined {
		state[name] = ccCursorDefLoopCarried
	}
}

// ccLoopFacts is what one traversal of a loop reports about it.
type ccLoopFacts struct {
	// defined holds every name the loop assigns or advances, in its header or its
	// body. A store through a cursor (`*p = x`, `p->f = x`) defines what p points at,
	// not p, and so does not land here.
	defined map[string]bool
	// nested holds the subset of defined that a loop nested inside this one makes --
	// the definitions that survive an exited loop into the enclosing body.
	nested map[string]bool
	// derefs holds, in source order, the names read through as a pointer (`p->f`,
	// `*p`). `p[i]` is left out on purpose: an indexed read off a base pointer is the
	// idiom that does not depend on where a previous loop left the cursor.
	derefs []string
}

func (c *ccConv) ccLoopFacts(loop *tree_sitter.Node) ccLoopFacts {
	facts := ccLoopFacts{defined: map[string]bool{}, nested: map[string]bool{}}
	seen := map[string]bool{}
	var walk func(n *tree_sitter.Node, inNested bool)
	walk = func(n *tree_sitter.Node, inNested bool) {
		if n == nil {
			return
		}
		kind := c.kind(n)
		var defines, deref string
		switch kind {
		case "assignment_expression":
			defines = c.ccCursorIdentifier(c.field(n, "left"))
		case "init_declarator":
			defines = c.declName(c.field(n, "declarator"))
		case "update_expression":
			defines = c.ccCursorIdentifier(c.field(n, "argument"))
		case "field_expression":
			if c.text(c.field(n, "operator")) == "->" {
				deref = c.ccCursorIdentifier(c.field(n, "argument"))
			}
		case "pointer_expression":
			if c.unaryOp(n) == "*" {
				deref = c.ccCursorIdentifier(c.field(n, "argument"))
			}
		}
		if defines != "" {
			facts.defined[defines] = true
			if inNested {
				facts.nested[defines] = true
			}
		}
		if deref != "" && !seen[deref] {
			seen[deref] = true
			facts.derefs = append(facts.derefs, deref)
		}
		for _, ch := range c.namedChildren(n) {
			walk(ch, inNested || ccIsLoopKind(c.kind(ch)))
		}
	}
	walk(loop, false)
	return facts
}

func (c *ccConv) ccCursorIdentifier(n *tree_sitter.Node) string {
	if n == nil || c.kind(n) != "identifier" {
		return ""
	}
	return c.text(n)
}

func ccCloneCursorState(state map[string]string) map[string]string {
	out := make(map[string]string, len(state))
	for name, kind := range state {
		out[name] = kind
	}
	return out
}

// ccJoinCursorStates folds two branch states back into state. loop_carried wins: a
// cursor an earlier loop may still own is not re-established by a reset one arm makes.
func ccJoinCursorStates(state, a, b map[string]string) {
	for name, kind := range a {
		if other, ok := b[name]; ok && other != kind {
			state[name] = ccCursorDefLoopCarried
			continue
		}
		state[name] = kind
	}
	for name, kind := range b {
		if _, ok := a[name]; !ok {
			state[name] = kind
		}
	}
}
