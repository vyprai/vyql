package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

const pyContextAssignmentFlowFactLimit = 64

// pyAssignmentFlowState is a bounded, function-local may-flow state. origins tracks
// values loaded from a server store or a request path; replacements remembers when
// a request value overwrote a server-loaded variable; truthy records branch facts
// needed to prune selected paths that terminate before a later operation.
type pyAssignmentFlowState struct {
	origins      map[string]string
	replacements map[string]string
	truthy       map[string]bool
}

type pyAssignmentFlowAnalyzer struct {
	c     *pyConv
	facts []string
	seen  map[string]bool
}

func (c *pyConv) pyAssignmentFlowFacts(body *tree_sitter.Node) []string {
	analyzer := &pyAssignmentFlowAnalyzer{c: c, seen: map[string]bool{}}
	analyzer.visitBlock(body, newPyAssignmentFlowState())
	return analyzer.facts
}

func newPyAssignmentFlowState() pyAssignmentFlowState {
	return pyAssignmentFlowState{
		origins:      map[string]string{},
		replacements: map[string]string{},
		truthy:       map[string]bool{},
	}
}

func clonePyAssignmentFlowState(state pyAssignmentFlowState) pyAssignmentFlowState {
	clone := newPyAssignmentFlowState()
	for name, source := range state.origins {
		clone.origins[name] = source
	}
	for name, source := range state.replacements {
		clone.replacements[name] = source
	}
	for name, truthy := range state.truthy {
		clone.truthy[name] = truthy
	}
	return clone
}

func joinPyAssignmentFlowStates(states []pyAssignmentFlowState) pyAssignmentFlowState {
	joined := newPyAssignmentFlowState()
	for _, state := range states {
		for name, source := range state.origins {
			current := joined.origins[name]
			if current == "" || current == "session" && source != "session" {
				joined.origins[name] = source
			}
		}
		for name, source := range state.replacements {
			if joined.replacements[name] == "" {
				joined.replacements[name] = source
			}
		}
		for name, truthy := range state.truthy {
			if truthy {
				joined.truthy[name] = true
			}
		}
	}
	return joined
}

func (a *pyAssignmentFlowAnalyzer) addFact(fact string) {
	if fact == "" || a.seen[fact] || len(a.facts) >= pyContextAssignmentFlowFactLimit {
		return
	}
	a.seen[fact] = true
	a.facts = append(a.facts, fact)
}

func (a *pyAssignmentFlowAnalyzer) visitBlock(block *tree_sitter.Node, state pyAssignmentFlowState) (pyAssignmentFlowState, bool) {
	if block == nil {
		return state, true
	}
	for _, statement := range pyContextStatements(block) {
		if len(a.facts) >= pyContextAssignmentFlowFactLimit {
			return state, true
		}
		if pyIsNestedContextScope(statement) {
			continue
		}

		a.recordCallsOutsideBlocks(statement, state)
		if statement.Kind() == "if_statement" {
			condition := field(statement, "condition")
			blocks := pyDirectContextBlocks(statement)
			if len(blocks) == 0 {
				continue
			}
			if a.conditionDefinitelyTrue(condition, state) {
				branch := clonePyAssignmentFlowState(state)
				a.recordTruthyCondition(condition, &branch)
				var alive bool
				state, alive = a.visitBlock(blocks[0], branch)
				if !alive {
					return state, false
				}
				continue
			}

			var surviving []pyAssignmentFlowState
			thenState := clonePyAssignmentFlowState(state)
			a.recordTruthyCondition(condition, &thenState)
			if result, alive := a.visitBlock(blocks[0], thenState); alive {
				surviving = append(surviving, result)
			}
			if pyContextIfHasAlternative(statement) {
				for _, alternative := range blocks[1:] {
					if result, alive := a.visitBlock(alternative, clonePyAssignmentFlowState(state)); alive {
						surviving = append(surviving, result)
					}
				}
			} else {
				surviving = append(surviving, clonePyAssignmentFlowState(state))
			}
			if len(surviving) == 0 {
				return state, false
			}
			state = joinPyAssignmentFlowStates(surviving)
			continue
		}

		if assignment := pyDirectContextAssignment(statement); assignment != nil {
			a.recordStoreFlow(assignment, state)
			a.updateAssignment(assignment, &state)
		}
		if _, terminal := a.c.pyUnconditionalTerminalKind(statement); terminal {
			return state, false
		}

		blocks := pyDirectContextBlocks(statement)
		if len(blocks) > 0 {
			surviving := []pyAssignmentFlowState{clonePyAssignmentFlowState(state)}
			for _, nested := range blocks {
				if result, alive := a.visitBlock(nested, clonePyAssignmentFlowState(state)); alive {
					surviving = append(surviving, result)
				}
			}
			state = joinPyAssignmentFlowStates(surviving)
		}
	}
	return state, true
}

func pyContextIfHasAlternative(statement *tree_sitter.Node) bool {
	if statement == nil {
		return false
	}
	for _, child := range namedChildren(statement) {
		if child.Kind() == "elif_clause" || child.Kind() == "else_clause" {
			return true
		}
	}
	return false
}

func (a *pyAssignmentFlowAnalyzer) recordCallsOutsideBlocks(statement *tree_sitter.Node, state pyAssignmentFlowState) {
	root := statement
	var walk func(*tree_sitter.Node)
	walk = func(node *tree_sitter.Node) {
		if node == nil || len(a.facts) >= pyContextAssignmentFlowFactLimit {
			return
		}
		if node != root && (node.Kind() == "block" || pyIsNestedContextScope(node)) {
			return
		}
		if node.Kind() == "call" {
			path := pyContextEvidenceCompact(a.c.dotted(field(node, "function")))
			operation := pyAssignmentFlowOperation(path)
			if operation != "" {
				args := pyCallArgumentsText(a.c, node)
				for _, target := range a.c.pyBoundedContextIdentifiers(field(node, "arguments"), pyContextUsesPerOperationLimit) {
					if source := state.replacements[target]; source != "" {
						a.addFact("assignment_flow_reaches_operation:source_category=request;source=" + source +
							";previous_source=session;operation_category=query;operation=" + operation +
							";target=" + pyContextEvidenceCompact(target) +
							";args=" + args + ";callee=" + path)
					}
				}
			}
		}
		for _, child := range namedChildren(node) {
			walk(child)
		}
	}
	walk(statement)
}

func pyAssignmentFlowOperation(path string) string {
	switch {
	case path == "query.get" || strings.HasSuffix(path, ".query.get"):
		return "query.get"
	case path == "query.get_or_404" || strings.HasSuffix(path, ".query.get_or_404"):
		return "query.get_or_404"
	case path == "query.filter_by" || strings.HasSuffix(path, ".query.filter_by"):
		return "query.filter_by"
	case path == "query.filter" || strings.HasSuffix(path, ".query.filter"):
		return "query.filter"
	default:
		return ""
	}
}

func (a *pyAssignmentFlowAnalyzer) recordStoreFlow(assignment *tree_sitter.Node, state pyAssignmentFlowState) {
	left, right := field(assignment, "left"), field(assignment, "right")
	if left == nil || left.Kind() != "subscript" || right == nil {
		return
	}
	store := pyContextEvidenceCompact(a.c.dotted(field(left, "value")))
	if store != "session" && !strings.HasSuffix(store, ".session") {
		return
	}
	source := a.expressionSource(right, state)
	if !pyAssignmentFlowRequestSource(source) {
		return
	}
	key := pyContextValue(a.c.text(field(left, "subscript")))
	a.addFact("assignment_flow_reaches_store:source_category=request;store=session;source=" + source +
		";key=" + pyContextEvidenceCompact(key) +
		";value=" + pyContextEvidenceCompact(a.c.text(right)))
}

func (a *pyAssignmentFlowAnalyzer) updateAssignment(assignment *tree_sitter.Node, state *pyAssignmentFlowState) {
	left, right := field(assignment, "left"), field(assignment, "right")
	if left == nil || left.Kind() != "identifier" {
		return
	}
	target := a.c.text(left)
	previous := state.origins[target]
	source := a.expressionSource(right, *state)
	replacementSource := a.expressionReplacementSource(right, *state)
	rightTruthy := a.expressionDefinitelyTruthy(right, *state)
	delete(state.origins, target)
	delete(state.replacements, target)
	delete(state.truthy, target)
	if source != "" {
		state.origins[target] = source
	}
	if pyAssignmentFlowRequestSource(source) && previous == "session" {
		state.replacements[target] = source
	} else if replacementSource != "" {
		state.replacements[target] = replacementSource
	}
	if rightTruthy {
		state.truthy[target] = true
	}
}

func (a *pyAssignmentFlowAnalyzer) expressionSource(expression *tree_sitter.Node, state pyAssignmentFlowState) string {
	if expression == nil || pyIsNestedContextScope(expression) {
		return ""
	}
	switch expression.Kind() {
	case "identifier":
		return state.origins[a.c.text(expression)]
	case "parenthesized_expression":
		children := namedChildren(expression)
		if len(children) == 1 {
			return a.expressionSource(children[0], state)
		}
	case "attribute":
		path := pyContextEvidenceCompact(a.c.dotted(expression))
		if pyAssignmentFlowRequestSource(path) {
			return path
		}
	case "subscript":
		base := field(expression, "value")
		path := pyContextEvidenceCompact(a.c.dotted(base))
		if path == "session" || strings.HasSuffix(path, ".session") {
			return "session"
		}
		if pyAssignmentFlowRequestSource(path) {
			return path
		}
		return a.expressionSource(base, state)
	case "call":
		path := pyContextEvidenceCompact(a.c.dotted(field(expression, "function")))
		if path == "session.get" || strings.HasSuffix(path, ".session.get") {
			return "session"
		}
		if pyAssignmentFlowRequestSource(path) {
			return path
		}
	}
	return ""
}

func (a *pyAssignmentFlowAnalyzer) expressionReplacementSource(expression *tree_sitter.Node, state pyAssignmentFlowState) string {
	if expression == nil {
		return ""
	}
	if expression.Kind() == "identifier" {
		return state.replacements[a.c.text(expression)]
	}
	if expression.Kind() == "parenthesized_expression" {
		children := namedChildren(expression)
		if len(children) == 1 {
			return a.expressionReplacementSource(children[0], state)
		}
	}
	return ""
}

func pyAssignmentFlowRequestSource(source string) bool {
	return source != "" && source != "session" && pyContextPathContainsSegment(source, "request")
}

func (a *pyAssignmentFlowAnalyzer) conditionDefinitelyTrue(condition *tree_sitter.Node, state pyAssignmentFlowState) bool {
	if a.c.pyConditionAlwaysTrue(condition) {
		return true
	}
	if condition == nil {
		return false
	}
	switch condition.Kind() {
	case "identifier":
		return state.truthy[a.c.text(condition)]
	case "parenthesized_expression":
		children := namedChildren(condition)
		return len(children) == 1 && a.conditionDefinitelyTrue(children[0], state)
	case "call":
		if !pyIsLenCall(a.c, condition) {
			return false
		}
		arguments := namedChildren(field(condition, "arguments"))
		return len(arguments) == 1 && arguments[0].Kind() == "identifier" && state.truthy[a.c.text(arguments[0])]
	case "boolean_operator":
		operator := pyContextCompactUnbounded(a.c.text(field(condition, "operator")))
		left := a.conditionDefinitelyTrue(field(condition, "left"), state)
		right := a.conditionDefinitelyTrue(field(condition, "right"), state)
		if operator == "or" {
			return left || right
		}
		if operator == "and" {
			return left && right
		}
	}
	return false
}

func (a *pyAssignmentFlowAnalyzer) recordTruthyCondition(condition *tree_sitter.Node, state *pyAssignmentFlowState) {
	if condition == nil {
		return
	}
	if condition.Kind() == "identifier" {
		state.truthy[a.c.text(condition)] = true
		return
	}
	if condition.Kind() == "parenthesized_expression" {
		children := namedChildren(condition)
		if len(children) == 1 {
			a.recordTruthyCondition(children[0], state)
		}
	}
}

func (a *pyAssignmentFlowAnalyzer) expressionDefinitelyTruthy(expression *tree_sitter.Node, state pyAssignmentFlowState) bool {
	if expression == nil {
		return false
	}
	if expression.Kind() == "identifier" {
		return state.truthy[a.c.text(expression)]
	}
	if expression.Kind() == "parenthesized_expression" {
		children := namedChildren(expression)
		return len(children) == 1 && a.expressionDefinitelyTruthy(children[0], state)
	}
	return false
}
