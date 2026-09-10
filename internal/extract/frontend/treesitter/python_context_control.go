package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

const (
	pyContextBaseTokenLimit           = 512
	pyContextTerminalFactLimit        = 128
	pyContextReachableMethodLimit     = 32
	pyContextGuardLimit               = 64
	pyContextOperationsPerGuardLimit  = 32
	pyContextUsesPerOperationLimit    = 16
	pyContextComparisonsPerGuardLimit = 8
	pyContextEvidenceFieldLimit       = 160
)

type pyControlContextFacts struct {
	terminal       []string
	reachable      []string
	assignmentFlow []string
}

type pyContextProvenance uint8

const (
	pyProvenanceUnknown pyContextProvenance = iota
	pyProvenanceSession
	pyProvenanceLiteral
)

type pyGuardComparison struct {
	kind  string
	left  string
	right string
}

type pyGuardRelation struct {
	target            string
	counterpart       string
	counterpartSource string
}

type pyProtectedOperation struct {
	kind      string
	operation string
	callee    string
	args      string
	uses      []string
	// branched records that the operation sits inside a conditional branch further
	// down the statement list, so the guard is only an ancestor of it and not the
	// last check on the path that reaches it.
	branched bool
}

type pyControlContextAnalyzer struct {
	c *pyConv

	terminalFacts []string
	terminalSeen  map[string]bool
	reachable     []string
	reachableSeen map[string]bool
	guardCount    int
}

func (c *pyConv) pyControlFlowContextFacts(body *tree_sitter.Node) pyControlContextFacts {
	analyzer := &pyControlContextAnalyzer{
		c:             c,
		terminalSeen:  map[string]bool{},
		reachableSeen: map[string]bool{},
	}
	analyzer.visitBlock(body, map[string]pyContextProvenance{})
	return pyControlContextFacts{
		terminal:       analyzer.terminalFacts,
		reachable:      analyzer.reachable,
		assignmentFlow: c.pyAssignmentFlowFacts(body),
	}
}

func (a *pyControlContextAnalyzer) visitBlock(block *tree_sitter.Node, provenance map[string]pyContextProvenance) {
	if block == nil {
		return
	}
	statements := pyContextStatements(block)
	for index, statement := range statements {
		if a.controlFactsSaturated() {
			return
		}
		if pyIsNestedContextScope(statement) {
			continue
		}

		a.recordReachableCallsOutsideBlocks(statement)

		if statement.Kind() == "if_statement" {
			condition := field(statement, "condition")
			terminalKind, terminal := a.c.pyTerminalBranchKind(field(statement, "consequence"))
			if terminal && a.guardCount < pyContextGuardLimit && len(a.terminalFacts) < pyContextTerminalFactLimit {
				a.guardCount++
				a.recordGuardCorrelations(condition, terminalKind, statements[index+1:], provenance)
			}

			blocks := pyDirectContextBlocks(statement)
			if a.c.pyConditionAlwaysTrue(condition) {
				reachableBlocks := blocks
				if len(reachableBlocks) > 1 {
					reachableBlocks = reachableBlocks[:1]
				}
				if len(blocks) > 0 {
					a.visitBlock(blocks[0], clonePyProvenance(provenance))
				}
				a.invalidateCompoundBindings(provenance, statement, reachableBlocks)
				if terminal {
					return
				}
			} else {
				for _, nested := range blocks {
					a.visitBlock(nested, clonePyProvenance(provenance))
				}
				a.invalidateCompoundBindings(provenance, statement, blocks)
			}
			continue
		}

		a.updateProvenance(statement, provenance)
		blocks := pyDirectContextBlocks(statement)
		for _, nested := range blocks {
			a.visitBlock(nested, clonePyProvenance(provenance))
		}
		a.invalidateCompoundBindings(provenance, statement, blocks)
		if _, terminal := a.c.pyUnconditionalTerminalKind(statement); terminal {
			return
		}
	}
}

func (a *pyControlContextAnalyzer) controlFactsSaturated() bool {
	return len(a.terminalFacts) >= pyContextTerminalFactLimit &&
		len(a.reachable) >= pyContextReachableMethodLimit
}

func (a *pyControlContextAnalyzer) addTerminalFact(fact string) bool {
	if fact == "" || a.terminalSeen[fact] {
		return len(a.terminalFacts) < pyContextTerminalFactLimit
	}
	if len(a.terminalFacts) >= pyContextTerminalFactLimit {
		return false
	}
	a.terminalSeen[fact] = true
	a.terminalFacts = append(a.terminalFacts, fact)
	return len(a.terminalFacts) < pyContextTerminalFactLimit
}

func (a *pyControlContextAnalyzer) addReachableMethod(method string) {
	method = pyContextEvidenceCompact(method)
	if method == "" || a.reachableSeen[method] || len(a.reachable) >= pyContextReachableMethodLimit {
		return
	}
	a.reachableSeen[method] = true
	a.reachable = append(a.reachable, "reachable_call_method:"+method)
}

func (a *pyControlContextAnalyzer) recordReachableCallsOutsideBlocks(statement *tree_sitter.Node) {
	if statement == nil || len(a.reachable) >= pyContextReachableMethodLimit {
		return
	}
	root := statement
	var walk func(*tree_sitter.Node)
	walk = func(node *tree_sitter.Node) {
		if node == nil || len(a.reachable) >= pyContextReachableMethodLimit {
			return
		}
		if node != root && (node.Kind() == "block" || pyIsNestedContextScope(node)) {
			return
		}
		if node.Kind() == "call" {
			path := a.c.dotted(field(node, "function"))
			a.addReachableMethod(lastSeg(path))
		}
		for _, child := range namedChildren(node) {
			walk(child)
		}
	}
	walk(statement)
}

func (a *pyControlContextAnalyzer) updateProvenance(statement *tree_sitter.Node, provenance map[string]pyContextProvenance) {
	assignment := pyDirectContextAssignment(statement)
	if assignment == nil {
		if augmented := pyDirectContextAugmentedAssignment(statement); augmented != nil {
			for _, target := range a.c.targets(field(augmented, "left")) {
				delete(provenance, target)
			}
		}
		return
	}
	left, right := field(assignment, "left"), field(assignment, "right")
	source := a.c.pyExpressionProvenance(right, provenance)
	for _, target := range a.c.targets(left) {
		delete(provenance, target)
	}
	if left == nil || left.Kind() != "identifier" {
		return
	}
	target := a.c.text(left)
	if source == pyProvenanceSession {
		provenance[target] = pyProvenanceSession
	}
}

func (a *pyControlContextAnalyzer) invalidateCompoundBindings(provenance map[string]pyContextProvenance, statement *tree_sitter.Node, blocks []*tree_sitter.Node) {
	directAssignment := pyDirectContextAssignment(statement)
	directAugmented := pyDirectContextAugmentedAssignment(statement)
	assigned := map[string]bool{}
	var walk func(*tree_sitter.Node, bool)
	walk = func(node *tree_sitter.Node, skipBlocks bool) {
		if node == nil || pyIsNestedContextScope(node) {
			return
		}
		if skipBlocks && node.Kind() == "block" {
			return
		}
		switch node.Kind() {
		case "assignment", "augmented_assignment":
			if !pySameContextNode(node, directAssignment) && !pySameContextNode(node, directAugmented) {
				a.collectContextBindingTarget(field(node, "left"), assigned)
			}
		case "named_expression":
			a.collectContextBindingTarget(field(node, "name"), assigned)
		case "for_statement":
			a.collectContextBindingTarget(field(node, "left"), assigned)
		case "as_pattern_target":
			a.collectContextBindingTarget(node, assigned)
		case "case_clause":
			for _, child := range namedChildren(node) {
				if child.Kind() == "case_pattern" {
					a.collectMatchCaptureTargets(child, assigned)
				}
			}
		}
		for _, child := range namedChildren(node) {
			walk(child, skipBlocks)
		}
	}
	walk(statement, true)
	for _, block := range blocks {
		walk(block, false)
	}
	for target := range assigned {
		delete(provenance, target)
	}
}

func pySameContextNode(left, right *tree_sitter.Node) bool {
	return left != nil && right != nil && left.Kind() == right.Kind() &&
		left.StartByte() == right.StartByte() && left.EndByte() == right.EndByte()
}

func (a *pyControlContextAnalyzer) collectContextBindingTarget(target *tree_sitter.Node, assigned map[string]bool) {
	if target == nil {
		return
	}
	switch target.Kind() {
	case "identifier", "keyword_identifier":
		assigned[a.c.text(target)] = true
	case "as_pattern_target", "pattern_list", "expression_list", "tuple_pattern", "list_pattern", "tuple", "list", "parenthesized_expression", "list_splat_pattern", "dictionary_splat_pattern":
		for _, child := range namedChildren(target) {
			a.collectContextBindingTarget(child, assigned)
		}
	}
}

func (a *pyControlContextAnalyzer) collectMatchCaptureTargets(pattern *tree_sitter.Node, assigned map[string]bool) {
	if pattern == nil {
		return
	}
	children := namedChildren(pattern)
	switch pattern.Kind() {
	case "case_pattern", "list_pattern", "tuple_pattern", "union_pattern":
		for _, child := range children {
			a.collectMatchCaptureTargets(child, assigned)
		}
	case "as_pattern":
		for _, child := range children {
			if child.Kind() == "identifier" {
				assigned[a.c.text(child)] = true
				continue
			}
			a.collectMatchCaptureTargets(child, assigned)
		}
	case "dotted_name":
		if len(children) == 1 && children[0].Kind() == "identifier" {
			assigned[a.c.text(children[0])] = true
		}
	case "splat_pattern":
		for _, child := range children {
			if child.Kind() == "identifier" && a.c.text(child) != "_" {
				assigned[a.c.text(child)] = true
			}
		}
	case "dict_pattern":
		for _, child := range children {
			if child.Kind() == "case_pattern" || child.Kind() == "splat_pattern" {
				a.collectMatchCaptureTargets(child, assigned)
			}
		}
	case "class_pattern":
		for _, child := range children {
			if child.Kind() == "case_pattern" {
				a.collectMatchCaptureTargets(child, assigned)
			}
		}
	case "keyword_pattern":
		if len(children) > 1 {
			for _, child := range children[1:] {
				a.collectMatchCaptureTargets(child, assigned)
			}
		}
	}
}

func pyDirectContextAssignment(statement *tree_sitter.Node) *tree_sitter.Node {
	if statement == nil {
		return nil
	}
	if statement.Kind() == "assignment" {
		return statement
	}
	if statement.Kind() != "expression_statement" {
		return nil
	}
	children := namedChildren(statement)
	if len(children) == 1 && children[0].Kind() == "assignment" {
		return children[0]
	}
	return nil
}

func pyDirectContextAugmentedAssignment(statement *tree_sitter.Node) *tree_sitter.Node {
	if statement == nil {
		return nil
	}
	if statement.Kind() == "augmented_assignment" {
		return statement
	}
	if statement.Kind() != "expression_statement" {
		return nil
	}
	children := namedChildren(statement)
	if len(children) == 1 && children[0].Kind() == "augmented_assignment" {
		return children[0]
	}
	return nil
}

func (c *pyConv) pyExpressionProvenance(expression *tree_sitter.Node, provenance map[string]pyContextProvenance) pyContextProvenance {
	if expression == nil || pyIsNestedContextScope(expression) {
		return pyProvenanceUnknown
	}
	if pyIsStableContextLiteral(expression) {
		return pyProvenanceLiteral
	}
	switch expression.Kind() {
	case "identifier":
		if provenance[c.text(expression)] == pyProvenanceSession {
			return pyProvenanceSession
		}
	case "parenthesized_expression":
		children := namedChildren(expression)
		if len(children) == 1 {
			return c.pyExpressionProvenance(children[0], provenance)
		}
	case "boolean_operator":
		if c.pyExpressionProvenance(field(expression, "left"), provenance) == pyProvenanceSession &&
			c.pyExpressionProvenance(field(expression, "right"), provenance) == pyProvenanceSession {
			return pyProvenanceSession
		}
	case "conditional_expression":
		children := namedChildren(expression)
		if len(children) == 3 &&
			c.pyExpressionProvenance(children[0], provenance) == pyProvenanceSession &&
			c.pyExpressionProvenance(children[2], provenance) == pyProvenanceSession {
			return pyProvenanceSession
		}
	case "subscript":
		path := c.dotted(field(expression, "value"))
		if path == "session" || strings.HasSuffix(path, ".session") {
			children := namedChildren(expression)
			if len(children) == 2 && pyIsStableContextLiteral(children[1]) {
				return pyProvenanceSession
			}
		}
	case "call":
		path := c.dotted(field(expression, "function"))
		argumentsNode := field(expression, "arguments")
		var arguments []*tree_sitter.Node
		if argumentsNode == nil {
			arguments = nil
		} else if argumentsNode.Kind() == "argument_list" {
			arguments = namedChildren(argumentsNode)
		} else {
			arguments = []*tree_sitter.Node{argumentsNode}
		}
		if path == "session.get" || strings.HasSuffix(path, ".session.get") {
			if len(arguments) == 0 {
				return pyProvenanceUnknown
			}
			for _, argument := range arguments {
				if c.pyCallArgumentProvenance(argument, provenance) != pyProvenanceLiteral {
					return pyProvenanceUnknown
				}
			}
			return pyProvenanceSession
		}
		if path == "" || pyContextPathContainsSegment(path, "request") {
			return pyProvenanceUnknown
		}
		hasSessionArgument := false
		for _, argument := range arguments {
			source := c.pyCallArgumentProvenance(argument, provenance)
			switch source {
			case pyProvenanceSession:
				hasSessionArgument = true
			case pyProvenanceLiteral:
			default:
				return pyProvenanceUnknown
			}
		}
		if hasSessionArgument {
			return pyProvenanceSession
		}
	}
	return pyProvenanceUnknown
}

func pyContextPathContainsSegment(path, segment string) bool {
	for _, candidate := range strings.Split(path, ".") {
		if candidate == segment {
			return true
		}
	}
	return false
}

func (c *pyConv) pyCallArgumentProvenance(argument *tree_sitter.Node, provenance map[string]pyContextProvenance) pyContextProvenance {
	if argument == nil {
		return pyProvenanceUnknown
	}
	if argument.Kind() == "keyword_argument" {
		return c.pyExpressionProvenance(field(argument, "value"), provenance)
	}
	return c.pyExpressionProvenance(argument, provenance)
}

func pyIsStableContextLiteral(expression *tree_sitter.Node) bool {
	if expression == nil {
		return false
	}
	switch expression.Kind() {
	case "integer", "float", "true", "false", "none", "ellipsis":
		return true
	case "string":
		for _, child := range namedChildren(expression) {
			if child.Kind() == "interpolation" {
				return false
			}
		}
		return true
	case "concatenated_string":
		children := namedChildren(expression)
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !pyIsStableContextLiteral(child) {
				return false
			}
		}
		return true
	}
	return false
}

func (a *pyControlContextAnalyzer) recordGuardCorrelations(condition *tree_sitter.Node, terminalKind string, laterStatements []*tree_sitter.Node, provenance map[string]pyContextProvenance) {
	comparisons := a.c.pyGuardComparisons(condition, pyContextComparisonsPerGuardLimit)
	tests := comparisons
	if len(tests) == 0 {
		// A guard whose condition is a pure truthiness test holds no comparison
		// operator, and it still ends every path past it. Its operands are recorded
		// the way a comparison's are: `if user_id and not is_admin(): abort(403)`
		// names the truthiness of `user_id` and the falsiness of `is_admin()`.
		tests = a.c.pyGuardTruthinessTests(condition, pyContextComparisonsPerGuardLimit)
	}
	if len(tests) == 0 {
		return
	}
	operations := a.c.pyBoundedLaterOperations(laterStatements, pyContextOperationsPerGuardLimit)
	for _, operation := range operations {
		if len(a.terminalFacts) >= pyContextTerminalFactLimit {
			return
		}
		for _, test := range tests {
			for _, relation := range pyGuardRelations(test, provenance) {
				// A truthiness test compares against nothing, so pyGuardRelations
				// names no counterpart and the fact carries no counterpart fields.
				counterpart := ""
				if relation.counterpartSource != "" {
					counterpart = ";counterpart_source=" + relation.counterpartSource +
						";guard_counterpart=" + relation.counterpart
				}
				scope := ";guard_scope=" + pyGuardScope(operation.branched)
				if operation.kind == "call" {
					if len(operation.uses) == 0 {
						continue
					}
					fact := "terminal_guard_blocks_call:operation=" + operation.operation +
						";args=" + operation.args +
						";guard_kind=" + test.kind +
						";guard_target=" + relation.target +
						counterpart +
						";terminal=" + terminalKind +
						";callee=" + operation.callee +
						scope
					if !a.addTerminalFact(fact) {
						return
					}
					continue
				}
				for _, use := range operation.uses {
					fact := "terminal_guard_blocks_return:use=" + use +
						";guard_kind=" + test.kind +
						";guard_target=" + relation.target +
						counterpart +
						";terminal=" + terminalKind +
						scope
					if !a.addTerminalFact(fact) {
						return
					}
				}
			}
		}
	}
}

func pyGuardRelations(comparison pyGuardComparison, provenance map[string]pyContextProvenance) []pyGuardRelation {
	switch comparison.kind {
	case "non_null":
		return []pyGuardRelation{{target: comparison.left, counterpart: "None", counterpartSource: "literal"}}
	case "truthy", "falsy":
		return []pyGuardRelation{{target: comparison.left}}
	}
	return []pyGuardRelation{
		{target: comparison.left, counterpart: comparison.right, counterpartSource: pyCounterpartSource(provenance, comparison.right)},
		{target: comparison.right, counterpart: comparison.left, counterpartSource: pyCounterpartSource(provenance, comparison.left)},
	}
}

func pyCounterpartSource(provenance map[string]pyContextProvenance, operand string) string {
	if strings.EqualFold(operand, "none") {
		return "literal"
	}
	if provenance[pyGuardSubject(operand)] == pyProvenanceSession {
		return "session"
	}
	return "unknown"
}

func (c *pyConv) pyGuardComparisons(condition *tree_sitter.Node, limit int) []pyGuardComparison {
	var out []pyGuardComparison
	var collect func(*tree_sitter.Node)
	collect = func(node *tree_sitter.Node) {
		if node == nil || len(out) >= limit {
			return
		}
		if node.Kind() == "parenthesized_expression" {
			children := namedChildren(node)
			if len(children) == 1 {
				collect(children[0])
			}
			return
		}
		if node.Kind() == "boolean_operator" {
			if pyContextCompactUnbounded(c.text(field(node, "operator"))) != "or" {
				return
			}
			collect(field(node, "left"))
			collect(field(node, "right"))
			return
		}
		leftNode, operator, rightNode, ok := c.pySimpleComparison(node)
		if !ok {
			return
		}
		left := pyGuardOperand(leftNode, pyContextCompactUnbounded(c.text(leftNode)))
		right := pyGuardOperand(rightNode, pyContextCompactUnbounded(c.text(rightNode)))
		if operator == "!=" || operator == "isnot" {
			if strings.EqualFold(left, "none") && right != "" {
				out = append(out, pyGuardComparison{kind: "non_null", left: right, right: "None"})
				return
			}
			if strings.EqualFold(right, "none") && left != "" {
				out = append(out, pyGuardComparison{kind: "non_null", left: left, right: "None"})
				return
			}
		}
		if left == "" || right == "" {
			return
		}
		switch operator {
		case "!=":
			out = append(out, pyGuardComparison{kind: "mismatch", left: left, right: right})
		case "==":
			out = append(out, pyGuardComparison{kind: "equal", left: left, right: right})
		}
	}
	collect(condition)
	return out
}

// pyGuardTruthinessTests names the operands a guard condition requires to hold when it
// holds no comparison operator: an operand read for truth (`user_id`) or, under a `not`,
// for falsity (`not is_admin()`). Both `and` and `or` links descend — a conjunct is
// required on every path past the guard and a disjunct on the path it selects — so
// `if user_id and not is_admin(): abort(403)` names both. A condition mixing a
// comparison with a truthiness operand names nothing here: the comparison collector
// already spoke for it, and neither half stands for the condition.
func (c *pyConv) pyGuardTruthinessTests(condition *tree_sitter.Node, limit int) []pyGuardComparison {
	var out []pyGuardComparison
	var collect func(*tree_sitter.Node)
	collect = func(node *tree_sitter.Node) {
		if node == nil || len(out) >= limit {
			return
		}
		switch node.Kind() {
		case "parenthesized_expression":
			children := namedChildren(node)
			if len(children) == 1 {
				collect(children[0])
			}
		case "boolean_operator":
			collect(field(node, "left"))
			collect(field(node, "right"))
		case "not_operator":
			if operand := pyGuardTruthinessOperand(field(node, "argument"), pyContextCompactUnbounded(c.text(field(node, "argument")))); operand != "" {
				out = append(out, pyGuardComparison{kind: "falsy", left: operand})
			}
		default:
			if operand := pyGuardTruthinessOperand(node, pyContextCompactUnbounded(c.text(node))); operand != "" {
				out = append(out, pyGuardComparison{kind: "truthy", left: operand})
			}
		}
	}
	collect(condition)
	return out
}

// pyGuardTruthinessOperand renders the value a truthiness test reads: a name, an
// attribute or subscript chain, or a call, which is the shape an authorization gate
// consults. A literal or an operator reads as a constant rather than as a value the
// path had to carry, so it names nothing.
func pyGuardTruthinessOperand(node *tree_sitter.Node, compact string) string {
	if node == nil || compact == "" {
		return ""
	}
	switch node.Kind() {
	case "identifier", "attribute", "subscript", "call":
		return pyContextEvidenceCompact(compact)
	default:
		return ""
	}
}

// pyGuardScope states where an operation sits relative to the guard that blocks it:
// `block` when it follows the guard in the same statement list, so the guard's terminal
// branch is the last check on the path that reaches it, and `branch` when it sits inside
// a conditional further down, so the operation is reached only on a branch of its own
// and a guard written there is not interchangeable with this one.
func pyGuardScope(branched bool) string {
	if branched {
		return "branch"
	}
	return "block"
}

func (c *pyConv) pyBoundedLaterOperations(statements []*tree_sitter.Node, limit int) []pyProtectedOperation {
	seen := map[string]bool{}
	var out []pyProtectedOperation
	for _, statement := range statements {
		if len(out) >= limit {
			break
		}
		for _, operation := range c.pyBoundedOperations(statement, limit-len(out)) {
			key := operation.kind + "\x00" + operation.operation + "\x00" + operation.callee + "\x00" + operation.args + "\x00" + strings.Join(operation.uses, "\x00")
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, operation)
			if len(out) >= limit {
				break
			}
		}
		if c.pyStatementDefinitelyTerminates(statement) {
			break
		}
	}
	return out
}

func (c *pyConv) pyBoundedOperations(node *tree_sitter.Node, limit int) []pyProtectedOperation {
	var out []pyProtectedOperation
	var walk func(*tree_sitter.Node, bool)
	walk = func(current *tree_sitter.Node, branched bool) {
		if current == nil || len(out) >= limit || pyIsNestedContextScope(current) {
			return
		}
		if current.Kind() == "if_statement" && c.pyConditionAlwaysTrue(field(current, "condition")) {
			for _, child := range namedChildren(current) {
				if child.Kind() == "block" {
					walk(child, branched)
					break
				}
				if child != field(current, "alternative") {
					walk(child, branched)
				}
			}
			return
		}
		switch current.Kind() {
		case "return_statement":
			out = append(out, pyProtectedOperation{kind: "return", uses: c.pyBoundedContextIdentifiers(current, pyContextUsesPerOperationLimit), branched: branched})
		case "call":
			path := pyContextEvidenceCompact(c.dotted(field(current, "function")))
			arguments := pyCallArgumentsText(c, current)
			out = append(out, pyProtectedOperation{
				kind:      "call",
				operation: pyNormalizedCallOperation(path),
				callee:    path,
				args:      arguments,
				uses:      c.pyBoundedContextIdentifiers(field(current, "arguments"), pyContextUsesPerOperationLimit),
				branched:  branched,
			})
		}
		for _, child := range namedChildren(current) {
			walk(child, branched || pyConditionalBlock(current, child))
		}
	}
	walk(node, false)
	return out
}

// pyConditionalBlock reports whether a child is the body of a conditional branch, so
// everything below it is reached only on the path that branch selects. The body of a
// `for`, `while`, `with` or `try` is left out: it runs without a further condition, and
// the guard still stands between it and every path that reaches it.
func pyConditionalBlock(parent, child *tree_sitter.Node) bool {
	if child == nil || child.Kind() != "block" {
		return false
	}
	switch parent.Kind() {
	case "if_statement", "elif_clause", "else_clause", "except_clause", "case_clause":
		return true
	}
	return false
}

func (c *pyConv) pyBoundedContextIdentifiers(node *tree_sitter.Node, limit int) []string {
	seen := map[string]bool{}
	var out []string
	var walk func(*tree_sitter.Node)
	walk = func(current *tree_sitter.Node) {
		if current == nil || len(out) >= limit || pyIsNestedContextScope(current) {
			return
		}
		if current.Kind() == "identifier" {
			identifier := pyContextEvidenceCompact(c.text(current))
			if identifier != "" && !seen[identifier] {
				seen[identifier] = true
				out = append(out, identifier)
			}
			return
		}
		for _, child := range namedChildren(current) {
			walk(child)
		}
	}
	walk(node)
	return out
}

func pyCallArgumentsText(c *pyConv, call *tree_sitter.Node) string {
	arguments := field(call, "arguments")
	if arguments == nil {
		return ""
	}
	text := pyContextEvidenceCompact(c.pyScopeLocalText(arguments))
	if len(text) >= 2 && text[0] == '(' && text[len(text)-1] == ')' {
		text = text[1 : len(text)-1]
	}
	return text
}

func pyNormalizedCallOperation(path string) string {
	if path == "query.get" || strings.HasSuffix(path, ".query.get") {
		return "query.get"
	}
	return lastSeg(path)
}

func (c *pyConv) pyStatementDefinitelyTerminates(statement *tree_sitter.Node) bool {
	if _, terminal := c.pyUnconditionalTerminalKind(statement); terminal {
		return true
	}
	if statement == nil || statement.Kind() != "if_statement" || !c.pyConditionAlwaysTrue(field(statement, "condition")) {
		return false
	}
	_, terminal := c.pyTerminalBranchKind(field(statement, "consequence"))
	return terminal
}

func (c *pyConv) pyTerminalBranchKind(block *tree_sitter.Node) (string, bool) {
	statements := pyContextStatements(block)
	if len(statements) == 0 {
		return "", false
	}
	return c.pyUnconditionalTerminalKind(statements[len(statements)-1])
}

func (c *pyConv) pyUnconditionalTerminalKind(statement *tree_sitter.Node) (string, bool) {
	if statement == nil {
		return "", false
	}
	switch statement.Kind() {
	case "return_statement":
		return "return", true
	case "raise_statement":
		return "raise", true
	case "expression_statement":
		children := namedChildren(statement)
		if len(children) == 1 && children[0].Kind() == "call" && lastSeg(c.dotted(field(children[0], "function"))) == "abort" {
			return "abort", true
		}
	}
	return "", false
}

func pyDirectContextBlocks(node *tree_sitter.Node) []*tree_sitter.Node {
	if node == nil || pyIsNestedContextScope(node) {
		return nil
	}
	var out []*tree_sitter.Node
	for _, child := range namedChildren(node) {
		if child.Kind() == "block" {
			out = append(out, child)
			continue
		}
		switch child.Kind() {
		case "elif_clause", "else_clause", "except_clause", "finally_clause", "with_clause":
			for _, clauseChild := range namedChildren(child) {
				if clauseChild.Kind() == "block" {
					out = append(out, clauseChild)
				}
			}
		}
	}
	return out
}

func pyContextStatements(block *tree_sitter.Node) []*tree_sitter.Node {
	if block == nil {
		return nil
	}
	var out []*tree_sitter.Node
	for _, child := range namedChildren(block) {
		if child.Kind() != "comment" {
			out = append(out, child)
		}
	}
	return out
}

func clonePyProvenance(provenance map[string]pyContextProvenance) map[string]pyContextProvenance {
	clone := make(map[string]pyContextProvenance, len(provenance))
	for name, source := range provenance {
		clone[name] = source
	}
	return clone
}

func pyContextEvidenceCompact(raw string) string {
	compact := pyContextCompactUnbounded(raw)
	if len(compact) <= pyContextEvidenceFieldLimit {
		return compact
	}
	const suffix = "..."
	cut := pyContextEvidenceFieldLimit - len(suffix)
	return strings.ToValidUTF8(compact[:cut], "") + suffix
}

func (c *pyConv) pySimpleComparison(condition *tree_sitter.Node) (*tree_sitter.Node, string, *tree_sitter.Node, bool) {
	if condition == nil || condition.Kind() != "comparison_operator" {
		return nil, "", nil, false
	}
	children := namedChildren(condition)
	if len(children) != 2 {
		return nil, "", nil, false
	}
	left := pyContextCompactUnbounded(c.text(children[0]))
	right := pyContextCompactUnbounded(c.text(children[1]))
	whole := pyContextCompactUnbounded(c.text(condition))
	if !strings.HasPrefix(whole, left) || !strings.HasSuffix(whole, right) || len(whole) < len(left)+len(right) {
		return nil, "", nil, false
	}
	operator := strings.TrimSuffix(strings.TrimPrefix(whole, left), right)
	return children[0], operator, children[1], operator != ""
}

func pyGuardOperand(node *tree_sitter.Node, compact string) string {
	if node == nil || compact == "" {
		return ""
	}
	switch node.Kind() {
	case "identifier", "attribute", "subscript", "none":
		return pyContextEvidenceCompact(compact)
	default:
		return ""
	}
}

func pyGuardSubject(value string) string {
	if i := strings.IndexAny(value, ".[ "); i >= 0 {
		return value[:i]
	}
	return value
}

func (c *pyConv) pyConditionAlwaysTrue(condition *tree_sitter.Node) bool {
	if condition == nil {
		return false
	}
	if condition.Kind() == "parenthesized_expression" {
		children := namedChildren(condition)
		return len(children) == 1 && c.pyConditionAlwaysTrue(children[0])
	}
	if condition.Kind() == "boolean_operator" {
		operator := pyContextCompactUnbounded(c.text(field(condition, "operator")))
		left := c.pyConditionAlwaysTrue(field(condition, "left"))
		right := c.pyConditionAlwaysTrue(field(condition, "right"))
		if operator == "or" {
			return left || right
		}
		if operator == "and" {
			return left && right
		}
		return false
	}
	left, operator, right, ok := c.pySimpleComparison(condition)
	if !ok {
		return false
	}
	return operator == ">=" && pyIsLenCall(c, left) && pyIsZeroLiteral(c, right) ||
		operator == "<=" && pyIsZeroLiteral(c, left) && pyIsLenCall(c, right)
}

func pyIsLenCall(c *pyConv, node *tree_sitter.Node) bool {
	if node == nil || node.Kind() != "call" {
		return false
	}
	function := field(node, "function")
	arguments := field(node, "arguments")
	return function != nil && function.Kind() == "identifier" && c.text(function) == "len" && len(namedChildren(arguments)) == 1
}

func pyIsZeroLiteral(c *pyConv, node *tree_sitter.Node) bool {
	return node != nil && node.Kind() == "integer" && pyContextCompactUnbounded(c.text(node)) == "0"
}
