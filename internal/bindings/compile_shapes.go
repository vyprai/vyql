package bindings

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/vyprai/vyql/internal/parser"
)

// Compiled from authored v2 binding declarations -- call shapes: the argument/callee/operator constraints a binding query compiles to.

type v2CallShape struct {
	NodeType    string
	Field       string
	Pattern     string
	Exact       bool
	Constraint  string
	ArgCountSet bool
	ArgCountMin int
	ArgCountMax int
	ValMatches  []string
	ValAbsents  []string
	ScopePreds  []PresencePredicate
}

const maxV2CallShapeExpansion = 256

func checkV2CallShapeExpansion(binding, op string, n int) error {
	if n <= maxV2CallShapeExpansion {
		return nil
	}
	return fmt.Errorf("binding %s: query predicate expansion for %s produced %d call shapes, limit %d", binding, op, n, maxV2CallShapeExpansion)
}

func lowerV2CallShapes(binding string, expr parser.V2Expr, allowNodeOnly bool, family string) ([]v2CallShape, error) {
	if expr == nil && allowNodeOnly {
		return []v2CallShape{{}}, nil
	}
	shapes, err := lowerV2CallShapeExpr(binding, expr, false, family)
	if err != nil {
		return nil, err
	}
	for _, shape := range shapes {
		if shape.Field == "" && !allowNodeOnly {
			return nil, fmt.Errorf("binding %s: query pattern lowering needs a callee.method/path predicate", binding)
		}
	}
	return dedupeV2CallShapes(shapes), nil
}

func lowerV2CallShapeExpr(binding string, expr parser.V2Expr, neg bool, family string) ([]v2CallShape, error) {
	if u, ok := expr.(parser.V2UnaryExpr); ok && u.Op == "not" {
		return lowerV2CallShapeExpr(binding, u.X, !neg, family)
	}
	if call, ok := expr.(parser.V2CallExpr); ok {
		return lowerV2CallShapeCall(binding, call, neg, family)
	}
	cmp, ok := expr.(parser.V2BinaryExpr)
	if !ok {
		return nil, fmt.Errorf("binding %s: unsupported query predicate %T", binding, expr)
	}
	switch cmp.Op {
	case "and":
		if neg {
			return lowerV2CallShapeOr(binding, cmp.Left, cmp.Right, true, family)
		}
		return lowerV2CallShapeAnd(binding, cmp.Left, cmp.Right, false, family)
	case "or":
		if neg {
			return lowerV2CallShapeAnd(binding, cmp.Left, cmp.Right, true, family)
		}
		return lowerV2CallShapeOr(binding, cmp.Left, cmp.Right, false, family)
	default:
		return lowerV2CallShapeAtom(binding, cmp, neg, family)
	}
}

func lowerV2CallShapeCall(binding string, call parser.V2CallExpr, neg bool, family string) ([]v2CallShape, error) {
	if call.Name != "containsAny" {
		return nil, fmt.Errorf("binding %s: unsupported query predicate call %q", binding, call.Name)
	}
	if len(call.Args) != 2 || len(call.NamedArgs) != 0 {
		return nil, fmt.Errorf("binding %s: containsAny requires two positional args", binding)
	}
	fieldRef, ok := call.Args[0].(parser.V2RefExpr)
	if !ok {
		return nil, fmt.Errorf("binding %s: containsAny first arg must be a query field", binding)
	}
	field := v2CallQueryField(fieldRef.Name, family)
	values, ok := parser.V2RuleWhereStringList(call.Args[1])
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("binding %s: containsAny second arg requires a non-empty string list", binding)
	}
	if _, prefix, ok := v2ArgsAnyContextField(field); ok {
		return lowerV2ContainsAnyValueShapes(binding, field, values, prefix, neg)
	}
	switch field {
	case "args.any.literal", "call.args.any.literal":
		return lowerV2ContainsAnyValueShapes(binding, field, values, "", neg)
	case "node.value", "node.name", "node.module":
		return lowerV2ContainsAnyValueShapes(binding, field, values, "", neg)
	case "assignment.any", "assignment.target", "assignment.value", "assignment.targetValue",
		"assignment.call", "assignment.callMethod", "assignment.item", "assignment.literal":
		prefix, _ := v2AssignmentTokenPrefix(field)
		return lowerV2ContainsAnyValueShapes(binding, field, values, prefix, neg)
	default:
		return nil, fmt.Errorf("binding %s: containsAny field %q is not implemented in scanner IR lowering", binding, fieldRef.Name)
	}
}

func lowerV2ContainsAnyValueShapes(binding, field string, values []string, prefix string, neg bool) ([]v2CallShape, error) {
	if err := checkV2CallShapeExpansion(binding, field, len(values)); err != nil {
		return nil, err
	}
	values = append([]string(nil), values...)
	if prefix != "" {
		for i, value := range values {
			if !strings.HasPrefix(value, prefix) {
				values[i] = prefix + value
			}
		}
	}
	if neg {
		return []v2CallShape{{ValAbsents: append([]string(nil), values...)}}, nil
	}
	out := make([]v2CallShape, 0, len(values))
	for _, value := range values {
		out = append(out, v2CallShape{ValMatches: []string{value}})
	}
	return out, nil
}

func lowerV2CallShapeAnd(binding string, left, right parser.V2Expr, neg bool, family string) ([]v2CallShape, error) {
	leftShapes, err := lowerV2CallShapeExpr(binding, left, neg, family)
	if err != nil {
		return nil, err
	}
	rightShapes, err := lowerV2CallShapeExpr(binding, right, neg, family)
	if err != nil {
		return nil, err
	}
	if err := checkV2CallShapeExpansion(binding, "and", len(leftShapes)*len(rightShapes)); err != nil {
		return nil, err
	}
	out := make([]v2CallShape, 0, len(leftShapes)*len(rightShapes))
	for _, l := range leftShapes {
		for _, r := range rightShapes {
			merged, err := mergeV2CallShapes(binding, l, r)
			if err != nil {
				return nil, err
			}
			out = append(out, merged)
		}
	}
	return out, nil
}

func lowerV2CallShapeOr(binding string, left, right parser.V2Expr, neg bool, family string) ([]v2CallShape, error) {
	leftShapes, err := lowerV2CallShapeExpr(binding, left, neg, family)
	if err != nil {
		return nil, err
	}
	rightShapes, err := lowerV2CallShapeExpr(binding, right, neg, family)
	if err != nil {
		return nil, err
	}
	if err := checkV2CallShapeExpansion(binding, "or", len(leftShapes)+len(rightShapes)); err != nil {
		return nil, err
	}
	return append(leftShapes, rightShapes...), nil
}

func lowerV2CallShapeAtom(binding string, cmp parser.V2BinaryExpr, neg bool, family string) ([]v2CallShape, error) {
	leftExpr := cmp.Left
	cmpNeg := neg
	if u, ok := leftExpr.(parser.V2UnaryExpr); ok && u.Op == "not" {
		leftExpr = u.X
		cmpNeg = !cmpNeg
	}
	left, ok := leftExpr.(parser.V2RefExpr)
	if !ok {
		return nil, fmt.Errorf("binding %s: unsupported query predicate left side %T", binding, cmp.Left)
	}
	field := v2CallQueryField(left.Name, family)
	if _, prefix, ok := v2ArgsAnyContextField(field); ok {
		if cmp.Op != "contains" {
			return nil, fmt.Errorf("binding %s: %s operator %q is not implemented in scanner IR lowering", binding, field, cmp.Op)
		}
		value, ok := parser.V2LiteralString(cmp.Right)
		if !ok {
			return nil, fmt.Errorf("binding %s: %s predicate right side must be a string", binding, field)
		}
		if !strings.HasPrefix(value, prefix) {
			value = prefix + value
		}
		if cmpNeg {
			return []v2CallShape{{ValAbsents: []string{value}}}, nil
		}
		return []v2CallShape{{ValMatches: []string{value}}}, nil
	}
	switch field {
	case "assignment.any", "assignment.target", "assignment.value", "assignment.targetValue",
		"assignment.call", "assignment.callMethod", "assignment.item", "assignment.literal":
		return lowerV2AssignmentTokenShapes(binding, field, cmp, cmpNeg)
	case "node.value", "node.name", "node.module":
		return lowerV2NodeValueShapes(binding, field, cmp, cmpNeg)
	case "operator":
		return lowerV2OperatorShapes(binding, cmp, cmpNeg)
	case "callee.method", "call.callee.method", "callee.path", "call.callee.path",
		"callee.analysis", "call.callee.analysis":
		return lowerV2CalleeShapes(binding, strings.TrimPrefix(field, "call."), cmp, cmpNeg)
	case "callee.receiver.type", "call.callee.receiver.type":
		if cmpNeg {
			return nil, fmt.Errorf("binding %s: negated receiver type predicate is not implemented in scanner IR lowering", binding)
		}
		constraint, ok := lowerV2ReceiverConstraint(cmp)
		if !ok {
			return nil, fmt.Errorf("binding %s: receiver type predicate must compare to string or string list", binding)
		}
		return []v2CallShape{{Constraint: constraint}}, nil
	case "scope.call.method", "scope.call.path":
		return lowerV2ScopeCallShapes(binding, field, cmp, cmpNeg)
	case "args.any.literal", "call.args.any.literal":
		if cmp.Op != "contains" {
			return nil, fmt.Errorf("binding %s: args.any.literal operator %q is not implemented in scanner IR lowering", binding, cmp.Op)
		}
		value, ok := parser.V2LiteralString(cmp.Right)
		if !ok {
			return nil, fmt.Errorf("binding %s: args.any.literal predicate right side must be a string", binding)
		}
		if cmpNeg {
			return []v2CallShape{{ValAbsents: []string{value}}}, nil
		}
		return []v2CallShape{{ValMatches: []string{value}}}, nil
	case "args.count", "call.args.count":
		shapes, ok := lowerV2ArgsCountShapes(cmp, cmpNeg)
		if !ok {
			return nil, fmt.Errorf("binding %s: args.count predicate must compare to a non-negative integer or integer list", binding)
		}
		if err := checkV2CallShapeExpansion(binding, field, len(shapes)); err != nil {
			return nil, err
		}
		return shapes, nil
	case "call.filter.global", "filter.global":
		if cmpNeg || cmp.Op != "==" {
			return nil, fmt.Errorf("binding %s: call.filter.global predicate must be == true", binding)
		}
		lit, ok := cmp.Right.(parser.V2LiteralExpr)
		if !ok {
			return nil, fmt.Errorf("binding %s: call.filter.global predicate right side must be a boolean", binding)
		}
		v, ok := lit.Value.(bool)
		if !ok {
			return nil, fmt.Errorf("binding %s: call.filter.global predicate right side must be a boolean", binding)
		}
		if !v {
			return nil, fmt.Errorf("binding %s: call.filter.global == false is not implemented in scanner IR lowering", binding)
		}
		return []v2CallShape{{}}, nil
	default:
		return nil, fmt.Errorf("binding %s: query predicate %q is not implemented in scanner IR lowering", binding, left.Name)
	}
}

func lowerV2NodeValueShapes(binding, field string, cmp parser.V2BinaryExpr, neg bool) ([]v2CallShape, error) {
	return lowerV2TokenValueShapes(binding, field, cmp, neg, "")
}

func lowerV2ScopeCallShapes(binding, field string, cmp parser.V2BinaryExpr, neg bool) ([]v2CallShape, error) {
	property := ""
	exact := false
	switch field {
	case "scope.call.method":
		property = "method"
	case "scope.call.path":
		property = "path"
		exact = cmp.Op == "==" || cmp.Op == "!=" || cmp.Op == "in" || cmp.Op == "not in"
	default:
		return nil, fmt.Errorf("binding %s: scope relation field %q is not implemented in scanner IR lowering", binding, field)
	}
	var values []string
	switch cmp.Op {
	case "==", "!=", "~=":
		if field == "scope.call.method" && cmp.Op == "~=" {
			return nil, fmt.Errorf("binding %s: scope call method does not support ~=; use == or in", binding)
		}
		value, ok := parser.V2LiteralString(cmp.Right)
		if !ok {
			return nil, fmt.Errorf("binding %s: %s predicate right side must be a string", binding, field)
		}
		values = []string{value}
	case "in", "not in":
		var ok bool
		values, ok = parser.V2RuleWhereStringList(cmp.Right)
		if !ok || len(values) == 0 {
			return nil, fmt.Errorf("binding %s: %s %s predicate requires a non-empty string list", binding, field, cmp.Op)
		}
	default:
		return nil, fmt.Errorf("binding %s: %s operator %q is not implemented in scanner IR lowering", binding, field, cmp.Op)
	}
	if err := checkV2CallShapeExpansion(binding, field, len(values)); err != nil {
		return nil, err
	}
	return []v2CallShape{{ScopePreds: []PresencePredicate{{
		Subject:  "scope_call",
		Property: property,
		Values:   values,
		Exact:    exact,
		Negative: neg != (cmp.Op == "!=" || cmp.Op == "not in"),
	}}}}, nil
}

func lowerV2AssignmentTokenShapes(binding, field string, cmp parser.V2BinaryExpr, neg bool) ([]v2CallShape, error) {
	prefix, ok := v2AssignmentTokenPrefix(field)
	if !ok {
		return nil, fmt.Errorf("binding %s: assignment field %q is not implemented in scanner IR lowering", binding, field)
	}
	return lowerV2TokenValueShapes(binding, field, cmp, neg, prefix)
}

func lowerV2TokenValueShapes(binding, field string, cmp parser.V2BinaryExpr, neg bool, prefix string) ([]v2CallShape, error) {
	var values []string
	switch cmp.Op {
	case "contains", "==", "!=":
		value, ok := parser.V2LiteralString(cmp.Right)
		if !ok {
			return nil, fmt.Errorf("binding %s: %s predicate right side must be a string", binding, field)
		}
		values = []string{value}
	case "in", "not in":
		var ok bool
		values, ok = parser.V2RuleWhereStringList(cmp.Right)
		if !ok || len(values) == 0 {
			return nil, fmt.Errorf("binding %s: %s %s predicate requires a non-empty string list", binding, field, cmp.Op)
		}
	default:
		return nil, fmt.Errorf("binding %s: %s operator %q is not implemented in scanner IR lowering", binding, field, cmp.Op)
	}
	if err := checkV2CallShapeExpansion(binding, field, len(values)); err != nil {
		return nil, err
	}
	for i, value := range values {
		if prefix != "" && !strings.HasPrefix(value, prefix) {
			values[i] = prefix + value
		}
	}
	negative := neg != (cmp.Op == "!=" || cmp.Op == "not in")
	if negative {
		return []v2CallShape{{ValAbsents: append([]string(nil), values...)}}, nil
	}
	out := make([]v2CallShape, 0, len(values))
	for _, value := range values {
		out = append(out, v2CallShape{ValMatches: []string{value}})
	}
	return out, nil
}

func lowerV2CalleeShapes(binding, field string, cmp parser.V2BinaryExpr, neg bool) ([]v2CallShape, error) {
	if neg {
		return nil, fmt.Errorf("binding %s: negated callee predicate is not implemented in scanner IR lowering", binding)
	}
	var values []string
	shapeField := field
	valuePrefix := ""
	if field == "callee.analysis" {
		shapeField = "callee.path"
		valuePrefix = "analysis."
	}
	exact := shapeField == "callee.path" && (cmp.Op == "==" || cmp.Op == "in")
	switch cmp.Op {
	case "==", "~=":
		pat, ok := parser.V2LiteralString(cmp.Right)
		if !ok {
			return nil, fmt.Errorf("binding %s: query predicate right side must be a string", binding)
		}
		values = []string{pat}
	case "in":
		var ok bool
		values, ok = parser.V2RuleWhereStringList(cmp.Right)
		if !ok || len(values) == 0 {
			return nil, fmt.Errorf("binding %s: callee %s in predicate requires a non-empty string list", binding, field)
		}
	default:
		return nil, fmt.Errorf("binding %s: callee predicate operator %q is not implemented in scanner IR lowering", binding, cmp.Op)
	}
	if err := checkV2CallShapeExpansion(binding, field, len(values)); err != nil {
		return nil, err
	}
	out := make([]v2CallShape, 0, len(values))
	for _, value := range values {
		if valuePrefix != "" && !strings.HasPrefix(value, valuePrefix) {
			value = valuePrefix + value
		}
		out = append(out, v2CallShape{Field: shapeField, Pattern: value, Exact: exact})
	}
	return out, nil
}

func lowerV2OperatorShapes(binding string, cmp parser.V2BinaryExpr, neg bool) ([]v2CallShape, error) {
	if neg {
		return nil, fmt.Errorf("binding %s: negated operator predicate is not implemented in scanner IR lowering", binding)
	}
	var values []string
	switch cmp.Op {
	case "==":
		pat, ok := parser.V2LiteralString(cmp.Right)
		if !ok {
			return nil, fmt.Errorf("binding %s: operator predicate right side must be a string", binding)
		}
		values = []string{pat}
	case "in":
		var ok bool
		values, ok = parser.V2RuleWhereStringList(cmp.Right)
		if !ok || len(values) == 0 {
			return nil, fmt.Errorf("binding %s: operator in predicate requires a non-empty string list", binding)
		}
	default:
		return nil, fmt.Errorf("binding %s: operator predicate operator %q is not implemented in scanner IR lowering", binding, cmp.Op)
	}
	if err := checkV2CallShapeExpansion(binding, "operator", len(values)); err != nil {
		return nil, err
	}
	out := make([]v2CallShape, 0, len(values))
	for _, value := range values {
		out = append(out, v2CallShape{Field: "callee.method", Pattern: v2BinaryOperatorMethod(value), Exact: true})
	}
	return out, nil
}

func mergeV2CallShapes(binding string, left, right v2CallShape) (v2CallShape, error) {
	out := left
	if right.Field != "" {
		if out.Field != "" && (out.Field != right.Field || out.Pattern != right.Pattern || out.Exact != right.Exact) {
			return v2CallShape{}, fmt.Errorf("binding %s: multiple different callee predicates in one conjunction are not supported", binding)
		}
		out.Field = right.Field
		out.Pattern = right.Pattern
		out.Exact = right.Exact
	}
	if right.Constraint != "" {
		if out.Constraint != "" && out.Constraint != right.Constraint {
			return v2CallShape{}, fmt.Errorf("binding %s: multiple receiver type predicates in one conjunction are not supported", binding)
		}
		out.Constraint = right.Constraint
	}
	if right.ArgCountSet {
		if out.ArgCountSet {
			min, max, ok := intersectV2ArgCount(out.ArgCountMin, out.ArgCountMax, right.ArgCountMin, right.ArgCountMax)
			if !ok {
				return v2CallShape{}, fmt.Errorf("binding %s: contradictory args.count predicates in one conjunction", binding)
			}
			out.ArgCountMin = min
			out.ArgCountMax = max
		} else {
			out.ArgCountSet = true
			out.ArgCountMin = right.ArgCountMin
			out.ArgCountMax = right.ArgCountMax
		}
	}
	out.ValMatches = append(append([]string(nil), left.ValMatches...), right.ValMatches...)
	out.ValAbsents = append(append([]string(nil), left.ValAbsents...), right.ValAbsents...)
	out.ScopePreds = append(append([]PresencePredicate(nil), left.ScopePreds...), right.ScopePreds...)
	return out, nil
}

func dedupeV2CallShapes(shapes []v2CallShape) []v2CallShape {
	seen := make(map[string]bool, len(shapes))
	out := make([]v2CallShape, 0, len(shapes))
	for _, shape := range shapes {
		key := strings.Join([]string{
			shape.NodeType,
			shape.Field,
			shape.Pattern,
			strconv.FormatBool(shape.Exact),
			shape.Constraint,
			strconv.FormatBool(shape.ArgCountSet),
			strconv.Itoa(shape.ArgCountMin),
			strconv.Itoa(shape.ArgCountMax),
			strings.Join(shape.ValMatches, "\x00"),
			strings.Join(shape.ValAbsents, "\x00"),
			v2PresencePredicatesKey(shape.ScopePreds),
		}, "\x01")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, shape)
	}
	return out
}

func lowerV2ArgsCountShapes(cmp parser.V2BinaryExpr, neg bool) ([]v2CallShape, bool) {
	value, ok := v2LiteralInt(cmp.Right)
	switch cmp.Op {
	case "==":
		if !ok {
			return nil, false
		}
		if neg {
			return v2ArgCountComplementValues([]int{value}), true
		}
		return []v2CallShape{v2ArgCountShape(value, value)}, true
	case "!=":
		if !ok {
			return nil, false
		}
		if neg {
			return []v2CallShape{v2ArgCountShape(value, value)}, true
		}
		return v2ArgCountComplementValues([]int{value}), true
	case ">=":
		if !ok {
			return nil, false
		}
		if neg {
			return v2ArgCountRange(0, value-1), true
		}
		return []v2CallShape{v2ArgCountShape(value, -1)}, true
	case ">":
		if !ok {
			return nil, false
		}
		if neg {
			return []v2CallShape{v2ArgCountShape(0, value)}, true
		}
		return []v2CallShape{v2ArgCountShape(value+1, -1)}, true
	case "<=":
		if !ok {
			return nil, false
		}
		if neg {
			return []v2CallShape{v2ArgCountShape(value+1, -1)}, true
		}
		return []v2CallShape{v2ArgCountShape(0, value)}, true
	case "<":
		if !ok || value == 0 {
			if !ok || !neg {
				return nil, false
			}
			return []v2CallShape{v2ArgCountShape(0, -1)}, true
		}
		if neg {
			return []v2CallShape{v2ArgCountShape(value, -1)}, true
		}
		return []v2CallShape{v2ArgCountShape(0, value-1)}, true
	case "in":
		values, ok := v2LiteralIntList(cmp.Right)
		if !ok || len(values) == 0 {
			return nil, false
		}
		if neg {
			return v2ArgCountComplementValues(values), true
		}
		out := make([]v2CallShape, 0, len(values))
		for _, v := range values {
			out = append(out, v2ArgCountShape(v, v))
		}
		return out, true
	case "not in":
		values, ok := v2LiteralIntList(cmp.Right)
		if !ok || len(values) == 0 {
			return nil, false
		}
		if neg {
			out := make([]v2CallShape, 0, len(values))
			for _, v := range values {
				out = append(out, v2ArgCountShape(v, v))
			}
			return out, true
		}
		return v2ArgCountComplementValues(values), true
	default:
		return nil, false
	}
}

func v2ArgCountShape(min, max int) v2CallShape {
	return v2CallShape{ArgCountSet: true, ArgCountMin: min, ArgCountMax: max}
}

func v2ArgCountRange(min, max int) []v2CallShape {
	if max >= 0 && min > max {
		return nil
	}
	return []v2CallShape{v2ArgCountShape(min, max)}
}

func v2ArgCountComplementValues(values []int) []v2CallShape {
	if len(values) == 0 {
		return []v2CallShape{v2ArgCountShape(0, -1)}
	}
	values = append([]int(nil), values...)
	sort.Ints(values)
	out := make([]v2CallShape, 0, len(values)+1)
	next := 0
	for _, v := range values {
		if v < next {
			continue
		}
		if next < v {
			out = append(out, v2ArgCountShape(next, v-1))
		}
		next = v + 1
	}
	out = append(out, v2ArgCountShape(next, -1))
	return out
}

func intersectV2ArgCount(aMin, aMax, bMin, bMax int) (int, int, bool) {
	min := aMin
	if bMin > min {
		min = bMin
	}
	max := aMax
	if max < 0 || (bMax >= 0 && bMax < max) {
		max = bMax
	}
	if max >= 0 && min > max {
		return 0, 0, false
	}
	return min, max, true
}
