package bindings

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/vyprai/vyql/internal/parser"
)

// Compiled from authored v2 binding declarations -- presence bindings: flag-style bindings that assert a property of a single node.

func builtinV2PresenceNodePattern() *parser.V2PatternDecl {
	return &parser.V2PatternDecl{
		Name:  "presenceNode",
		Alias: "node",
		Items: []parser.V2PatternItem{{Kind: "node", Name: "node"}},
	}
}

func lowerV2PresenceBinding(b *parser.V2BindingDecl, names parser.V2Names, expr parser.V2Expr, alias string, matchers v2MatcherResolver, mechanics parser.V2Context) ([]Action, bool, error) {
	fl, ok, err := lowerV2PresenceFlagExpr(alias, expr, matchers)
	if err != nil || !ok {
		return nil, ok, err
	}
	pkgs, req, err := lowerV2Requirements(b.Requirements)
	if err != nil {
		return nil, true, fmt.Errorf("binding %s: %w", b.Name, err)
	}
	// Self-gate by content: when a presence binding declares no explicit requirement, derive a
	// content() gate from its most distinctive necessary literal (a positive identifier-like
	// predicate value that must occur for any match). The binding then skips whole programs that
	// don't contain that literal — so a CVE pattern binding targeting one project doesn't scan
	// every node of unrelated trees. Sound: the literal is required by the match either way.
	if req == nil {
		if lit := deriveV2ContentGate(fl); lit != "" {
			req = &Requirement{Op: "content", Value: lit}
		}
	}
	var out []Action
	for _, action := range b.Outputs {
		action.Concept = names.Concept(action.Concept)
		action.About = names.Concept(action.About)
		if action.Kind != "emit issue" && action.Kind != "emit sink" && action.Kind != "emit source" && action.Kind != "emit check" {
			return nil, true, fmt.Errorf("binding %s: presenceNode only supports emit issue/source/sink/check", b.Name)
		}
		if action.Location != alias {
			return nil, true, fmt.Errorf("binding %s: presenceNode emit location must be %q", b.Name, alias)
		}
		coverage := ""
		var coverageDetail map[string]string
		if len(action.Covers) > 1 {
			return nil, true, fmt.Errorf("binding %s: presenceNode supports at most one coverage mode", b.Name)
		}
		if len(action.Covers) == 1 {
			if err := validateV2OutputCoverageMechanics(b.Name, action, mechanics); err != nil {
				return nil, true, err
			}
			coverage = action.Covers[0].Mode
			coverageDetail = lowerV2CoverageDetail(action.Covers[0])
		}
		flag := *fl
		out = appendV2BindingAction(out, Action{
			Kind:           v2PresenceOutputKind(action.Kind),
			Concept:        action.Concept,
			About:          action.About,
			Advisory:       action.Advisory != nil && *action.Advisory,
			Coverage:       coverage,
			CoverageDetail: coverageDetail,
			Packages:       pkgs,
			Requirement:    req,
			Flag:           &flag,
		}, b.Attrs)
	}
	return out, true, nil
}

func v2PresenceOutputKind(actionKind string) string {
	switch actionKind {
	case "emit source":
		return "presence_source"
	case "emit sink":
		return "presence_sink"
	case "emit check":
		return "presence_check"
	case "emit issue":
		return "presence_issue"
	default:
		return "presence"
	}
}

func lowerV2PresenceFlagExpr(alias string, expr parser.V2Expr, matchers v2MatcherResolver) (*Presence, bool, error) {
	if alias == "" {
		return nil, true, fmt.Errorf("query alias is required")
	}
	fl := &Presence{NodeKind: "any"}
	handled := false
	for _, atom := range flattenV2And(expr) {
		neg := false
		if u, ok := atom.(parser.V2UnaryExpr); ok && u.Op == "not" {
			neg = true
			atom = u.X
		}
		if handledOperand, err := lowerV2PresenceOperand(fl, alias, atom, neg, matchers); handledOperand || err != nil {
			if err != nil {
				return nil, true, err
			}
			handled = true
			continue
		}
		if handledMeta, err := lowerV2PresenceMeta(fl, alias, atom, neg); handledMeta || err != nil {
			if err != nil {
				return nil, true, err
			}
			handled = true
			continue
		}
		pred, err := lowerV2PresencePredicate(alias, "node", atom, neg, matchers)
		if err != nil {
			return nil, true, err
		}
		handled = true
		fl.Predicates = append(fl.Predicates, pred)
	}
	if !handled {
		return nil, false, nil
	}
	return fl, true, nil
}

func lowerV2PresenceOperand(fl *Presence, alias string, expr parser.V2Expr, neg bool, matchers v2MatcherResolver) (bool, error) {
	if neg {
		return false, nil
	}
	call, ok := expr.(parser.V2CallExpr)
	if !ok || call.Name != "operand" {
		return false, nil
	}
	if len(call.Args) != 1 {
		return true, fmt.Errorf("operand requires the flag alias as its positional arg")
	}
	ref, ok := call.Args[0].(parser.V2RefExpr)
	if !ok || ref.Name != alias {
		return true, fmt.Errorf("operand first arg must be %s", alias)
	}
	var where parser.V2Expr
	for _, arg := range call.NamedArgs {
		if arg.Name != "where" {
			return true, fmt.Errorf("unsupported operand arg %q", arg.Name)
		}
		where = arg.Expr
	}
	if where == nil {
		return true, fmt.Errorf("operand requires where")
	}
	var operand PresenceOperand
	for _, atom := range flattenV2And(where) {
		opNeg := false
		if u, ok := atom.(parser.V2UnaryExpr); ok && u.Op == "not" {
			opNeg = true
			atom = u.X
		}
		pred, err := lowerV2PresencePredicate("operand", "operand", atom, opNeg, matchers)
		if err != nil {
			return true, err
		}
		operand.Predicates = append(operand.Predicates, pred)
	}
	fl.Operands = append(fl.Operands, operand)
	return true, nil
}

func lowerV2PresenceMeta(fl *Presence, alias string, expr parser.V2Expr, neg bool) (bool, error) {
	if neg {
		return false, nil
	}
	b, ok := expr.(parser.V2BinaryExpr)
	if !ok || b.Op != "==" {
		return false, nil
	}
	field, ok := v2PresenceField(alias, b.Left)
	if !ok || (field != "kind" && field != "scope") {
		return false, nil
	}
	value, ok := parser.V2LiteralString(b.Right)
	if !ok {
		return true, fmt.Errorf("%s must compare to a string", field)
	}
	if field == "scope" {
		fl.Scope = value
	} else {
		fl.NodeKind = value
	}
	return true, nil
}

func lowerV2PresencePredicate(alias, defaultSubject string, expr parser.V2Expr, neg bool, matchers v2MatcherResolver) (PresencePredicate, error) {
	switch x := expr.(type) {
	case parser.V2BinaryExpr:
		return lowerV2PresenceBinary(alias, defaultSubject, x, neg, matchers)
	case parser.V2CallExpr:
		return lowerV2PresenceCall(alias, defaultSubject, x, neg)
	default:
		return PresencePredicate{}, fmt.Errorf("unsupported predicate expression %T", expr)
	}
}

func lowerV2PresenceBinary(alias, defaultSubject string, x parser.V2BinaryExpr, neg bool, matchers v2MatcherResolver) (PresencePredicate, error) {
	field, ok := v2PresenceField(alias, x.Left)
	if !ok {
		return PresencePredicate{}, fmt.Errorf("predicate left side must be %s.<field>", alias)
	}
	subject, prop, ok := v2PresenceProperty(defaultSubject, field)
	if !ok {
		return PresencePredicate{}, fmt.Errorf("unsupported predicate field %q", field)
	}
	switch x.Op {
	case "exists":
		value := prefixV2PresenceValue(field, "")
		values := []string(nil)
		if value != "" {
			values = []string{value}
		}
		return PresencePredicate{Subject: subject, Property: prop, Op: "exists", Values: values, Negative: neg}, nil
	case "~=", "==", "!=", "contains", "startsWith", "endsWith":
		value, ok := parser.V2LiteralString(x.Right)
		if !ok {
			return PresencePredicate{}, fmt.Errorf("%s predicate right side must be a string", field)
		}
		value = prefixV2PresenceValue(field, value)
		pred := PresencePredicate{Subject: subject, Property: prop, Values: []string{value}, Negative: neg != (x.Op == "!=")}
		switch {
		case prop == "path" && (x.Op == "~=" || x.Op == "==" || x.Op == "!=" || x.Op == "contains"):
			pred.Op = "match"
			pred.Exact = x.Op == "==" || x.Op == "!="
		case x.Op == "contains":
			pred.Op = "contains"
		case x.Op == "startsWith":
			pred.Op = "starts_with"
		case x.Op == "endsWith":
			pred.Op = "ends_with"
		case x.Op == "==" || x.Op == "!=":
			pred.Op = "equals"
		default:
			return PresencePredicate{}, fmt.Errorf("unsupported operator %q for %s", x.Op, field)
		}
		return pred, nil
	case "in", "not in":
		values, ok := parser.V2RuleWhereStringList(x.Right)
		if !ok {
			return PresencePredicate{}, fmt.Errorf("%s %s predicate requires a string list", field, x.Op)
		}
		values = prefixV2PresenceValues(field, values)
		return PresencePredicate{Subject: subject, Property: prop, Op: "equals_any", Values: values, Negative: neg != (x.Op == "not in")}, nil
	case "is":
		matcherName, ok := v2MatcherRef(x.Right)
		if !ok {
			return PresencePredicate{}, fmt.Errorf("%s is predicate requires a matcher name", field)
		}
		matcher, ok := matchers.resolve(matcherName)
		if !ok {
			return PresencePredicate{}, fmt.Errorf("unknown matcher %q", matcherName)
		}
		if matcher.Unsupported != "" {
			return PresencePredicate{}, fmt.Errorf("matcher %s: %s requires native matcher lowering", matcherName, matcher.Unsupported)
		}
		if matcher.Op == "matches" {
			return PresencePredicate{}, fmt.Errorf("matcher %s: regex matcher invocation requires reviewed scanner support", matcherName)
		}
		if matcher.Op == "" || len(matcher.Values) == 0 {
			return PresencePredicate{}, fmt.Errorf("matcher %s: empty matcher", matcherName)
		}
		return PresencePredicate{Subject: subject, Property: prop, Op: matcher.Op, Values: prefixV2PresenceValues(field, matcher.Values), Negative: neg}, nil
	default:
		return PresencePredicate{}, fmt.Errorf("unsupported operator %q", x.Op)
	}
}

func lowerV2PresenceCall(alias, defaultSubject string, x parser.V2CallExpr, neg bool) (PresencePredicate, error) {
	if x.Name != "containsAny" {
		return PresencePredicate{}, fmt.Errorf("unsupported call %q", x.Name)
	}
	if len(x.Args) != 2 || len(x.NamedArgs) != 0 {
		return PresencePredicate{}, fmt.Errorf("containsAny requires two positional args")
	}
	field, ok := v2PresenceField(alias, x.Args[0])
	if !ok {
		return PresencePredicate{}, fmt.Errorf("containsAny first arg must be %s.<field>", alias)
	}
	subject, prop, ok := v2PresenceProperty(defaultSubject, field)
	if !ok {
		return PresencePredicate{}, fmt.Errorf("unsupported predicate field %q", field)
	}
	values, ok := parser.V2RuleWhereStringList(x.Args[1])
	if !ok {
		return PresencePredicate{}, fmt.Errorf("containsAny second arg must be a string list")
	}
	values = prefixV2PresenceValues(field, values)
	return PresencePredicate{Subject: subject, Property: prop, Op: "contains_any", Values: values, Negative: neg}, nil
}

func v2PresenceField(alias string, expr parser.V2Expr) (string, bool) {
	ref, ok := expr.(parser.V2RefExpr)
	if !ok {
		return "", false
	}
	prefix := alias + "."
	if !strings.HasPrefix(ref.Name, prefix) {
		return "", false
	}
	return strings.TrimPrefix(ref.Name, prefix), true
}

func v2PresenceProperty(defaultSubject, field string) (string, string, bool) {
	if rest, ok := strings.CutPrefix(field, "scopeCall."); ok {
		return "scope_call", rest, true
	}
	if rest, ok := strings.CutPrefix(field, "scope_call."); ok {
		return "scope_call", rest, true
	}
	if rest, ok := strings.CutPrefix(field, "flowTo."); ok {
		return "flow_to", rest, true
	}
	if rest, ok := strings.CutPrefix(field, "flow_to."); ok {
		return "flow_to", rest, true
	}
	if rest, ok := strings.CutPrefix(field, "prop."); ok {
		return defaultSubject, rest, true
	}
	if field == "context.scopeCall" || field == "context.inScopeCall" {
		return "scope_call", "any", true
	}
	if field == "analysis" {
		return defaultSubject, "path", true
	}
	if _, ok := strings.CutPrefix(field, "context."); ok {
		if v2PresenceValuePrefix(field) != "" {
			return defaultSubject, "tokens", true
		}
	}
	switch field {
	case "path":
		return defaultSubject, "path", true
	case "method":
		return defaultSubject, "method", true
	case "token":
		return defaultSubject, "tokens", true
	case "arg", "args", "valueToken":
		return defaultSubject, "tokens", true
	case "op", "identifier", "key", "any":
		return defaultSubject, field, true
	default:
		return "", "", false
	}
}

func prefixV2PresenceValue(field, value string) string {
	prefix := v2PresenceValuePrefix(field)
	if prefix == "" || strings.HasPrefix(value, prefix) {
		return value
	}
	return prefix + value
}

func prefixV2PresenceValues(field string, values []string) []string {
	prefix := v2PresenceValuePrefix(field)
	if prefix == "" {
		return values
	}
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = value
		if !strings.HasPrefix(value, prefix) {
			out[i] = prefix + value
		}
	}
	return out
}

func v2PresenceValuePrefix(field string) string {
	if field == "analysis" {
		return "analysis."
	}
	if !strings.HasPrefix(field, "context.") {
		return ""
	}
	field = strings.TrimPrefix(field, "context.")
	switch field {
	case "language":
		return "lang="
	case "name":
		return "name="
	case "abi":
		return "abi="
	case "callPath":
		return "call_path:"
	case "call":
		return "call:"
	case "callArg":
		return "call_arg:"
	case "callArgAt":
		return "call_arg_at:"
	case "callArgShape":
		return "call_arg_shape:"
	case "callArgShapeAt":
		return "call_arg_shape_at:"
	case "callMethod":
		return "call_method:"
	case "callOrder":
		return "call_order:"
	case "entryKind":
		return "entry_kind:"
	case "functionParamType":
		return "function_param_type:"
	case "functionName":
		return "function_name:"
	case "functionVisibility":
		return "function_visibility:"
	case "category":
		return "category:"
	case "vulnerable":
		return "vulnerable:"
	case "className":
		return "class_name:"
	case "classBase":
		return "class_base:"
	case "classAttribute":
		return "class_attribute:"
	case "classAnnotation":
		return "class_annotation:"
	case "methodAttribute":
		return "method_attribute:"
	case "attrName":
		return "attr_name:"
	case "selector":
		return "selector:"
	case "literal":
		return "literal:"
	case "regex":
		return "regex:"
	case "identifier":
		return "identifier:"
	case "expr":
		return "expr:"
	case "annotation":
		return "annotation:"
	case "attrPath":
		return "attr_path:"
	case "paramName":
		return "param_name:"
	case "paramType":
		return "param_type:"
	case "binary":
		return "binary:"
	case "binaryShape":
		return "binary_shape:"
	case "assign":
		return "assign:"
	case "assignShape":
		return "assign_shape:"
	case "assignOpShape":
		return "assign_op_shape:"
	case "appendCopy":
		return "append_copy:"
	case "subscript":
		return "subscript:"
	case "subscriptShape":
		return "subscript_shape:"
	case "slice":
		return "slice:"
	case "field":
		return "field:"
	case "fieldTag":
		return "field_tag:"
	case "macroName":
		return "macro_name:"
	case "macroBody":
		return "macro_body:"
	case "catchType":
		return "catch_type:"
	case "prop":
		return "prop:"
	case "index":
		return "index:"
	case "indexBase":
		return "index_base:"
	case "indexKind":
		return "index_kind="
	case "guard":
		return "guard="
	case "indexShape":
		return "index_shape:"
	case "lengthCheck":
		return "length_check:"
	case "indexKey":
		return "index_key:"
	case "globalSubscriptWrite":
		return "global_subscript_write="
	case "prototypeNameGuard":
		return "prototype_name_guard="
	case "gitCloneArgvMissingDelimiter":
		return "git_clone_argv_missing_delimiter="
	case "tlsRejectUnauthorizedDisabledDefault":
		return "tls_reject_unauthorized_disabled_default="
	case "tlsRejectUnauthorizedPropagated":
		return "tls_reject_unauthorized_propagated="
	case "foldedHeaderCurrentGuard":
		return "folded_header_current_guard="
	case "prototypeKeyGuard":
		return "prototype_key_guard="
	case "pathSegmentTypeGuard":
		return "path_segment_type_guard="
	case "ownPropertyKeyGuard":
		return "own_property_key_guard="
	case "forIn":
		return "for_in="
	case "objectKeysForEach":
		return "object_keys_for_each="
	case "dynamicPropertyWrite":
		return "dynamic_property_write="
	case "dynamicPropertyWriteObjectLiteral":
		return "dynamic_property_write_object_literal="
	case "dynamicPropertyWriteArrayLiteral":
		return "dynamic_property_write_array_literal="
	case "dynamicPropertyWriteFromSubscript":
		return "dynamic_property_write_from_subscript="
	case "dynamicPropertyWriteFromCall":
		return "dynamic_property_write_from_call="
	case "dynamicPropertyPlainObjectFallback":
		return "dynamic_property_plain_object_fallback="
	case "zeroStepSequenceRisk":
		return "zero_step_sequence_risk="
	case "convertSvgMultiSvgSanitizerBypass":
		return "convert_svg_multi_svg_sanitizer_bypass="
	case "incompleteGeneratedJsIdentifierReservedWords":
		return "incomplete_generated_js_identifier_reserved_words="
	case "ajaxBackslashProtocolRelativeUrlXss":
		return "ajax_backslash_protocol_relative_url_xss="
	case "cryptoJsRandomFloatWordArrayRisk":
		return "cryptojs_random_float_wordarray_risk="
	case "return":
		return "return:"
	case "returnCallPath":
		return "return_call_path:"
	case "returnIdentifier":
		return "return_identifier:"
	case "returnType":
		return "return_type:"
	case "metadataExportAfterSensitiveKey":
		return "metadata_export_after_sensitive_key:"
	case "metadataExportAfterSensitiveSource":
		return "metadata_export_after_sensitive_source:"
	case "metadataExportWriter":
		return "metadata_export_writer:"
	case "advisoryCwe":
		return "advisory_cwe="
	case "status":
		return "status="
	case "reachable":
		return "reachable="
	case "shellBridge":
		return "shell_bridge:"
	case "startupOrder":
		return "startup_order:"
	case "csrfValidation":
		return "csrf_validation:"
	case "redirectFlow":
		return "redirect_flow:"
	case "rsaPkcs1":
		return "rsa_pkcs1:"
	case "portProtocol":
		return "port_protocol:"
	case "rubyReview":
		return "ruby_review:"
	case "rustReview":
		return "rust_review:"
	case "pythonReview":
		return "python_review:"
	case "phpReview":
		return "php_review:"
	case "annotationArg":
		return "annotation_arg:"
	case "assignCall":
		return "assign_call:"
	case "assignCallMethod":
		return "assign_call_method:"
	case "assignItem":
		return "assign_item:"
	case "assignLiteral":
		return "assign_literal:"
	case "callBefore":
		return "call_before:"
	case "castCallLiteral":
		return "cast_call_literal:"
	case "castShape":
		return "cast_shape:"
	case "checkedShape":
		return "checked_shape:"
	case "classModifier":
		return "class_modifier:"
	case "decoratorMethod":
		return "decorator_method:"
	case "decoratorPath":
		return "decorator_path:"
	case "fieldType":
		return "field_type:"
	case "functionModifier":
		return "function_modifier:"
	case "method":
		return "method:"
	case "matchArm":
		return "match_arm:"
	case "paramIndex":
		return "param_index:"
	case "paramLabel":
		return "param_label:"
	case "repr":
		return "repr:"
	case "serdeAttr":
		return "serde_attr:"
	case "noNetwork":
		return "no_network:"
	case "resolveEntities":
		return "resolve_entities:"
	case "value":
		return "value:"
	case "erbValue":
		return "value="
	case "template":
		return "template="
	case "attr":
		return "attr="
	case "const":
		return "const:"
	case "switchCase":
		return "switch_case:"
	case "varName":
		return "var_name:"
	default:
		return ""
	}
}

func v2PresencePredicatesKey(preds []PresencePredicate) string {
	if len(preds) == 0 {
		return ""
	}
	parts := make([]string, 0, len(preds))
	for _, pred := range preds {
		parts = append(parts, strings.Join([]string{
			pred.Subject,
			pred.Property,
			pred.Op,
			strings.Join(pred.Values, "\x1f"),
			strconv.FormatBool(pred.Exact),
			strconv.FormatBool(pred.Negative),
		}, "\x1e"))
	}
	return strings.Join(parts, "\x1d")
}
