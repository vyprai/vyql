package bindings

import (
	"strings"
)

// Compiled from authored v2 binding declarations -- authored field names to the extractor token prefixes they select.

func v2AssignmentTokenPrefix(field string) (string, bool) {
	switch field {
	case "assignment.any":
		return "assign:", true
	case "assignment.target", "assignment.targetValue":
		return "assign:", true
	case "assignment.value":
		return "=", true
	case "assignment.call":
		return "assign_call:", true
	case "assignment.callMethod":
		return "assign_call_method:", true
	case "assignment.item":
		return "assign_item:", true
	case "assignment.literal":
		return "assign_literal:", true
	default:
		return "", false
	}
}

func v2ArgsAnyContextField(field string) (string, string, bool) {
	for _, prefix := range []string{"args.any.context.", "call.args.any.context."} {
		if rest, ok := strings.CutPrefix(field, prefix); ok {
			if valuePrefix := v2ArgsAnyContextValuePrefix(rest); valuePrefix != "" {
				return rest, valuePrefix, true
			}
		}
	}
	return "", "", false
}

func v2ArgsAnyContextValuePrefix(field string) string {
	switch field {
	case "firstParam":
		return "first_param:"
	case "hasParamType":
		return "has_param_type:"
	case "noNetwork":
		return "no_network="
	case "resolveEntities":
		return "resolve_entities="
	case "value":
		return "value="
	default:
		return v2PresenceValuePrefix("context." + field)
	}
}

func v2CallQueryField(name, family string) string {
	if mapped := v2MappedCallQueryField(name, family); mapped != "" {
		return mapped
	}
	if _, rest, ok := strings.Cut(name, "."); ok && v2IsKnownCallQueryField(rest) {
		return rest
	}
	if _, rest, ok := strings.Cut(name, "."); ok {
		if mapped := v2MappedCallQueryField(rest, family); mapped != "" {
			return mapped
		}
	}
	return name
}

func v2MappedCallQueryField(name, family string) string {
	if family == "assignment" {
		switch name {
		case "any", "assignment.any":
			return "assignment.any"
		case "target", "assignment.target":
			return "assignment.target"
		case "value", "assignment.value":
			return "assignment.value"
		case "targetValue", "text", "assignment.targetValue", "assignment.text":
			return "assignment.targetValue"
		case "call", "assignment.call":
			return "assignment.call"
		case "callMethod", "assignment.callMethod":
			return "assignment.callMethod"
		case "item", "assignment.item":
			return "assignment.item"
		case "literal", "assignment.literal":
			return "assignment.literal"
		}
	}
	switch name {
	case "property", "memberAccess.property":
		return "callee.method"
	case "path", "memberAccess.path":
		return "callee.path"
	case "operator", "op", "binaryExpr.operator", "binaryExpr.op":
		return "operator"
	case "value", "raw", "literal.value", "literal.raw", "stringLiteral.value", "stringLiteral.raw":
		return "node.value"
	case "name", "function.name", "class.name":
		return "node.name"
	case "module", "import.module", "import.symbol", "import.package":
		return "node.module"
	case "assignment.any":
		return "assignment.any"
	case "assignment.target":
		return "assignment.target"
	case "assignment.value":
		return "assignment.value"
	case "assignment.targetValue", "assignment.text":
		return "assignment.targetValue"
	case "assignment.call":
		return "assignment.call"
	case "assignment.callMethod":
		return "assignment.callMethod"
	case "assignment.item":
		return "assignment.item"
	case "assignment.literal":
		return "assignment.literal"
	default:
		if v2IsKnownCallQueryField(name) {
			return name
		}
		return ""
	}
}

func v2IsKnownCallQueryField(name string) bool {
	switch name {
	case "callee.method", "call.callee.method", "callee.path", "call.callee.path",
		"callee.analysis", "call.callee.analysis",
		"callee.receiver.type", "call.callee.receiver.type",
		"node.value", "node.name", "node.module",
		"assignment.any", "assignment.target", "assignment.value", "assignment.targetValue",
		"assignment.call", "assignment.callMethod", "assignment.item", "assignment.literal",
		"scope.call.method", "scope.call.path",
		"args.any.literal", "call.args.any.literal",
		"args.count", "call.args.count",
		"call.filter.global", "filter.global":
		return true
	default:
		return false
	}
}
