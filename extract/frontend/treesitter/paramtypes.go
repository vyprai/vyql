package treesitter

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

func cleanTypeName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "()")
	s = strings.TrimPrefix(s, "*")
	s = strings.TrimPrefix(s, "&")
	s = strings.TrimSuffix(s, "*")
	s = strings.TrimSuffix(s, "&")
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, ":")
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") && strings.Contains(s, "]") {
		s = strings.TrimPrefix(s, "[")
		if i := strings.Index(s, "]"); i >= 0 {
			s = s[:i]
		}
	}
	for _, p := range []string{"const ", "final ", "mut ", "readonly ", "ref ", "out ", "in "} {
		s = strings.TrimPrefix(s, p)
	}
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "?")
	s = strings.TrimSuffix(s, "!")
	if i := strings.IndexAny(s, "<["); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if i := strings.LastIndexAny(s, " \t\n\r"); i >= 0 {
		s = strings.TrimSpace(s[i+1:])
	}
	return s
}

func putParamType(out map[string]string, name, typ string) {
	name = strings.TrimSpace(name)
	typ = cleanTypeName(typ)
	if name == "" || typ == "" {
		return
	}
	out[name] = typ
}

func paramTypeFromField(c interface {
	text(*tree_sitter.Node) string
}, n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	if typ := field(n, "type"); typ != nil {
		return c.text(typ)
	}
	for _, ch := range namedChildren(n) {
		switch ch.Kind() {
		case "type", "type_identifier", "predefined_type", "generic_name", "qualified_name",
			"scoped_type_identifier", "user_type", "simple_type", "nullable_type",
			"array_type", "pointer_type", "reference_type", "optional_type",
			"navigation_expression", "type_annotation", "type_literal", "type_constraint":
			return c.text(ch)
		}
	}
	return ""
}
