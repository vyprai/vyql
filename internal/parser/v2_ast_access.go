package parser

// V2LiteralString and V2NormalizedCodeFamily are AST accessors the binding compiler needs
// as well as this package's own validation. They are exported rather than copied: both
// answer a question about the definition language, and two copies of that answer would
// drift.

func V2LiteralString(expr V2Expr) (string, bool) {
	lit, ok := expr.(V2LiteralExpr)
	if !ok {
		return "", false
	}
	s, ok := lit.Value.(string)
	return s, ok
}

func V2NormalizedCodeFamily(family string) string {
	switch family {
	case "callExpr", "node":
		return "call"
	default:
		return family
	}
}
