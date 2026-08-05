package treesitter

import (
	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/vyprai/vyql/internal/extract/nir"
)

func (c *pyConv) pyTerminalRejectValidation(loop *tree_sitter.Node) (nir.Validation, bool) {
	if loop == nil || loop.Kind() != "for_statement" || pyNodeContains(loop, "break_statement") || pyDirectChild(loop, "else_clause") != nil {
		return nir.Validation{}, false
	}
	vars := c.targets(field(loop, "left"))
	iter := field(loop, "right")
	body := field(loop, "body")
	if len(vars) != 1 || iter == nil || body == nil {
		return nir.Validation{}, false
	}
	var target string
	matches := 0
	for _, stmt := range namedChildren(body) {
		if stmt.Kind() != "if_statement" {
			continue
		}
		cond, ok := c.expr(field(stmt, "condition")).(nir.BinOp)
		if !ok || cond.Op != "in" {
			continue
		}
		needle, ok := cond.Left.(nir.Name)
		if !ok || needle.ID != vars[0] {
			continue
		}
		candidate, ok := pyValidationTarget(cond.Right)
		if !ok {
			continue
		}
		if _, terminal := c.pyTerminalBranchKind(field(stmt, "consequence")); !terminal {
			continue
		}
		target, matches = candidate, matches+1
	}
	if matches != 1 {
		return nir.Validation{}, false
	}
	return nir.Validation{Target: target, Evidence: c.expr(iter), Kind: "character_rejection", Loc: c.loc(loop)}, true
}

func pyValidationTarget(expr nir.Expr) (string, bool) {
	if name, ok := expr.(nir.Name); ok && name.ID != "" {
		return name.ID, true
	}
	call, ok := expr.(nir.Call)
	if !ok || call.Method != "lower" || len(call.Args) != 0 {
		return "", false
	}
	attr, ok := call.Callee.(nir.Attr)
	if !ok {
		return "", false
	}
	name, ok := attr.Base.(nir.Name)
	return name.ID, ok && name.ID != ""
}

func pyDirectChild(node *tree_sitter.Node, kind string) *tree_sitter.Node {
	for _, child := range namedChildren(node) {
		if child.Kind() == kind {
			return child
		}
	}
	return nil
}

func pyNodeContains(node *tree_sitter.Node, kind string) bool {
	if node == nil {
		return false
	}
	for _, child := range namedChildren(node) {
		if child.Kind() == kind || pyNodeContains(child, kind) {
			return true
		}
	}
	return false
}
