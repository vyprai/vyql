package lowering

import (
	"github.com/vyprai/vyql/internal/extract/nir"
)

func (l *lowerer) builtinLenCall(expr nir.Expr, sc *scope) bool {
	call, ok := expr.(nir.Call)
	if !ok || call.Method != "len" || len(call.Args) != 1 {
		return false
	}
	name, ok := call.Callee.(nir.Name)
	if !ok || name.ID != "len" || sc.node["len"] != "" {
		return false
	}
	if l.importTables[l.curModule]["len"].module != "" || len(l.funcShort["len"]) != 0 {
		return false
	}
	return true
}

func (l *lowerer) nonNegativeLenFact(expr nir.Expr, sc *scope) (bool, bool) {
	cmp, ok := expr.(nir.BinOp)
	if !ok {
		return false, false
	}
	leftLen, rightLen := l.builtinLenCall(cmp.Left, sc), l.builtinLenCall(cmp.Right, sc)
	leftZero, leftOK := l.constInt(cmp.Left, sc)
	rightZero, rightOK := l.constInt(cmp.Right, sc)
	switch {
	case leftLen && rightOK && rightZero == 0 && cmp.Op == ">=":
		return true, true
	case leftLen && rightOK && rightZero == 0 && cmp.Op == "<":
		return false, true
	case rightLen && leftOK && leftZero == 0 && cmp.Op == "<=":
		return true, true
	case rightLen && leftOK && leftZero == 0 && cmp.Op == ">":
		return false, true
	}
	return false, false
}
