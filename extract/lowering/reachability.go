package lowering

import "github.com/vyprai/vyql/extract/nir"

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

func (l *lowerer) blockDefinitelyExits(stmts []nir.Stmt, sc *scope) bool {
	for _, stmt := range stmts {
		if l.stmtDefinitelyExits(stmt, sc) {
			return true
		}
	}
	return false
}

func (l *lowerer) stmtDefinitelyExits(stmt nir.Stmt, sc *scope) bool {
	switch st := stmt.(type) {
	case nir.Return, nir.Terminate:
		return true
	case nir.Block:
		return l.blockDefinitelyExits(st.Stmts, sc)
	case nir.If:
		if live, ok := l.constBool(st.Cond, sc); ok {
			if live {
				return l.blockDefinitelyExits(st.Then, sc)
			}
			return l.blockDefinitelyExits(st.Else, sc)
		}
		return len(st.Then) > 0 && len(st.Else) > 0 &&
			l.blockDefinitelyExits(st.Then, sc) && l.blockDefinitelyExits(st.Else, sc)
	}
	return false
}
