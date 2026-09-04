package parsecache

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// deferredBodyChunkNodes bounds the amount of NIR decoded at once. It is a semantic-node
// estimate rather than a statement count: generated code often hides thousands of expressions
// under one statement. Nested statement lists are deferred before their parent is measured, so
// one deeply nested generated function cannot smuggle all of its branch bodies into one chunk.
const deferredBodyChunkNodes = 4096

// DeferModuleBodies replaces every function/lambda body in m with content-addressed body
// references. The module's outer declaration list remains inline: pass 1 needs those cheap
// signatures to construct the global symbol table before any body is lowered.
func (c *Cache) DeferModuleBodies(m *nir.Module) {
	if c == nil || m == nil || len(m.Body) == 0 {
		return
	}
	m.Body = c.prepareStmtList(m.Body)
}

// DeferFunctionBody persists a completed function body immediately. Frontends with a central
// function converter use this before moving to the next function, so repository-size memory is
// bounded by one active frontend body rather than the sum of every body parsed so far.
func (c *Cache) DeferFunctionBody(body []nir.Stmt) []nir.Stmt {
	if c == nil || len(body) == 0 {
		return body
	}
	return c.storeStmtList(c.prepareStmtList(body), true)
}

// MaybeDeferStatements recursively defers oversized statement lists while a frontend is still
// constructing a function. It is cheap for small lists and lets native frontends flush large
// branch/block bodies before their enclosing generated function has finished conversion.
func (c *Cache) MaybeDeferStatements(stmts []nir.Stmt) []nir.Stmt {
	if c == nil || len(stmts) == 0 {
		return stmts
	}
	return c.storeStmtList(c.prepareStmtList(stmts), false)
}

func (c *Cache) prepareStmtList(stmts []nir.Stmt) []nir.Stmt {
	for i, st := range stmts {
		stmts[i] = c.prepareStmt(st)
	}
	return stmts
}

func (c *Cache) prepareStmt(st nir.Stmt) nir.Stmt {
	switch s := st.(type) {
	case nil, nir.BodyRef:
		return st
	case nir.Assign:
		s.Value = c.prepareExpr(s.Value)
		return s
	case nir.AugAssign:
		s.Value = c.prepareExpr(s.Value)
		return s
	case nir.Return:
		s.Value = c.prepareExpr(s.Value)
		return s
	case nir.Validation:
		s.Evidence = c.prepareExpr(s.Evidence)
		return s
	case nir.Terminate:
		s.Value = c.prepareExpr(s.Value)
		return s
	case nir.ExprStmt:
		s.Value = c.prepareExpr(s.Value)
		return s
	case nir.FuncDef:
		s.Body = c.DeferFunctionBody(s.Body)
		return s
	case nir.ClassDef:
		s.Body = c.prepareStmtList(s.Body)
		return s
	case nir.Block:
		s.Stmts = c.MaybeDeferStatements(s.Stmts)
		return s
	case nir.If:
		s.Cond = c.prepareExpr(s.Cond)
		s.Then = c.MaybeDeferStatements(s.Then)
		s.Else = c.MaybeDeferStatements(s.Else)
		return s
	case nir.Loop:
		s.Cond = c.prepareExpr(s.Cond)
		s.Iter = c.prepareExpr(s.Iter)
		s.Body = c.MaybeDeferStatements(s.Body)
		return s
	case nir.Switch:
		s.Subject = c.prepareExpr(s.Subject)
		for i := range s.Cases {
			s.Cases[i] = c.MaybeDeferStatements(s.Cases[i])
		}
		for i := range s.Labels {
			for j := range s.Labels[i] {
				s.Labels[i][j] = c.prepareExpr(s.Labels[i][j])
			}
		}
		s.Default = c.MaybeDeferStatements(s.Default)
		return s
	case nir.Try:
		s.Body = c.MaybeDeferStatements(s.Body)
		for i := range s.Handlers {
			s.Handlers[i] = c.MaybeDeferStatements(s.Handlers[i])
		}
		s.Finally = c.MaybeDeferStatements(s.Finally)
		return s
	case nir.Defer:
		s.Body = c.MaybeDeferStatements(s.Body)
		return s
	default:
		return st
	}
}

func (c *Cache) prepareExpr(ex nir.Expr) nir.Expr {
	switch e := ex.(type) {
	case nil, nir.Name, nir.Const:
		return ex
	case nir.Attr:
		e.Base = c.prepareExpr(e.Base)
		return e
	case nir.Index:
		e.Base = c.prepareExpr(e.Base)
		e.Key = c.prepareExpr(e.Key)
		return e
	case nir.Call:
		e.Callee = c.prepareExpr(e.Callee)
		for i := range e.Args {
			e.Args[i] = c.prepareExpr(e.Args[i])
		}
		return e
	case nir.Format:
		for i := range e.Parts {
			e.Parts[i] = c.prepareExpr(e.Parts[i])
		}
		return e
	case nir.Seq:
		for i := range e.Parts {
			e.Parts[i] = c.prepareExpr(e.Parts[i])
		}
		return e
	case nir.Pair:
		e.Value = c.prepareExpr(e.Value)
		return e
	case nir.Lambda:
		e.Body = c.DeferFunctionBody(e.Body)
		return e
	case nir.Thru:
		e.Inner = c.prepareExpr(e.Inner)
		return e
	case nir.BinOp:
		e.Left = c.prepareExpr(e.Left)
		e.Right = c.prepareExpr(e.Right)
		return e
	case nir.Unary:
		e.Operand = c.prepareExpr(e.Operand)
		return e
	case nir.Ternary:
		e.Cond = c.prepareExpr(e.Cond)
		e.Then = c.prepareExpr(e.Then)
		e.Else = c.prepareExpr(e.Else)
		return e
	default:
		return ex
	}
}

func (c *Cache) storeStmtList(stmts []nir.Stmt, force bool) []nir.Stmt {
	if len(stmts) == 0 || (len(stmts) == 1 && isBodyRef(stmts[0])) {
		return stmts
	}
	weight := 0
	for _, st := range stmts {
		weight += stmtWeight(st)
	}
	if !force && weight < deferredBodyChunkNodes {
		return stmts
	}
	keys := make([]string, 0, weight/deferredBodyChunkNodes+1)
	start, chunkWeight := 0, 0
	for i, st := range stmts {
		w := stmtWeight(st)
		if i > start && chunkWeight+w > deferredBodyChunkNodes {
			key := c.putBodyChunk(stmts[start:i])
			if key == "" {
				return stmts // never publish a partial body
			}
			keys = append(keys, key)
			start, chunkWeight = i, 0
		}
		chunkWeight += w
	}
	if start < len(stmts) {
		key := c.putBodyChunk(stmts[start:])
		if key == "" {
			return stmts // never publish a partial body
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return stmts // best-effort cache failure must not discard executable NIR
	}
	return []nir.Stmt{nir.BodyRef{Keys: keys, Summarized: true, Summary: summarizeBody(stmts)}}
}

func isBodyRef(st nir.Stmt) bool {
	_, ok := st.(nir.BodyRef)
	return ok
}

func (c *Cache) putBodyChunk(stmts []nir.Stmt) string {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(stmts); err != nil {
		return ""
	}
	raw := buf.Bytes()
	sum := sha256.Sum256(raw)
	key := "body\x00" + hex.EncodeToString(sum[:])
	if !c.putRaw(key, raw) {
		return ""
	}
	return key
}

func summarizeBody(stmts []nir.Stmt) nir.BodySummary {
	local := map[string]bool{}
	used := map[string]bool{}
	addressed := map[string]bool{}
	var declarations []nir.Stmt
	var context []string
	summarizeLocalDecls(stmts, local)
	for _, st := range stmts {
		summarizeUsedNames(st, used)
	}
	summarizeAddressTakenStmts(stmts, addressed)
	for _, st := range stmts {
		switch s := st.(type) {
		case nir.BodyRef:
			if s.Summarized {
				declarations = append(declarations, s.Summary.Declarations...)
			}
		case nir.FuncDef, nir.ClassDef:
			declarations = append(declarations, st)
		}
	}
	summarizeContextTokens(stmts, &context)
	return nir.BodySummary{
		Declarations:  declarations,
		LocalDecls:    sortedSet(local),
		UsedNames:     sortedSet(used),
		AddressTaken:  sortedSet(addressed),
		ContextTokens: context,
	}
}

func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func summarizeLocalDecls(stmts []nir.Stmt, out map[string]bool) {
	for _, st := range stmts {
		switch s := st.(type) {
		case nir.BodyRef:
			if s.Summarized {
				for _, name := range s.Summary.LocalDecls {
					out[name] = true
				}
			}
		case nir.Assign:
			if s.Decl {
				for _, target := range s.Targets {
					if target != "" && !strings.ContainsAny(target, ".[") {
						out[target] = true
					}
				}
			}
		case nir.FuncDef:
			if s.Name != "" {
				out[s.Name] = true
			}
		case nir.ClassDef:
			if s.Name != "" {
				out[s.Name] = true
			}
		case nir.Block:
			summarizeLocalDecls(s.Stmts, out)
		case nir.If:
			summarizeLocalDecls(s.Then, out)
			summarizeLocalDecls(s.Else, out)
		case nir.Loop:
			for _, name := range s.Vars {
				if name != "" && !strings.ContainsAny(name, ".[") {
					out[name] = true
				}
			}
			summarizeLocalDecls(s.Body, out)
		case nir.Switch:
			for _, body := range s.Cases {
				summarizeLocalDecls(body, out)
			}
			summarizeLocalDecls(s.Default, out)
		case nir.Try:
			summarizeLocalDecls(s.Body, out)
			for _, body := range s.Handlers {
				summarizeLocalDecls(body, out)
			}
			summarizeLocalDecls(s.Finally, out)
		case nir.Defer:
			summarizeLocalDecls(s.Body, out)
		}
	}
}

func summarizeUsedNames(st nir.Stmt, out map[string]bool) {
	switch s := st.(type) {
	case nir.BodyRef:
		if s.Summarized {
			for _, name := range s.Summary.UsedNames {
				out[name] = true
			}
		}
	case nir.Assign:
		if !s.Decl {
			for _, target := range s.Targets {
				if target != "" && !strings.ContainsAny(target, ".[") {
					out[target] = true
				}
			}
		}
		summarizeUsedExpr(s.Value, out)
	case nir.AugAssign:
		if s.Target != "" {
			out[s.Target] = true
		}
		summarizeUsedExpr(s.Value, out)
	case nir.Return:
		summarizeUsedExpr(s.Value, out)
	case nir.Validation:
		summarizeUsedExpr(s.Evidence, out)
	case nir.Terminate:
		summarizeUsedExpr(s.Value, out)
	case nir.ExprStmt:
		summarizeUsedExpr(s.Value, out)
	case nir.Defer:
		for _, child := range s.Body {
			summarizeUsedNames(child, out)
		}
	case nir.Block:
		for _, child := range s.Stmts {
			summarizeUsedNames(child, out)
		}
	case nir.If:
		summarizeUsedExpr(s.Cond, out)
		for _, body := range [][]nir.Stmt{s.Then, s.Else} {
			for _, child := range body {
				summarizeUsedNames(child, out)
			}
		}
	case nir.Loop:
		summarizeUsedExpr(s.Cond, out)
		summarizeUsedExpr(s.Iter, out)
		for _, child := range s.Body {
			summarizeUsedNames(child, out)
		}
	case nir.Switch:
		summarizeUsedExpr(s.Subject, out)
		for _, labels := range s.Labels {
			for _, label := range labels {
				summarizeUsedExpr(label, out)
			}
		}
		for _, body := range s.Cases {
			for _, child := range body {
				summarizeUsedNames(child, out)
			}
		}
		for _, child := range s.Default {
			summarizeUsedNames(child, out)
		}
	case nir.Try:
		bodies := append([][]nir.Stmt{s.Body}, s.Handlers...)
		bodies = append(bodies, s.Finally)
		for _, body := range bodies {
			for _, child := range body {
				summarizeUsedNames(child, out)
			}
		}
	}
}

func summarizeUsedExpr(ex nir.Expr, out map[string]bool) {
	switch e := ex.(type) {
	case nir.Name:
		if e.ID != "" {
			out[e.ID] = true
		}
	case nir.Attr:
		summarizeUsedExpr(e.Base, out)
	case nir.Index:
		summarizeUsedExpr(e.Base, out)
		summarizeUsedExpr(e.Key, out)
	case nir.Call:
		summarizeUsedExpr(e.Callee, out)
		for _, a := range e.Args {
			summarizeUsedExpr(a, out)
		}
	case nir.Format:
		for _, p := range e.Parts {
			summarizeUsedExpr(p, out)
		}
	case nir.Seq:
		for _, p := range e.Parts {
			summarizeUsedExpr(p, out)
		}
	case nir.Pair:
		summarizeUsedExpr(e.Value, out)
	case nir.Thru:
		summarizeUsedExpr(e.Inner, out)
	case nir.BinOp:
		summarizeUsedExpr(e.Left, out)
		summarizeUsedExpr(e.Right, out)
	case nir.Unary:
		summarizeUsedExpr(e.Operand, out)
	case nir.Ternary:
		summarizeUsedExpr(e.Cond, out)
		summarizeUsedExpr(e.Then, out)
		summarizeUsedExpr(e.Else, out)
	}
}

func summarizeAddressTakenStmts(stmts []nir.Stmt, out map[string]bool) {
	for _, st := range stmts {
		switch s := st.(type) {
		case nir.BodyRef:
			if s.Summarized {
				for _, name := range s.Summary.AddressTaken {
					out[name] = true
				}
			}
		case nir.ExprStmt:
			summarizeAddressTakenExpr(s.Value, out)
		case nir.Assign:
			summarizeAddressTakenExpr(s.Value, out)
		case nir.AugAssign:
			summarizeAddressTakenExpr(s.Value, out)
		case nir.Return:
			summarizeAddressTakenExpr(s.Value, out)
		case nir.Validation:
			summarizeAddressTakenExpr(s.Evidence, out)
		case nir.Terminate:
			summarizeAddressTakenExpr(s.Value, out)
		case nir.FuncDef:
			summarizeAddressTakenStmts(s.Body, out)
		case nir.ClassDef:
			summarizeAddressTakenStmts(s.Body, out)
		case nir.Block:
			summarizeAddressTakenStmts(s.Stmts, out)
		case nir.If:
			summarizeAddressTakenExpr(s.Cond, out)
			summarizeAddressTakenStmts(s.Then, out)
			summarizeAddressTakenStmts(s.Else, out)
		case nir.Loop:
			summarizeAddressTakenExpr(s.Cond, out)
			summarizeAddressTakenExpr(s.Iter, out)
			summarizeAddressTakenStmts(s.Body, out)
		case nir.Switch:
			summarizeAddressTakenExpr(s.Subject, out)
			for _, body := range s.Cases {
				summarizeAddressTakenStmts(body, out)
			}
			for _, labels := range s.Labels {
				for _, label := range labels {
					summarizeAddressTakenExpr(label, out)
				}
			}
			summarizeAddressTakenStmts(s.Default, out)
		case nir.Try:
			summarizeAddressTakenStmts(s.Body, out)
			for _, body := range s.Handlers {
				summarizeAddressTakenStmts(body, out)
			}
			summarizeAddressTakenStmts(s.Finally, out)
		case nir.Defer:
			summarizeAddressTakenStmts(s.Body, out)
		}
	}
}

func summarizeAddressTakenExpr(ex nir.Expr, out map[string]bool) {
	switch e := ex.(type) {
	case nir.Name:
		out[e.ID] = true
	case nir.Attr:
		out[e.Attr] = true
		summarizeAddressTakenExpr(e.Base, out)
	case nir.Index:
		summarizeAddressTakenExpr(e.Base, out)
		summarizeAddressTakenExpr(e.Key, out)
	case nir.Call:
		switch callee := e.Callee.(type) {
		case nir.Name:
		case nir.Attr:
			summarizeAddressTakenExpr(callee.Base, out)
		default:
			summarizeAddressTakenExpr(e.Callee, out)
		}
		for _, a := range e.Args {
			summarizeAddressTakenExpr(a, out)
		}
	case nir.Format:
		for _, p := range e.Parts {
			summarizeAddressTakenExpr(p, out)
		}
	case nir.Seq:
		for _, p := range e.Parts {
			summarizeAddressTakenExpr(p, out)
		}
	case nir.Pair:
		summarizeAddressTakenExpr(e.Value, out)
	case nir.Lambda:
		summarizeAddressTakenStmts(e.Body, out)
	case nir.Thru:
		summarizeAddressTakenExpr(e.Inner, out)
	case nir.BinOp:
		summarizeAddressTakenExpr(e.Left, out)
		summarizeAddressTakenExpr(e.Right, out)
	case nir.Unary:
		summarizeAddressTakenExpr(e.Operand, out)
	case nir.Ternary:
		summarizeAddressTakenExpr(e.Cond, out)
		summarizeAddressTakenExpr(e.Then, out)
		summarizeAddressTakenExpr(e.Else, out)
	}
}

func summarizeContextTokens(stmts []nir.Stmt, out *[]string) {
	for _, st := range stmts {
		if len(*out) >= 512 {
			return
		}
		switch s := st.(type) {
		case nir.BodyRef:
			if s.Summarized {
				*out = append(*out, s.Summary.ContextTokens...)
			}
		case nir.FuncDef:
			*out = append(*out, s.ContextTokens...)
			summarizeContextTokens(s.Body, out)
		case nir.ClassDef:
			continue
		case nir.Block:
			summarizeContextTokens(s.Stmts, out)
		case nir.If:
			summarizeContextTokens(s.Then, out)
			summarizeContextTokens(s.Else, out)
		case nir.Loop:
			summarizeContextTokens(s.Body, out)
		case nir.Switch:
			for _, body := range s.Cases {
				summarizeContextTokens(body, out)
			}
		case nir.Try:
			summarizeContextTokens(s.Body, out)
			for _, body := range s.Handlers {
				summarizeContextTokens(body, out)
			}
			summarizeContextTokens(s.Finally, out)
		case nir.Defer:
			summarizeContextTokens(s.Body, out)
		}
	}
	if len(*out) > 512 {
		*out = (*out)[:512]
	}
}

func stmtWeight(st nir.Stmt) int {
	switch s := st.(type) {
	case nil, nir.BodyRef:
		return 1
	case nir.Assign:
		return 1 + len(s.Targets) + exprWeight(s.Value)
	case nir.AugAssign:
		return 2 + exprWeight(s.Value)
	case nir.Return:
		return 1 + exprWeight(s.Value)
	case nir.Validation:
		return 1 + exprWeight(s.Evidence)
	case nir.Terminate:
		return 1 + exprWeight(s.Value)
	case nir.ExprStmt:
		return 1 + exprWeight(s.Value)
	case nir.FuncDef:
		return 2 + len(s.Params) + len(s.Body)
	case nir.ClassDef:
		return 2 + len(s.Body)
	case nir.Block:
		return 1 + listWeight(s.Stmts)
	case nir.If:
		return 2 + exprWeight(s.Cond) + listWeight(s.Then) + listWeight(s.Else)
	case nir.Loop:
		return 2 + exprWeight(s.Cond) + exprWeight(s.Iter) + listWeight(s.Body)
	case nir.Switch:
		n := 2 + exprWeight(s.Subject) + listWeight(s.Default)
		for _, body := range s.Cases {
			n += listWeight(body)
		}
		for _, labels := range s.Labels {
			for _, label := range labels {
				n += exprWeight(label)
			}
		}
		return n
	case nir.Try:
		n := 2 + listWeight(s.Body) + listWeight(s.Finally)
		for _, h := range s.Handlers {
			n += listWeight(h)
		}
		return n
	case nir.Defer:
		return 1 + listWeight(s.Body)
	default:
		return 1
	}
}

func listWeight(stmts []nir.Stmt) int {
	n := 0
	for _, st := range stmts {
		n += stmtWeight(st)
	}
	return n
}

func exprWeight(ex nir.Expr) int {
	switch e := ex.(type) {
	case nil:
		return 0
	case nir.Name, nir.Const:
		return 1
	case nir.Attr:
		return 1 + exprWeight(e.Base)
	case nir.Index:
		return 1 + exprWeight(e.Base) + exprWeight(e.Key)
	case nir.Call:
		n := 2 + exprWeight(e.Callee)
		for _, a := range e.Args {
			n += exprWeight(a)
		}
		return n
	case nir.Format:
		n := 1
		for _, p := range e.Parts {
			n += exprWeight(p)
		}
		return n
	case nir.Seq:
		n := 1
		for _, p := range e.Parts {
			n += exprWeight(p)
		}
		return n
	case nir.Pair:
		return 1 + exprWeight(e.Value)
	case nir.Lambda:
		return 2 + len(e.Params) + len(e.Body)
	case nir.Thru:
		return exprWeight(e.Inner)
	case nir.BinOp:
		return 1 + exprWeight(e.Left) + exprWeight(e.Right)
	case nir.Unary:
		return 1 + exprWeight(e.Operand)
	case nir.Ternary:
		return 1 + exprWeight(e.Cond) + exprWeight(e.Then) + exprWeight(e.Else)
	default:
		return 1
	}
}
