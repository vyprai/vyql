package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/nir"
)

func TestTypeScriptAbstractClassMethodsAreExtracted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "asset.ts")
	src := []byte(`
export abstract class AssetGroup {
  private newRequestWithMetadata(url: string, options: RequestInit): Request {
    return this.adapter.newRequest(url, {headers: options.headers});
  }
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := findFuncDef(prog, "newRequestWithMetadata")
	if !ok {
		t.Fatalf("abstract class method newRequestWithMetadata was not extracted; program=%#v", prog)
	}
	if !funcBodyHasCall(fn.Body, "newRequest") {
		t.Fatalf("abstract class method body did not include adapter.newRequest call; body=%#v", fn.Body)
	}
}

func findFuncDef(prog nir.Program, name string) (nir.FuncDef, bool) {
	for _, mod := range prog.Modules {
		if fn, ok := findFuncDefInStmts(mod.Body, name); ok {
			return fn, true
		}
	}
	return nir.FuncDef{}, false
}

func findFuncDefInStmts(stmts []nir.Stmt, name string) (nir.FuncDef, bool) {
	for _, st := range stmts {
		switch s := st.(type) {
		case nir.FuncDef:
			if s.Name == name {
				return s, true
			}
			if fn, ok := findFuncDefInStmts(s.Body, name); ok {
				return fn, true
			}
		case nir.ClassDef:
			if fn, ok := findFuncDefInStmts(s.Body, name); ok {
				return fn, true
			}
		case nir.Block:
			if fn, ok := findFuncDefInStmts(s.Stmts, name); ok {
				return fn, true
			}
		case nir.If:
			if fn, ok := findFuncDefInStmts(s.Then, name); ok {
				return fn, true
			}
			if fn, ok := findFuncDefInStmts(s.Else, name); ok {
				return fn, true
			}
		case nir.Loop:
			if fn, ok := findFuncDefInStmts(s.Body, name); ok {
				return fn, true
			}
		case nir.Try:
			if fn, ok := findFuncDefInStmts(s.Body, name); ok {
				return fn, true
			}
			for _, h := range s.Handlers {
				if fn, ok := findFuncDefInStmts(h, name); ok {
					return fn, true
				}
			}
		}
	}
	return nir.FuncDef{}, false
}

func funcBodyHasCall(stmts []nir.Stmt, method string) bool {
	for _, st := range stmts {
		switch s := st.(type) {
		case nir.ExprStmt:
			if exprHasCall(s.Value, method) {
				return true
			}
		case nir.Return:
			if exprHasCall(s.Value, method) {
				return true
			}
		case nir.Assign:
			if exprHasCall(s.Value, method) {
				return true
			}
		case nir.Block:
			if funcBodyHasCall(s.Stmts, method) {
				return true
			}
		case nir.If:
			if funcBodyHasCall(s.Then, method) || funcBodyHasCall(s.Else, method) {
				return true
			}
		case nir.Loop:
			if funcBodyHasCall(s.Body, method) {
				return true
			}
		case nir.Try:
			if funcBodyHasCall(s.Body, method) {
				return true
			}
			for _, h := range s.Handlers {
				if funcBodyHasCall(h, method) {
					return true
				}
			}
		}
	}
	return false
}

func exprHasCall(expr nir.Expr, method string) bool {
	switch e := expr.(type) {
	case nir.Call:
		if e.Method == method {
			return true
		}
		for _, arg := range e.Args {
			if exprHasCall(arg, method) {
				return true
			}
		}
	case nir.Thru:
		return exprHasCall(e.Inner, method)
	case nir.Format:
		for _, part := range e.Parts {
			if exprHasCall(part, method) {
				return true
			}
		}
	}
	return false
}
