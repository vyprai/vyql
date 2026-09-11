package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/extract/nir"
)

// The shapes a Haskell file has to lower into for a call inside it to be
// labelable: applications carry the dotted callee path a binding matches on, a
// monadic bind carries its binding, and the value a definition evaluates to
// reaches a call site as its return.
func TestExtractHaskellShapes(t *testing.T) {
	dir := t.TempDir()
	src := `module Upload.Handler where

import Database.MySQL.Simple (query)
import qualified Data.Text as T

-- one clause per guard
classify n
  | n > 0 = "pos"
  | otherwise = "neg"

handleUpload req = do
  let raw = T.unpack (param req)
      note = "upload " <> raw
  rows <- query conn "insert into files values (?)" [note]
  case rows of
    [] -> return empty
    (r:_) -> sink r
  report rows
`
	path := filepath.Join(dir, "Handler.hs")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractHaskell([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("got %d modules, want 1", len(prog.Modules))
	}
	mod := prog.Modules[0]

	var importMods []string
	for _, im := range mod.Imports {
		importMods = append(importMods, im.Module+"|"+im.Symbol)
	}
	for _, want := range []string{"Database.MySQL.Simple|query", "Data.Text|"} {
		found := false
		for _, got := range importMods {
			if strings.HasPrefix(got, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("import table missing %q; got %v", want, importMods)
		}
	}

	var (
		sawGuarded, sawHandle  bool
		sawQueryBind           bool
		sawUnpack, sawSinkCall bool
		sawConcatBuild         bool
		sawCaseArms            int
	)
	var expr func(nir.Expr)
	var stmts func([]nir.Stmt)
	expr = func(e nir.Expr) {
		switch x := e.(type) {
		case nir.Call:
			switch x.Path {
			case "T.unpack", "param", "report", "sink":
				if x.Method == lastSegOf(x.Path) {
					if x.Path == "T.unpack" {
						sawUnpack = true
					}
					if x.Path == "sink" {
						sawSinkCall = true
					}
				} else {
					t.Errorf("call %q carried method %q", x.Path, x.Method)
				}
			case "return":
				// monadic return is an application like any other; nothing to check
			}
			for _, a := range x.Args {
				expr(a)
			}
		case nir.Format:
			sawConcatBuild = true
			for _, p := range x.Parts {
				expr(p)
			}
		case nir.Attr:
			expr(x.Base)
		case nir.Seq:
			for _, p := range x.Parts {
				expr(p)
			}
		case nir.Lambda:
			stmts(x.Body)
		}
	}
	stmts = func(list []nir.Stmt) {
		for _, st := range list {
			switch s := st.(type) {
			case nir.FuncDef:
				if s.Name == "classify" {
					sawGuarded = true
					if len(s.Params) != 1 || s.Params[0] != "n" {
						t.Errorf("classify params = %v, want [n]", s.Params)
					}
				}
				if s.Name == "handleUpload" {
					sawHandle = true
				}
				stmts(s.Body)
			case nir.Assign:
				if len(s.Targets) == 1 && s.Targets[0] == "rows" {
					sawQueryBind = true
				}
				expr(s.Value)
			case nir.Return:
				expr(s.Value)
			case nir.ExprStmt:
				expr(s.Value)
			case nir.If:
				expr(s.Cond)
				stmts(s.Then)
				stmts(s.Else)
			case nir.Switch:
				sawCaseArms += len(s.Cases) + len(s.Default)
				for _, arm := range s.Cases {
					stmts(arm)
				}
				stmts(s.Default)
			}
		}
	}
	stmts(mod.Body)

	if !sawGuarded || !sawHandle {
		t.Fatalf("definitions missing: classify=%v handleUpload=%v", sawGuarded, sawHandle)
	}
	if !sawQueryBind {
		t.Error("monadic bind `rows <- query …` did not bind rows")
	}
	if !sawUnpack {
		t.Error("no call on the qualified path T.unpack")
	}
	if !sawSinkCall {
		t.Error("no call to the bare sink application inside the case arm")
	}
	if !sawConcatBuild {
		t.Error("no string build; the `<>` append did not lower as concatenation")
	}
	if sawCaseArms != 2 {
		t.Errorf("case lowered to %d arms, want 2", sawCaseArms)
	}
}

// A case arm reads the value it matched on through the names its pattern binds.
// Until those bindings reached the graph, taint stopped at every `case` — a
// source on one side of a case and a sink inside an arm never connected.
func TestExtractHaskellCaseArmCarriesFlow(t *testing.T) {
	dir := t.TempDir()
	src := `module H where

handle req = do
  xs <- param req
  case xs of
    [] -> query "none"
    (r:_) -> query r
`
	path := filepath.Join(dir, "H.hs")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractHaskell([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, false)
	if err != nil {
		t.Fatal(err)
	}
	calls, _ := g.NodesOfType("code.Call")
	var source, sink string
	for _, id := range calls {
		n, _, _ := g.GetNode(id)
		switch n.Prop("callee_path") {
		case "param":
			source = id
		case "query":
			sink = id
		}
	}
	if source == "" || sink == "" {
		t.Fatalf("calls missing: param=%q query=%q", source, sink)
	}
	if !reaches(t, g, source, sink) {
		t.Error("no flow from the param call into the query call inside the case arm")
	}
}

func lastSegOf(s string) string {
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}
