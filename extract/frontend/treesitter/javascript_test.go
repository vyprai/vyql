package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
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

func TestTypeScriptObjectGeneratorMethodsAreExtracted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "login.ts")
	src := []byte(`
const Model = {
  effects: {
    *login() {
      window.location.href = redirect;
    },
  },
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := findFuncDef(prog, "login")
	if !ok {
		t.Fatalf("object generator method login was not extracted; program=%#v", prog)
	}
	if !funcBodyHasPath(fn.Body, "window.location.href") {
		t.Fatalf("object generator method body did not include location assignment; body=%#v", fn.Body)
	}
}

func TestTypeScriptNestedScalarReassignmentIsExtracted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "table.ts")
	src := []byte(`
export function createTablePopper(popperContent: string) {
  function renderContent() {
    popperContent = escapeHtml(popperContent)
    content.innerHTML = popperContent
  }
  return renderContent()
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := findFuncDef(prog, "renderContent")
	if !ok {
		t.Fatalf("nested function renderContent was not extracted; program=%#v", prog)
	}
	if !funcBodyHasAssignTarget(fn.Body, "popperContent") {
		t.Fatalf("nested function body did not include popperContent reassignment; body=%#v", fn.Body)
	}
}

func TestJavaScriptAnonymousDefaultExportFunctionIsExtracted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "index.js")
	src := []byte(`
export default function (obj, keys, val) {
  keys.split && (keys = keys.split('.'));
  obj[keys[0]] = val;
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := findFuncDef(prog, "__default_export__")
	if !ok {
		t.Fatalf("anonymous default export function was not extracted; program=%#v", prog)
	}
	if !fn.Exported {
		t.Fatalf("anonymous default export should be marked exported; fn=%#v", fn)
	}
	if len(fn.Params) != 3 || fn.Params[0] != "obj" || fn.Params[1] != "keys" || fn.Params[2] != "val" {
		t.Fatalf("anonymous default export params not preserved; params=%#v", fn.Params)
	}
	if !funcBodyHasPath(fn.Body, "__js_dynamic_property_write") {
		t.Fatalf("anonymous default export body did not include dynamic property write; body=%#v", fn.Body)
	}
}

func TestTypeScriptImportsAreExtracted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.ts")
	src := []byte(`
import { cookies } from 'next/headers';
import { NextRequest, NextResponse } from 'next/server';
import workos from '@workos-inc/node';
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("module count = %d, want 1", len(prog.Modules))
	}
	got := map[string]bool{}
	for _, imp := range prog.Modules[0].Imports {
		got[imp.Module] = true
	}
	for _, want := range []string{"next/headers", "next/server", "@workos-inc/node"} {
		if !got[want] {
			t.Fatalf("missing import %q; imports=%#v", want, prog.Modules[0].Imports)
		}
	}
}

func TestJavaScriptNestedRegExpInConditionalChainIsLowered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "index.js")
	src := []byte(`
module.exports.parse = (event) => {
  const boundary = getValueIgnoringKeyCase(event.headers, 'Content-Type').split('=')[1];
  const body = (event.isBase64Encoded ? Buffer.from(event.body, 'base64').toString('binary') : event.body)
    .split(new RegExp(boundary))
    .filter(item => item.match(/Content-Disposition/));
  return body;
};
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "RegExp" {
			return
		}
	}
	t.Fatalf("nested new RegExp(boundary) was not lowered; nodes=%#v", nodes)
}

func TestJavaScriptInlineLambdaContextIsLowered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "origin.ts")
	src := []byte(`
export const middleware = createAuthMiddleware(async (ctx) => {
  if (ctx.request?.method !== "POST") {
    return;
  }
  const callbackURL = ctx.query?.callbackURL;
  callbackURL && validateURL(callbackURL, "callbackURL");
});
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		tokens := n.Prop("str_args")
		if strings.Contains(tokens, "name=<lambda>") &&
			strings.Contains(tokens, "ctx.request?.method") &&
			strings.Contains(tokens, "callbackURL") &&
			strings.Contains(tokens, "validateURL") {
			return
		}
	}
	t.Fatalf("inline lambda context was not lowered; nodes=%#v", nodes)
}

func TestJavaScriptModuleContextIncludesStructuredTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "init.js")
	src := []byte(`
let nodeIntegration = 'false';
if (window.location.protocol === 'chrome-devtools:') {
  nodeIntegration = 'true';
}
execFile("powershell.exe", ["-Command", "echo ok"], { shell: true });
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.module.context" {
			continue
		}
		tokens := n.Prop("str_args")
		if strings.Contains(tokens, "expr:window.location.protocol==='chrome-devtools:'") &&
			strings.Contains(tokens, "assign:nodeIntegration=true") &&
			strings.Contains(tokens, "selector:window.location.protocol") &&
			strings.Contains(tokens, "prop:shell=true") {
			return
		}
	}
	t.Fatalf("module context did not include structured tokens; nodes=%#v", nodes)
}

func TestJavaScriptBrowserGlobalAssignmentLambdaParamEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "origin.tsx")
	src := []byte(`
function setup(board: Board) {
  (window as any)['__debug_console'] = (value: string) => {
    addDebugLog(board, value);
  };
}
function addDebugLog(board: Board, value: string) {
  const div = document.createElement('div');
  div.innerHTML = value;
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var eventID, paramID string
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.parameter.entry" &&
			strings.Contains(n.Prop("str_args"), "entry_kind:global_function_assignment") &&
			strings.Contains(n.Prop("str_args"), "global_object:window") &&
			strings.Contains(n.Prop("str_args"), "global_target:window.__debug_console") &&
			strings.Contains(n.Prop("str_args"), "param_name:value") {
			eventID = n.ID
		}
		if n.Type == "code.Param" && n.Prop("name") == "value" && n.Loc == "origin.tsx:3" {
			paramID = n.ID
		}
	}
	if eventID == "" || paramID == "" {
		t.Fatalf("missing global assignment parameter entry event=%q param=%q nodes=%#v", eventID, paramID, nodes)
	}
	outs, _ := g.OutEdges(eventID, "FLOWS")
	for _, edge := range outs {
		if edge.Dst == paramID {
			return
		}
	}
	t.Fatalf("global assignment parameter entry event does not flow to callback param")
}

func TestJavaScriptModuleContextIsLowered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "table.js")
	src := []byte(`
const defaults = {
  exportOptions: {
    onCellHtmlData (cell, rowIndex, colIndex, htmlData) {
      return htmlData;
    }
  }
};
function exportTable () {
  tableExport({ escape: false });
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.module.context" {
			continue
		}
		tokens := n.Prop("str_args")
		if strings.Contains(tokens, "lang=javascript") &&
			strings.Contains(tokens, "onCellHtmlData") &&
			strings.Contains(tokens, "returnhtmlData") &&
			strings.Contains(tokens, "tableExport") &&
			strings.Contains(tokens, "escape:false") {
			return
		}
	}
	t.Fatalf("module context was not lowered with file-level tokens; nodes=%#v", nodes)
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

func funcBodyHasPath(stmts []nir.Stmt, path string) bool {
	for _, st := range stmts {
		switch s := st.(type) {
		case nir.ExprStmt:
			if exprHasPath(s.Value, path) {
				return true
			}
		case nir.Return:
			if exprHasPath(s.Value, path) {
				return true
			}
		case nir.Assign:
			if exprHasPath(s.Value, path) {
				return true
			}
		case nir.Block:
			if funcBodyHasPath(s.Stmts, path) {
				return true
			}
		case nir.If:
			if funcBodyHasPath(s.Then, path) || funcBodyHasPath(s.Else, path) {
				return true
			}
		case nir.Loop:
			if funcBodyHasPath(s.Body, path) {
				return true
			}
		case nir.Try:
			if funcBodyHasPath(s.Body, path) {
				return true
			}
			for _, h := range s.Handlers {
				if funcBodyHasPath(h, path) {
					return true
				}
			}
		}
	}
	return false
}

func funcBodyHasAssignTarget(stmts []nir.Stmt, target string) bool {
	for _, st := range stmts {
		switch s := st.(type) {
		case nir.Assign:
			for _, t := range s.Targets {
				if t == target {
					return true
				}
			}
		case nir.Block:
			if funcBodyHasAssignTarget(s.Stmts, target) {
				return true
			}
		case nir.If:
			if funcBodyHasAssignTarget(s.Then, target) || funcBodyHasAssignTarget(s.Else, target) {
				return true
			}
		case nir.Loop:
			if funcBodyHasAssignTarget(s.Body, target) {
				return true
			}
		case nir.Try:
			if funcBodyHasAssignTarget(s.Body, target) {
				return true
			}
			for _, h := range s.Handlers {
				if funcBodyHasAssignTarget(h, target) {
					return true
				}
			}
		}
	}
	return false
}

func exprHasPath(expr nir.Expr, path string) bool {
	switch e := expr.(type) {
	case nir.Call:
		if e.Path == path {
			return true
		}
		for _, arg := range e.Args {
			if exprHasPath(arg, path) {
				return true
			}
		}
		return exprHasPath(e.Callee, path)
	case nir.Attr:
		return exprHasPath(e.Base, path)
	case nir.Index:
		return exprHasPath(e.Base, path) || exprHasPath(e.Key, path)
	case nir.Thru:
		return exprHasPath(e.Inner, path)
	case nir.Format:
		for _, part := range e.Parts {
			if exprHasPath(part, path) {
				return true
			}
		}
	}
	return false
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
