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

func TestJavaScriptCommandRegexRejectGuardObservation(t *testing.T) {
	dir := t.TempDir()
	guarded := filepath.Join(dir, "guarded.js")
	unguarded := filepath.Join(dir, "unguarded.js")
	if err := os.WriteFile(guarded, []byte("module.exports = function (packageName, registry = '') {\n"+
		"  if (/[`$&{}[;|]/g.test(packageName) || /[`$&{}[;|]/g.test(registry)) {\n"+
		"    return null;\n"+
		"  }\n"+
		"  return require('child_process').execSync(`npm view ${packageName} --registry ${registry}`);\n"+
		"};\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unguarded, []byte("module.exports = function (packageName) {\n"+
		"  if (/[`$&{}[;|]/g.test(packageName)) {\n"+
		"    console.warn('bad package name');\n"+
		"  }\n"+
		"  return require('child_process').execSync(`npm view ${packageName}`);\n"+
		"};\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{guarded, unguarded}, dir)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := graph.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	seenGuarded := false
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.javascript.command_argument_regex_guard" {
			continue
		}
		if strings.Contains(n.Prop("loc"), "unguarded.js") {
			t.Fatalf("non-terminating regex check emitted command guard at %s", n.Prop("loc"))
		}
		if strings.Contains(n.Prop("loc"), "guarded.js") {
			seenGuarded = true
		}
	}
	if !seenGuarded {
		t.Fatalf("terminating command regex reject guard was not emitted; nodes=%#v", nodes)
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

func TestJavaScriptDangerouslySetInnerHTMLLowersHtmlValueAsCallArg(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ChatMessage.jsx")
	src := []byte(`
export function ChatMessage({ item }) {
  return <div dangerouslySetInnerHTML={{ __html: item.data }} />
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := findFuncDef(prog, "ChatMessage")
	if !ok {
		t.Fatalf("ChatMessage was not extracted; program=%#v", prog)
	}
	if !funcBodyHasCall(fn.Body, "dangerouslySetInnerHTML") {
		t.Fatalf("JSX dangerous HTML attribute did not lower to a call; body=%#v", fn.Body)
	}
	if !funcBodyHasCallArgPath(fn.Body, "dangerouslySetInnerHTML", "item.data") {
		t.Fatalf("JSX dangerous HTML call did not carry __html value item.data; body=%#v", fn.Body)
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

func TestJavaScriptCommonJSArgumentsExportAddsSyntheticPublicParam(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "index.js")
	src := []byte(`
module.exports = function () {
  const commands = Array.isArray(arguments[0]) ? arguments[0] : Array.prototype.slice.apply(arguments);
  return commands[0];
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
		t.Fatalf("CommonJS default export function was not extracted; program=%#v", prog)
	}
	if !fn.Exported {
		t.Fatalf("CommonJS default export should be marked exported; fn=%#v", fn)
	}
	if len(fn.Params) != 1 || fn.Params[0] != nir.JSArgumentsParam {
		t.Fatalf("exported arguments-using function should get synthetic param; params=%#v", fn.Params)
	}
}

func TestJavaScriptExportedClassThisAssignedHelperIsPublicEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "parser.js")
	src := []byte(`
export default class Parser {
  constructor() {
    this.addExternalEntities = addExternalEntities;
  }
}

function addExternalEntities(externalEntities) {
  return new RegExp("&" + Object.keys(externalEntities)[0] + ";", "g");
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := findFuncDef(prog, "addExternalEntities")
	if !ok {
		t.Fatalf("this-assigned helper function was not extracted; program=%#v", prog)
	}
	if !fn.Exported {
		t.Fatalf("this-assigned helper on exported class should be marked exported; fn=%#v", fn)
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

func TestJavaScriptRequireMemberImportIsExtracted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "index.js")
	src := []byte(`
const quote = require("shell-quote").quote;
quote(command);
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range prog.Modules[0].Imports {
		if imp.Local == "quote" && imp.Module == "shell-quote" && imp.Symbol == "quote" && !imp.IsModule {
			return
		}
	}
	t.Fatalf("missing require member import for shell-quote.quote; imports=%#v", prog.Modules[0].Imports)
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

func TestJavaScriptSiblingInlineLambdaContextsUseDistinctScopes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.ts")
	src := []byte(`
export function setup(app: any) {
  app.post(PATH_EXPORT, async (req, res) => {
    const path = req.body.path;
    await exportAll(path);
  });
  app.post(PATH_DISABLE, async (req, res) => {
    res.status(200).send({ ok: true });
  });
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
	var exportCtx, disableCtx, exportCallScope string
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.function.context" {
			tokens := n.Prop("str_args")
			switch {
			case strings.Contains(tokens, "name=<lambda>") && strings.Contains(tokens, "call_path:app.post") && strings.Contains(tokens, "req.body.path") && strings.Contains(tokens, "exportAll"):
				exportCtx = n.Region
			case strings.Contains(tokens, "name=<lambda>") && strings.Contains(tokens, "call_path:app.post") && strings.Contains(tokens, "res.status") && strings.Contains(tokens, "send"):
				disableCtx = n.Region
			}
		}
		if n.Type == "code.Call" && n.Prop("callee_path") == "exportAll" {
			exportCallScope = n.Region
		}
	}
	if exportCtx == "" || disableCtx == "" {
		t.Fatalf("missing sibling lambda contexts: export=%q disable=%q nodes=%#v", exportCtx, disableCtx, nodes)
	}
	if exportCtx == disableCtx {
		t.Fatalf("sibling inline lambda contexts share scope %q", exportCtx)
	}
	if exportCallScope == "" || !strings.HasPrefix(exportCallScope, exportCtx) {
		t.Fatalf("exportAll call scope %q is not nested under export lambda context %q", exportCallScope, exportCtx)
	}
	if strings.HasPrefix(exportCallScope, disableCtx) {
		t.Fatalf("exportAll call scope %q is incorrectly nested under sibling lambda context %q", exportCallScope, disableCtx)
	}
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

func TestJavaScriptFunctionContextIncludesSubscriptAndRegexTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evaluate.js")
	src := []byte(`
function evaluate(tokens, expr, values) {
  for (var i = 0; i < tokens.length; i++) {
    var item = tokens[i];
    if (/^__proto__|prototype|constructor$/.test(item.value)) throw new Error("prototype access detected");
    if (item.value in expr.functions) return values[item.value];
    return nstack.pop()[item.value];
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
		if strings.Contains(tokens, "index_base:values") &&
			strings.Contains(tokens, "index_key:item.value") &&
			strings.Contains(tokens, "subscript:values[item.value]") &&
			strings.Contains(tokens, "identifier:item") &&
			strings.Contains(tokens, "identifier:values") &&
			strings.Contains(tokens, "regex:^__proto__|prototype|constructor$") &&
			strings.Contains(tokens, "prototype_name_guard=true") {
			return
		}
	}
	t.Fatalf("function context did not include subscript/regex tokens; nodes=%#v", nodes)
}

func TestJavaScriptTemplateFormatCarriesStaticText(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clone.js")
	src := []byte(`
async function clone(remoteUrl, tmpDir) {
  await utils.run(` + "`git clone ${remoteUrl} ${tmpDir}`" + `);
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
	ids, _ := g.NodesOfType("code.Format")
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil || !ok {
			continue
		}
		if strings.Contains(n.Prop("str_args"), "gitclone") &&
			strings.Contains(n.Prop("str_args"), "remoteUrl") {
			return
		}
	}
	t.Fatalf("template format did not carry static command text")
}

func TestJavaScriptGitCloneContextTokensShowEndOfOptionsDelimiter(t *testing.T) {
	dir := t.TempDir()
	vulnerable := filepath.Join(dir, "vulnerable.ts")
	fixed := filepath.Join(dir, "fixed.ts")
	vulnerableSrc := []byte(`
export class Git {
  protected gitExec(cmd: string): Promise<string> {
    return Promise.resolve(cmd);
  }

  public clone(repository: string, dest: string, options?: { depth?: number }) {
    const opt = options || { depth: Infinity };
    const depthOption = opt.depth !== Infinity ? ` + "` --depth=${opt.depth}`" + ` : '';
    return this.gitExec(` + "`clone ${repository} ${dest}${depthOption}`" + `);
  }
}
`)
	fixedSrc := []byte(`
export class Git {
  protected gitExec(cmd: string): Promise<string> {
    return Promise.resolve(cmd);
  }

  public clone(repository: string, dest: string, options?: { depth?: number }) {
    const opt = options || { depth: Infinity };
    const depthOption = opt.depth !== Infinity ? ` + "`--depth=${opt.depth}`" + ` : '';
    return this.gitExec(` + "`clone ${depthOption} -- ${repository} ${dest}`" + `);
  }
}
`)
	if err := os.WriteFile(vulnerable, vulnerableSrc, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixed, fixedSrc, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJavaScript([]string{vulnerable, fixed}, dir)
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
	var sawVulnerable, sawFixed bool
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		tokens := n.Prop("str_args")
		switch {
		case strings.Contains(n.Prop("loc"), "vulnerable.ts") &&
			strings.Contains(tokens, "literal:clone${repository}${dest}${depthOption}") &&
			!strings.Contains(tokens, "--${repository}"):
			sawVulnerable = true
		case strings.Contains(n.Prop("loc"), "fixed.ts") &&
			strings.Contains(tokens, "literal:clone${depthOption}--${repository}${dest}"):
			sawFixed = true
		}
	}
	if !sawVulnerable || !sawFixed {
		t.Fatalf("git clone context tokens did not distinguish delimiter: vulnerable=%v fixed=%v nodes=%#v", sawVulnerable, sawFixed, nodes)
	}
}

func TestJavaScriptGitCloneArgvContextTokensShowEndOfOptionsDelimiter(t *testing.T) {
	dir := t.TempDir()
	vulnerable := filepath.Join(dir, "vulnerable.js")
	fixed := filepath.Join(dir, "fixed.js")
	vulnerableSrc := []byte(`
function cloneRepo(url, outPath, depth) {
  const flag = depth < Infinity ? '--depth=' + depth : '--single-branch';
  const args = ['clone', flag, url, outPath];
  spawn('git', args, {}, cb);
}
`)
	fixedSrc := []byte(`
function cloneRepo(url, outPath, depth) {
  const flag = depth < Infinity ? '--depth=' + depth : '--single-branch';
  const args = ['clone', flag, '--', url, outPath];
  spawn('git', args, {}, cb);
}
`)
	if err := os.WriteFile(vulnerable, vulnerableSrc, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixed, fixedSrc, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractJavaScript([]string{vulnerable, fixed}, dir)
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
	var sawVulnerable, sawFixed bool
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		tokens := n.Prop("str_args")
		switch {
		case strings.Contains(n.Prop("loc"), "vulnerable.js") &&
			strings.Contains(tokens, "git_clone_argv_sequence=cloneflagurloutPath") &&
			strings.Contains(tokens, "git_clone_argv_missing_delimiter=true"):
			sawVulnerable = true
		case strings.Contains(n.Prop("loc"), "fixed.js") &&
			strings.Contains(tokens, "git_clone_argv_sequence=cloneflag--urloutPath") &&
			strings.Contains(tokens, "git_clone_argv_delimited=true") &&
			!strings.Contains(tokens, "git_clone_argv_missing_delimiter=true"):
			sawFixed = true
		}
	}
	if !sawVulnerable || !sawFixed {
		t.Fatalf("git clone argv context tokens did not distinguish delimiter: vulnerable=%v fixed=%v nodes=%#v", sawVulnerable, sawFixed, nodes)
	}
}

func TestJavaScriptRegexMayBacktrackAmbiguousAdjacentQuantifiers(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "ambiguous numeric halves with optional decimal",
			src:  `const numberRx = /^(?:[0-9]*\.?[0-9]*){1}$/;`,
			want: true,
		},
		{
			name: "decimal suffix grouped as a single optional branch",
			src:  `const numberRx = /^(?:[0-9]*(\.[0-9]*)?){1}$/;`,
			want: false,
		},
		{
			name: "classic nested quantified group",
			src:  `const nested = /^(a+)+$/;`,
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "regex.js")
			if err := os.WriteFile(path, []byte(tt.src), 0o600); err != nil {
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
			got := false
			for _, n := range nodes {
				got = got || n.Type == "code.Call" && n.Prop("callee_path") == "__regex.match"
			}
			if got != tt.want {
				t.Fatalf("synthetic regex match = %v, want %v; nodes=%#v", got, tt.want, nodes)
			}
		})
	}
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

func TestTypeScriptNuxtPublicRuntimeSecretConfigToken(t *testing.T) {
	dir := t.TempDir()
	vuln := filepath.Join(dir, "vuln.ts")
	fixed := filepath.Join(dir, "fixed.ts")
	if err := os.WriteFile(vuln, []byte(`
export default defineNuxtModule({
  setup (options, nuxt) {
    const config = {
      owner: options.owner || process.env.GITHUB_OWNER,
      token: options.token || process.env.GITHUB_TOKEN
    }
    nuxt.options.runtimeConfig.public.github = defu(nuxt.options.runtimeConfig.public.github, config)
  }
})
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixed, []byte(`
export default defineNuxtModule({
  setup (options, nuxt) {
    const config = {
      owner: options.owner || process.env.GITHUB_OWNER
    }
    nuxt.options.runtimeConfig.public.github = defu(nuxt.options.runtimeConfig.public.github, config)
    nuxt.options.runtimeConfig.github = defu(nuxt.options.runtimeConfig.github, {
      token: options.token || process.env.GITHUB_TOKEN
    }, config)
  }
})
`), 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractJavaScript([]string{vuln, fixed}, dir)
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
	seenVulnToken := false
	seenVulnCall := false
	for _, n := range nodes {
		if strings.Contains(n.Prop("loc"), "vuln.ts") && n.Type == "code.Call" && n.Prop("callee_path") == "defineNuxtModule" {
			seenVulnCall = true
		}
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.module.context" {
			continue
		}
		tokens := n.Prop("str_args")
		if strings.Contains(n.Prop("loc"), "vuln.ts") && strings.Contains(tokens, "public_runtime_secret_config") {
			seenVulnToken = true
		}
		if strings.Contains(n.Prop("loc"), "fixed.ts") && strings.Contains(tokens, "public_runtime_secret_config") {
			t.Fatalf("fixed private runtime config should not emit public secret token: %s", tokens)
		}
	}
	if !seenVulnCall {
		t.Fatalf("default-export defineNuxtModule call was not extracted; nodes=%#v", nodes)
	}
	if !seenVulnToken {
		t.Fatalf("vulnerable public runtime secret config token was not emitted; nodes=%#v", nodes)
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
	case nir.Seq:
		for _, part := range e.Parts {
			if exprHasCall(part, method) {
				return true
			}
		}
	}
	return false
}

func funcBodyHasCallArgPath(stmts []nir.Stmt, method, path string) bool {
	for _, st := range stmts {
		switch s := st.(type) {
		case nir.ExprStmt:
			if exprHasCallArgPath(s.Value, method, path) {
				return true
			}
		case nir.Return:
			if exprHasCallArgPath(s.Value, method, path) {
				return true
			}
		case nir.Assign:
			if exprHasCallArgPath(s.Value, method, path) {
				return true
			}
		case nir.Block:
			if funcBodyHasCallArgPath(s.Stmts, method, path) {
				return true
			}
		case nir.If:
			if funcBodyHasCallArgPath(s.Then, method, path) || funcBodyHasCallArgPath(s.Else, method, path) {
				return true
			}
		case nir.Loop:
			if funcBodyHasCallArgPath(s.Body, method, path) {
				return true
			}
		case nir.Try:
			if funcBodyHasCallArgPath(s.Body, method, path) {
				return true
			}
			for _, h := range s.Handlers {
				if funcBodyHasCallArgPath(h, method, path) {
					return true
				}
			}
		}
	}
	return false
}

func exprHasCallArgPath(expr nir.Expr, method, path string) bool {
	switch e := expr.(type) {
	case nir.Call:
		if e.Method == method {
			for _, arg := range e.Args {
				if exprPathEquals(arg, path) {
					return true
				}
			}
		}
		for _, arg := range e.Args {
			if exprHasCallArgPath(arg, method, path) {
				return true
			}
		}
		return exprHasCallArgPath(e.Callee, method, path)
	case nir.Thru:
		return exprHasCallArgPath(e.Inner, method, path)
	case nir.Format:
		for _, part := range e.Parts {
			if exprHasCallArgPath(part, method, path) {
				return true
			}
		}
	case nir.Seq:
		for _, part := range e.Parts {
			if exprHasCallArgPath(part, method, path) {
				return true
			}
		}
	}
	return false
}

func exprPathEquals(expr nir.Expr, path string) bool {
	switch e := expr.(type) {
	case nir.Attr:
		return e.Path == path
	case nir.Thru:
		return exprPathEquals(e.Inner, path)
	}
	return false
}
