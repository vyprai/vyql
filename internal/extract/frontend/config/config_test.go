package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/extract/nir"
)

func TestJellyTemplateAliasesJSetInputVariables(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "column.jelly")
	src := []byte(`<?jelly escape-by-default='true'?>
<j:jelly xmlns:j="jelly:core">
  <j:set var="tooltipdesc" value="${it.getToolTip(job)}"/>
  <div tooltip="${tooltipdesc}">
    <j:out value="${app.markupFormatter.translate(tooltipdesc)}"/>
  </div>
</j:jelly>
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := Extract([]string{path}, dir)
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
	renderCount := 0
	inputCount := 0
	for _, n := range nodes {
		switch n.Prop("callee_path") {
		case "analysis.template.jelly.render":
			renderCount++
		case "analysis.template.jelly.input":
			inputCount++
		}
	}
	if renderCount != 1 {
		t.Fatalf("jelly render count = %d, want 1; nodes=%#v", renderCount, nodes)
	}
	if inputCount != 1 {
		t.Fatalf("jelly input count = %d, want 1; nodes=%#v", inputCount, nodes)
	}
}

func TestJellySecretEntryTextboxSignature(t *testing.T) {
	dir := t.TempDir()
	vuln := filepath.Join(dir, "config-vuln.jelly")
	fixed := filepath.Join(dir, "config-fixed.jelly")
	if err := os.WriteFile(vuln, []byte(`<?jelly escape-by-default='true'?>
<j:jelly xmlns:j="jelly:core" xmlns:f="/lib/form">
  <f:entry title="Client Secret" field="clientSecret">
    <f:textbox />
  </f:entry>
</j:jelly>
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixed, []byte(`<?jelly escape-by-default='true'?>
<j:jelly xmlns:j="jelly:core" xmlns:f="/lib/form">
  <f:entry title="Client Secret" field="clientSecret">
    <f:password />
  </f:entry>
</j:jelly>
`), 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := Extract([]string{vuln, fixed}, dir)
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
	seen := false
	for _, n := range nodes {
		if n.Prop("callee_path") != "analysis.config.jenkins_jelly_secret_textbox" {
			continue
		}
		if strings.Contains(n.Prop("loc"), "config-fixed.jelly") {
			t.Fatalf("password field should suppress secret textbox event at %s", n.Prop("loc"))
		}
		if strings.Contains(n.Prop("loc"), "config-vuln.jelly") {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("secret textbox event not emitted; nodes=%#v", nodes)
	}
}

func TestSchematronLinkHrefDenylistSignature(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docbook.iso.sch")
	src := []byte(`<s:schema xmlns:s="http://purl.oclc.org/dsdl/schematron">
  <s:rule context="db:link">
    <s:assert test="not(contains(@*[name()='xlink:href'], 'javascript:') or contains(@*[name()='xlink:href'], 'vbscript:'))">using scripts in links is not allowed</s:assert>
  </s:rule>
</s:schema>
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := Extract([]string{path}, dir)
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
		if n.Prop("callee_path") == "analysis.config.schematron_link_href_case_sensitive_script_denylist" {
			return
		}
	}
	t.Fatalf("schematron signature event not emitted; nodes=%#v", nodes)
}

func TestNpmPackageNodePreGypRemoteBinarySignature(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	src := []byte(`{
  "name": "fsevents",
  "scripts": {
    "install": "node install",
    "node-pre-gyp": "node-pre-gyp"
  },
  "dependencies": {
    "node-pre-gyp": "^0.12.0"
  },
  "binary": {
    "module_name": "fse",
    "host": "https://fsevents-binaries.s3-us-west-2.amazonaws.com"
  }
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := Extract([]string{path}, dir)
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
		if n.Prop("callee_path") == "analysis.config.npm.node_pre_gyp_remote_binary_install" {
			return
		}
	}
	t.Fatalf("npm node-pre-gyp remote binary signature event not emitted; nodes=%#v", nodes)
}

func TestAttributeValueSpansJoinValuesThatContinueOverLines(t *testing.T) {
	src := []byte(`<html>
  <head>
    <script type="text/javascript"
        tal:content="structure string:
        // this is the field we're working on
        field = '${request/form/property/value}';">
    </script>
    <td tal:content="structure context/username/field">username</td>
  </head>
</html>
`)
	spans := attributeValueSpans(src)
	want := []attributeValueSpan{
		{Name: "type", Value: "text/javascript", Line: 3},
		{Name: "tal:content", Value: "structure string:\n        // this is the field we're working on\n        field = '${request/form/property/value}';", Line: 4},
		{Name: "tal:content", Value: "structure context/username/field", Line: 8},
	}
	if len(spans) != len(want) {
		t.Fatalf("span count = %d, want %d; spans=%#v", len(spans), len(want), spans)
	}
	for i, w := range want {
		if spans[i] != w {
			t.Errorf("span[%d] = %#v, want %#v", i, spans[i], w)
		}
	}
	if !containsAllFold(spans[1].Value, []string{"structure string:", "${"}) {
		t.Errorf("multi-line value does not carry both needles: %q", spans[1].Value)
	}
}

func TestAttributeValueSpansSkipProseAndUnquotedAttributes(t *testing.T) {
	src := []byte(`<!-- don't treat prose quotes as values -->
<p class=plain tal:content="string:${request/form/x}">
`)
	spans := attributeValueSpans(src)
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1; spans=%#v", len(spans), spans)
	}
	if spans[0].Name != "tal:content" || spans[0].Line != 2 {
		t.Fatalf("span = %#v, want the tal:content attribute on line 2", spans[0])
	}
}

// resetConfigProfile drops the compiled config profile so the next loadProfile reads
// the data root that is pinned when it runs. Only the tests below use it: the profile
// is read once per process from whatever root is pinned at that moment.
func resetConfigProfile() {
	configProfileOnce = sync.Once{}
	configProfileData = configProfile{}
}

// A Grails template is markup carrying ${…} writes, and it lowers to the render and
// input calls the binding metadata declares for the gsp template scope. Until a
// frontend claimed the .gsp extension the file fell out of every language filter: no
// module, no node, nothing for a binding to label. The scope profile is data, not Go,
// so the test pins a minimal data dir that declares one and asserts the markup write
// inside the template comes out the other side of the lowering.
func TestGSPTemplateScopeLowersMarkupWrite(t *testing.T) {
	dataRoot := t.TempDir()
	metaDir := filepath.Join(dataRoot, "bindings", "config")
	if err := os.MkdirAll(metaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := `module bindings.config.test.gsp;

pattern bindingMetadata {
  binding: {
    name: "config"
    meta: {
      config_template_scopes: ["gsp"]
      config_template_input_pattern_gsp: "\\b(params|flash)\\.[A-Za-z0-9_]+\\b"
      config_template_input_event_gsp: "analysis.template.gsp.input"
      config_template_render_event_gsp: "analysis.template.gsp.render"
      cross_language: "true"
      fidelity: "resolved"
    }
  }
}
`
	if err := os.WriteFile(filepath.Join(metaDir, "gsp.vyql"), []byte(meta), 0o600); err != nil {
		t.Fatal(err)
	}

	oldRoot, _ := datadir.Lookup()
	datadir.Set(dataRoot)
	resetConfigProfile()
	defer func() {
		datadir.Set(oldRoot)
		resetConfigProfile()
	}()

	dir := t.TempDir()
	path := filepath.Join(dir, "_edit.gsp")
	src := `<div class="message">${flash.message}</div>
<div class="jobListTitle">${params.name}</div>
<div class="safe">${job.displayName}</div>
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf(".gsp file produced %d modules, want 1; the file was not lowered", len(prog.Modules))
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	renderCount := 0
	inputCount := 0
	for _, n := range nodes {
		switch n.Prop("callee_path") {
		case "analysis.template.gsp.render":
			renderCount++
		case "analysis.template.gsp.input":
			inputCount++
		}
	}
	// two writes the input pattern recognises; the third line names no input and must
	// stay unlabelled rather than widen the scope to every ${…} on the page.
	if renderCount != 2 {
		t.Fatalf("gsp render count = %d, want 2; nodes=%#v", renderCount, nodes)
	}
	if inputCount != 2 {
		t.Fatalf("gsp input count = %d, want 2; nodes=%#v", inputCount, nodes)
	}
}

// Claiming the extension is not the same as speaking for it. The config frontend
// reads every .gsp it is handed, but a template scope is data: with the metadata
// declaring jsp and no gsp scope, a Grails template full of ${…} writes lowers to
// no module at all, and no repository's findings move until a definition declares
// the scope. The same markup in a .jsp still lowers, which is what says the empty
// result is the undeclared scope and not a fixture that lowers nothing anyway.
func TestGSPWithoutADeclaredScopeStaysUnlowered(t *testing.T) {
	dataRoot := t.TempDir()
	metaDir := filepath.Join(dataRoot, "bindings", "config")
	if err := os.MkdirAll(metaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := `module bindings.config.test.nogsp;

pattern bindingMetadata {
  binding: {
    name: "config"
    meta: {
      config_template_scopes: ["jsp"]
      config_template_input_pattern_jsp: "\\b(params|flash)\\.[A-Za-z0-9_]+\\b"
      config_template_input_event_jsp: "analysis.template.jsp.input"
      config_template_render_event_jsp: "analysis.template.jsp.render"
      cross_language: "true"
      fidelity: "resolved"
    }
  }
}
`
	if err := os.WriteFile(filepath.Join(metaDir, "nogsp.vyql"), []byte(meta), 0o600); err != nil {
		t.Fatal(err)
	}

	oldRoot, _ := datadir.Lookup()
	datadir.Set(dataRoot)
	resetConfigProfile()
	defer func() {
		datadir.Set(oldRoot)
		resetConfigProfile()
	}()

	dir := t.TempDir()
	src := `<div class="message">${flash.message}</div>
<div class="jobListTitle">${params.name}</div>
`
	gsp := filepath.Join(dir, "_edit.gsp")
	if err := os.WriteFile(gsp, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	jsp := filepath.Join(dir, "edit.jsp")
	if err := os.WriteFile(jsp, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := Extract([]string{gsp, jsp}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range prog.Modules {
		if strings.HasSuffix(m.File, ".gsp") {
			t.Fatalf("%s lowered to a module under a profile that declares no gsp scope; claiming the extension moved a finding", m.File)
		}
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("the same markup in a .jsp produced %d modules, want 1; the fixture does not show the empty gsp result is the undeclared scope", len(prog.Modules))
	}
}

// templateCallShapes renders every expression statement of a lowered template as the
// call shape it produced, so a test reads "render(escape(input(old.email)))" rather
// than counting nodes and guessing at the nesting.
func templateCallShapes(prog nir.Program) []string {
	var shapes []string
	var expr func(nir.Expr) string
	expr = func(e nir.Expr) string {
		switch x := e.(type) {
		case nir.Call:
			args := make([]string, 0, len(x.Args))
			for _, a := range x.Args {
				args = append(args, expr(a))
			}
			return strings.TrimPrefix(x.Path, "analysis.template.") + "(" + strings.Join(args, ", ") + ")"
		case nir.Const:
			return x.Value
		case nir.Name:
			return x.ID
		}
		return fmt.Sprintf("%T", e)
	}
	for _, m := range prog.Modules {
		for _, st := range m.Body {
			fn, ok := st.(nir.FuncDef)
			if !ok {
				continue
			}
			for _, s := range fn.Body {
				if es, ok := s.(nir.ExprStmt); ok {
					shapes = append(shapes, expr(es.Value))
				}
			}
		}
	}
	return shapes
}

// pinDataDir installs a data root holding one config binding whose metadata
// declares the template scopes the caller names, and returns a function that
// puts the previous root back. The scope profile is data, not Go, so the tests
// pin a minimal data dir rather than reach into loadProfile.
func pinDataDir(t *testing.T, meta string) func() {
	t.Helper()
	dataRoot := t.TempDir()
	metaDir := filepath.Join(dataRoot, "bindings", "config")
	if err := os.MkdirAll(metaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(metaDir, "scope.vyql"), []byte(meta), 0o600); err != nil {
		t.Fatal(err)
	}
	oldRoot, _ := datadir.Lookup()
	datadir.Set(dataRoot)
	resetConfigProfile()
	return func() {
		datadir.Set(oldRoot)
		resetConfigProfile()
	}
}

// A Twig template's `{{ … }}` is an output position: the CVE this scope exists for
// renders a session-carried value straight into a value attribute at the vulnerable
// revision and gains `|e` at the fixed one, so what the frontend must hand the
// definitions is a render call per output, the input expression beneath it, and —
// only where the template escapes — an escape call between the two. Without a
// frontend claiming .twig, none of the three reached the graph at all.
func TestTwigTemplateScopeLowersOutputAndEscapeFilter(t *testing.T) {
	defer pinDataDir(t, `module bindings.config.test.twig;

pattern bindingMetadata {
  binding: {
    name: "config"
    meta: {
      config_template_scopes: ["twig"]
      config_template_expr_start_twig: "{{"
      config_template_expr_end_twig: "}}"
      config_template_input_pattern_twig: "\\b(old\\.[A-Za-z0-9_]+|recovertoken)\\b"
      config_template_input_event_twig: "analysis.template.twig.input"
      config_template_render_event_twig: "analysis.template.twig.render"
      config_template_escape_event_twig: "analysis.template.twig.escape"
      config_template_escape_filters_twig: ["e", "escape"]
      cross_language: "true"
      fidelity: "resolved"
    }
  }
}
`)()

	dir := t.TempDir()
	path := filepath.Join(dir, "reset.twig")
	src := `{% extends 'layouts/layoutAuth.twig' %}
{% block content %}
<form method="POST" action="{{ url_for("auth.login") }}">
<input type="text" name="username" value="{{ old.username }}">
<input type="hidden" name="recovertoken" value="{{recovertoken}}">
<input type="text" name="email" value="{{ old.email|e }}">
<span class="error">{{ errors.username|first }}</span>
{% endblock %}
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf(".twig file produced %d modules, want 1; the file was not lowered", len(prog.Modules))
	}
	want := []string{
		// the vulnerable spelling: the input reaches the render with nothing between
		"twig.render(twig.input(old.username))",
		"twig.render(twig.input(recovertoken))",
		// the patched spelling: the declared escape filter sits between the two
		"twig.render(twig.escape(twig.input(old.email)))",
	}
	if shapes := templateCallShapes(prog); !reflect.DeepEqual(shapes, want) {
		t.Fatalf("twig output shapes =\n  %s\nwant\n  %s\n(a filter the metadata does not name must not become an escape, and an expression the input pattern does not recognise must stay unlabelled)",
			strings.Join(shapes, "\n  "), strings.Join(want, "\n  "))
	}
}

// The escape filter is a spelling the metadata declares, not one the engine knows:
// with no filter named for the scope, `|e` is just text in the input expression and
// lowers to a plain input. This is what keeps Twig's filter names in the definitions,
// where a binding answers for them, rather than baked into the frontend.
func TestTwigEscapeFilterIsDeclaredNotBuiltIn(t *testing.T) {
	defer pinDataDir(t, `module bindings.config.test.twig.nofilters;

pattern bindingMetadata {
  binding: {
    name: "config"
    meta: {
      config_template_scopes: ["twig"]
      config_template_expr_start_twig: "{{"
      config_template_expr_end_twig: "}}"
      config_template_input_pattern_twig: "\\bold\\.[A-Za-z0-9_]+\\b"
      config_template_input_event_twig: "analysis.template.twig.input"
      config_template_render_event_twig: "analysis.template.twig.render"
      config_template_escape_event_twig: "analysis.template.twig.escape"
      cross_language: "true"
      fidelity: "resolved"
    }
  }
}
`)()

	dir := t.TempDir()
	path := filepath.Join(dir, "login.twig")
	src := `<input type="text" name="username" value="{{ old.username|e }}">
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"twig.render(twig.input(old.username|e))"}
	if shapes := templateCallShapes(prog); !reflect.DeepEqual(shapes, want) {
		t.Fatalf("twig output shapes = %v, want %v; an undeclared filter must lower as plain input text", shapes, want)
	}
}

// Claiming .twig is not speaking for it. The config frontend reads every .twig it is
// handed, but a template scope is data: with the metadata declaring jsp and no twig
// scope, a Twig template lowers to no module at all, and no repository's findings move
// until a definition declares the scope. The same markup in a .jsp still lowers, which
// is what says the empty result is the undeclared scope and not a fixture that lowers
// nothing anyway.
func TestTwigWithoutADeclaredScopeStaysUnlowered(t *testing.T) {
	defer pinDataDir(t, `module bindings.config.test.no.twig;

pattern bindingMetadata {
  binding: {
    name: "config"
    meta: {
      config_template_scopes: ["jsp"]
      config_template_expr_start_jsp: "{{"
      config_template_expr_end_jsp: "}}"
      config_template_input_pattern_jsp: "\\bold\\.[A-Za-z0-9_]+\\b"
      config_template_input_event_jsp: "analysis.template.jsp.input"
      config_template_render_event_jsp: "analysis.template.jsp.render"
      cross_language: "true"
      fidelity: "resolved"
    }
  }
}
`)()

	dir := t.TempDir()
	src := `<input type="text" name="username" value="{{ old.username }}">
`
	twig := filepath.Join(dir, "login.twig")
	if err := os.WriteFile(twig, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	jsp := filepath.Join(dir, "login.jsp")
	if err := os.WriteFile(jsp, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := Extract([]string{twig, jsp}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range prog.Modules {
		if strings.HasSuffix(m.File, ".twig") {
			t.Fatalf("%s lowered to a module under a profile that declares no twig scope; claiming the extension moved a finding", m.File)
		}
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("the same markup in a .jsp produced %d modules, want 1; the fixture does not show the empty twig result is the undeclared scope", len(prog.Modules))
	}
}

// The filter grammar the escape recognition reads: a filter is a `|` followed by the
// declared name as a whole word, so `|escape` is not a declared `e` and `|first` is no
// escape at all. The prefix form keeps its own branch; these pin the suffix form.
func TestTemplateFilterArg(t *testing.T) {
	filters := []string{"e", "escape"}
	for _, tc := range []struct {
		expr  string
		inner string
		ok    bool
	}{
		{"old.username|e", "old.username", true},
		{"recovertoken|e", "recovertoken", true},
		{"old.email|escape", "old.email", true},
		{"old.email|escape('html')", "old.email", true},
		{"old.email|striptags|e", "old.email|striptags", true},
		{"errors.username|escape", "errors.username", true}, // the grammar holds; the input pattern decides the rest
		{"errors.username|first", "", false},
		{"errors.username|entry", "", false}, // a declared `e` is not the head of `entry`
		{"old.username", "", false},
	} {
		inner, ok := templateFilterArg(tc.expr, filters)
		if ok != tc.ok || inner != tc.inner {
			t.Errorf("templateFilterArg(%q) = (%q, %v), want (%q, %v)", tc.expr, inner, ok, tc.inner, tc.ok)
		}
	}
}
