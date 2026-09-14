package config

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/extract/lowering"
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
