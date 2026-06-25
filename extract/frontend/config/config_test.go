package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/extract/lowering"
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
