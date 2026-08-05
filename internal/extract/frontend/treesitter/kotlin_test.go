package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
)

func TestKotlinPropertyInitializerScopeFunctionLambdaIsLowered(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "BaselineFormat.kt")
	src := `
fun read() {
  val reader = SAXParserFactory.newInstance()
    .apply {
      setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
    }
    .newSAXParser()
  reader.parse(input, handler)
}`
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractKotlin([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}

	var sawSetFeature, sawNewSAXParser bool
	cs, _ := g.NodesOfType("code.Call")
	for _, id := range cs {
		n, _, _ := g.GetNode(id)
		path := n.Prop("callee_path")
		if strings.Contains(path, "setFeature") {
			sawSetFeature = true
		}
		if strings.Contains(path, "newSAXParser") {
			sawNewSAXParser = true
		}
	}
	if !sawSetFeature {
		t.Fatalf("scope-function lambda body was not lowered; missing setFeature call")
	}
	if !sawNewSAXParser {
		t.Fatalf("parser construction was not lowered; missing newSAXParser call")
	}
}
