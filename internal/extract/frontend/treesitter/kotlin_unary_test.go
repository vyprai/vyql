package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
)

// A unary operator on a call argument must not hide the argument from a sink
// binding: a postfix operator (`uri!!`, `i++`) leaves the flowing value
// unchanged and lowers as a pass-through, and a prefix one (`-count`, `!flag`)
// keeps its operator the way the java and rust frontends lower theirs. Before
// this, every unary expression fell to the generic Seq fallback and the sink
// applicator skipped the argument.
func TestKotlinUnaryExpressionArgumentKeepsValueShape(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "Unary.kt")
	src := `
fun read() {
  val a = contentResolver.openInputStream(intent.data!!)
  val b = loadBytes(-count)
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

	sawPostfixArg, sawPrefixUnary := false, false
	args, _ := g.NodesOfType("code.Arg")
	for _, id := range args {
		n, ok, _ := g.GetNode(id)
		if !ok {
			continue
		}
		if n.Prop("vkind") == "Seq" {
			t.Fatalf("argument at %s lowered as Seq; a sink applicator would skip it", n.Prop("loc"))
		}
		if strings.Contains(n.Prop("loc"), "Unary.kt:3") && n.Prop("vkind") != "" {
			sawPostfixArg = true
		}
	}
	unaries, _ := g.NodesOfType("code.Unary")
	for _, id := range unaries {
		n, ok, _ := g.GetNode(id)
		if !ok {
			continue
		}
		if strings.Contains(n.Prop("loc"), "Unary.kt:4") {
			sawPrefixUnary = true
		}
	}
	if !sawPostfixArg {
		t.Fatalf("the !!-asserted argument did not lower to a value-shaped Arg node")
	}
	if !sawPrefixUnary {
		t.Fatalf("the negated argument did not lower to a Unary node")
	}
}
