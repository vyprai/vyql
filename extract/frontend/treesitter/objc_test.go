package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
)

// The vendored tree-sitter Objective-C grammar (cgo-wrapped) finds a command
// injection: getenv flows through [NSString stringWithFormat:] into system().
func TestTreeSitterObjC(t *testing.T) {
	run := func(src string) int {
		dir := t.TempDir()
		p := filepath.Join(dir, "Foo.m")
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		prog, _ := treesitter.ExtractObjC([]string{p}, dir)
		g, _ := lowering.Lower(prog, true)
		adapters.Apply(g, frontend.ObjCAdapters(), nil)
		onto := ontology.Seed()
		decls, _ := parser.Parse(twoSinkRules)
		compiled, _ := engine.CompileRules(decls, onto)
		var n int
		for _, cr := range compiled {
			fs, _ := engine.New(onto, g).Evaluate(cr)
			n += len(fs)
		}
		return n
	}

	vuln := `@implementation Foo
- (void)run {
  char *name = getenv("NAME");
  NSString *cmd = [NSString stringWithFormat:@"ping %s", name];
  system([cmd UTF8String]);
}
@end`
	if run(vuln) == 0 {
		t.Fatal("expected command injection (getenv → stringWithFormat → system), got 0")
	}

	safe := `@implementation Foo
- (void)run {
  system("ping localhost");
}
@end`
	if run(safe) != 0 {
		t.Fatal("constant command should be clean, got a finding")
	}
}
