package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
)

func TestCSharpExtractsCallsInsidePreprocessorBranches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Sample.cs")
	src := `using System;
using System.Runtime.Loader;

class T {
  public static Type GetType(string typeName, bool throwOnError, bool ignoreCase) {
    try {
      return Type.GetType(typeName, throwOnError, ignoreCase);
    } catch {
#if NET5_0_OR_GREATER
      string[] splitName = typeName.Split(',');
      var asm = AssemblyLoadContext.Default.LoadFromAssemblyPath(AppContext.BaseDirectory + splitName[1].Trim() + ".dll");
      return asm.GetType(splitName[0].Trim());
#else
      throw;
#endif
    }
  }
}`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractCSharp([]string{path}, dir)
	if err != nil {
		t.Fatalf("ExtractCSharp: %v", err)
	}
	g, err := lowering.Lower(prog, false)
	if err != nil {
		t.Fatalf("Lower: %v", err)
	}
	calls, _ := g.NodesOfType("code.Call")
	for _, id := range calls {
		n, _, _ := g.GetNode(id)
		if strings.Contains(n.Prop("callee_path"), "LoadFromAssemblyPath") {
			return
		}
	}
	t.Fatal("expected LoadFromAssemblyPath call inside #if branch to be extracted")
}
