package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
)

func TestPHPFunctionContextIncludesAstInventory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "TasksController.php")
	src := []byte(`<?php
class TasksController {
  public function anyData() {
    return Datatables::of($tasks)
      ->addColumn('view', function ($tasks) {
        return '<a data-title="' . $tasks->title . '">Delete</a>';
      })
      ->rawColumns(['view'])
      ->make(true);
  }
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{path}, dir)
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
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.function.context" && strings.Contains(n.Prop("str_args"), "name=anyData") {
			args := n.Prop("str_args")
			for _, want := range []string{
				"call_path:Datatables.of",
				"call_path:Datatables.of.addColumn.rawColumns",
				"attr_path:$tasks.title",
			} {
				if !strings.Contains(args, want) {
					t.Fatalf("PHP function context missing %q; context=%q", want, args)
				}
			}
			return
		}
	}
	t.Fatalf("analysis.function.context for anyData not found")
}

func TestPHPLegacyScriptLanguageTagParsesStatements(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "search_opensearch.php")
	src := []byte(`<script language="PHP">
$query = array_key_exists('query', $_GET) ? $_GET['query'] : "";
print "Search results for '$query':\n\n";
</script>
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{path}, dir)
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
	var sawPost, sawPrint bool
	for _, n := range nodes {
		if strings.Contains(n.Prop("callee_path"), "$_GET") || strings.Contains(n.Prop("path"), "$_GET") {
			sawPost = true
		}
		if n.Type == "code.Call" && n.Prop("method") == "print" {
			sawPrint = true
		}
	}
	if !sawPost || !sawPrint {
		t.Fatalf("legacy PHP script tag did not expose $_GET and print nodes; sawGet=%v sawPrint=%v", sawPost, sawPrint)
	}
}
