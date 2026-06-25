package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/usg"
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

func TestPHPFunctionContextIncludesParameterTypes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Driver.php")
	src := []byte(`<?php
class Driver {
  protected function unserialize(string $data) {
    if (is_numeric($data)) {
      return $data;
    }
    $unserialize = $this->options['serialize'][1] ?? "unserialize";
    return $unserialize($data);
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
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.function.context" && strings.Contains(n.Prop("str_args"), "name=unserialize") {
			args := n.Prop("str_args")
			for _, want := range []string{"param_type:string", "function_param_type:string"} {
				if !strings.Contains(args, want) {
					t.Fatalf("PHP function context missing %q; context=%q", want, args)
				}
			}
			return
		}
	}
	t.Fatalf("analysis.function.context for unserialize not found")
}

func TestPHPFunctionContextIncludesAssignmentFacts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "TempPath.php")
	src := []byte(`<?php
function zipdl($args) {
  $file = $args['targets'][1];
  $path = $volume->getTempPath() . DIRECTORY_SEPARATOR . $file;
  $GLOBALS['tempFiles'][$path] = true;
}
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
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.function.context" && strings.Contains(n.Prop("str_args"), "name=zipdl") {
			args := n.Prop("str_args")
			for _, want := range []string{
				"assign_call_method:getTempPath",
				"assign_literal:DIRECTORY_SEPARATOR",
				"global_subscript_write=true",
				"subscript:$GLOBALS['tempFiles'][$path]",
			} {
				if !strings.Contains(args, want) {
					t.Fatalf("PHP function context missing %q; context=%q", want, args)
				}
			}
			return
		}
	}
	t.Fatalf("analysis.function.context for zipdl not found")
}

func TestPHPObjectCreationArgumentsCarryAssignedTaint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Redirect.php")
	src := []byte(`<?php
function handle($request) {
  $url = Arr::get($request->getQueryParams(), 'return', '/');
  return new RedirectResponse($url);
}
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
	var source, sink string
	for _, n := range nodes {
		switch n.Prop("callee_path") {
		case "$request.getQueryParams":
			source = n.ID
		case "RedirectResponse":
			if n.Prop("arg0") == "" {
				t.Fatalf("RedirectResponse constructor is missing arg0: %#v", n)
			}
			sink = n.Prop("arg0")
		}
	}
	if source == "" || sink == "" {
		t.Fatalf("missing source or RedirectResponse arg; source=%q sink=%q nodes=%#v", source, sink, nodes)
	}
	reachable, err := usg.BFS(g, source, "FLOWS", 20)
	if err != nil {
		t.Fatal(err)
	}
	if reachable[sink] {
		return
	}
	t.Fatalf("query params did not flow into RedirectResponse arg; source=%q sink=%q reachable=%v", source, sink, reachable)
}

func TestPHPModuleContextIncludesAstInventory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "search.php")
	src := []byte(`<?php
$pageLimit = $http->variable('BrowsePageLimit');
$result = eZSearch::search($searchText, array('SearchLimit' => $pageLimit));
$tpl->setVariable('search_page_limit', $pageLimit);
foreach ($subTreeList as $subTreeItem) {
  if ($subTreeItem > 0) {
    $subTreeArray[] = $subTreeItem;
  }
}
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
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.module.context" {
			args := n.Prop("str_args")
			for _, want := range []string{
				"call_path:$http.variable",
				"call_path:eZSearch.search",
				"call_path:$tpl.setVariable",
				"subscript:$subTreeArray[]",
			} {
				if !strings.Contains(args, want) {
					t.Fatalf("PHP module context missing %q; context=%q", want, args)
				}
			}
			return
		}
	}
	t.Fatalf("analysis.module.context not found")
}

func TestPHPModuleContextIncludesCallArgsAndCastFacts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "search.php")
	src := []byte(`<?php
$http = eZHTTPTool::instance();
$pageLimit = (int)$http->variable('BrowsePageLimit');
$searchSectionID = (int)$http->variable('SectionID');
foreach ( $subTreeList as $subTreeItem ) {
    if ( is_numeric( $subTreeItem ) && $subTreeItem > 0 )
        $subTreeArray[] = $subTreeItem;
}
$searchResult = eZSearch::search( $searchText, array(
    'SearchSectionID' => $searchSectionID,
    'SearchSubTreeArray' => $subTreeArray,
    'SearchLimit' => $pageLimit
) );
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
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.module.context" {
			args := n.Prop("str_args")
			for _, want := range []string{
				"call_path:eZSearch.search",
				"call_arg:is_numeric:$subTreeItem",
				"assign_call:$pageLimit:$http.variable",
				"cast_call_literal:int:$http.variable:BrowsePageLimit",
				"cast_call_literal:int:$http.variable:SectionID",
			} {
				if !strings.Contains(args, want) {
					t.Fatalf("PHP module context missing %q; context=%q", want, args)
				}
			}
			return
		}
	}
	t.Fatalf("analysis.module.context not found")
}

func TestPHPClassContextIncludesPropertyAndMethodInventory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "FileService.php")
	src := []byte(`<?php
class FileService {
  protected $fallbackExtensions = 'jpg,jpeg,png,gif,bmp,svg,tif,tiff';

  protected function validFileExtension(): bool {
    $fileInfo = pathinfo($this->fileName);
    return GeneralUtility::inList($this->fallbackExtensions, strtolower($fileInfo['extension']))
      && GeneralUtility::verifyFilenameAgainstDenyPattern($this->fileName);
  }
}
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
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.class.context" && strings.Contains(n.Prop("str_args"), "name=FileService") {
			args := n.Prop("str_args")
			for _, want := range []string{
				"function_name:validFileExtension",
				"property:protected$fallbackExtensions='jpg,jpeg,png,gif,bmp,svg,tif,tiff';",
				"property_literal:jpg,jpeg,png,gif,bmp,svg,tif,tiff",
				"call_path:pathinfo",
				"call_path:GeneralUtility.inList",
				"call_path:GeneralUtility.verifyFilenameAgainstDenyPattern",
			} {
				if !strings.Contains(args, want) {
					t.Fatalf("PHP class context missing %q; context=%q", want, args)
				}
			}
			return
		}
	}
	t.Fatalf("analysis.class.context for FileService not found")
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
