package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/extract/nir"
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

func TestPHPFunctionContextIncludesPolicyAccessTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ThreadPolicy.php")
	src := []byte(`<?php
class ThreadPolicy {
  public function edit(User $user, Thread $thread) {
    if (($thread->created_by_customer_id && in_array($thread->type, [Thread::TYPE_CUSTOMER]))) {
      return true;
    }
    return false;
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
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.function.context" && strings.Contains(n.Prop("str_args"), "name=edit") {
			args := n.Prop("str_args")
			for _, want := range []string{
				"param_type:User",
				"param_type:Thread",
				"attr_path:$thread.created_by_customer_id",
				"attr_path:$thread.type",
				"call_path:in_array",
				"Thread::TYPE_CUSTOMER",
			} {
				if !strings.Contains(args, want) {
					t.Fatalf("PHP policy function context missing %q; context=%q", want, args)
				}
			}
			return
		}
	}
	t.Fatalf("analysis.function.context for edit not found")
}

func TestPHPFunctionContextMarksBpDocsSaveWhenCapabilityCheckIsAfterSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Component.php")
	src := []byte(`<?php
class BP_Docs_Component {
  function catch_page_load() {
    if ( !empty( $_POST['doc-edit-submit'] ) ) {
      check_admin_referer( 'bp_docs_save' );
      $this_doc = new BP_Docs_Query;
      $result = $this_doc->save();
      bp_core_redirect( $result['redirect_url'] );
    }

    if ( bp_docs_is_doc_edit() ) {
      if ( current_user_can( 'bp_docs_edit' ) ) {
        return;
      }
    }

    if ( bp_docs_is_doc_create() ) {
      if ( ! current_user_can( 'bp_docs_create' ) ) {
        return;
      }
    }
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
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.function.context" && strings.Contains(n.Prop("str_args"), "name=catch_page_load") {
			args := n.Prop("str_args")
			if !strings.Contains(args, "php_review:bp_docs_save_missing_access_policy") {
				t.Fatalf("PHP BP Docs save review token missing when capability checks are after save; context=%q", args)
			}
			return
		}
	}
	t.Fatalf("analysis.function.context for catch_page_load not found")
}

func TestPHPFunctionContextDoesNotMarkBpDocsSaveWhenCapabilityCheckPrecedesSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Component.php")
	src := []byte(`<?php
class BP_Docs_Component {
  function catch_page_load() {
    if ( !empty( $_POST['doc-edit-submit'] ) ) {
      $doc = bp_docs_get_current_doc();
      if ( $doc && ! current_user_can( 'bp_docs_edit', $doc->ID ) ) {
        return;
      } elseif ( ! $doc && ! current_user_can( 'bp_docs_create' ) ) {
        return;
      }
      check_admin_referer( 'bp_docs_save' );
      $this_doc = new BP_Docs_Query;
      $result = $this_doc->save();
      bp_core_redirect( $result['redirect_url'] );
    }
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
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.function.context" && strings.Contains(n.Prop("str_args"), "name=catch_page_load") {
			args := n.Prop("str_args")
			if strings.Contains(args, "php_review:bp_docs_save_missing_access_policy") {
				t.Fatalf("PHP BP Docs save review token should be suppressed by prior capability checks; context=%q", args)
			}
			return
		}
	}
	t.Fatalf("analysis.function.context for catch_page_load not found")
}

func TestPHPFunctionContextIncludesAdminerRouteTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "AdminerController.php")
	src := []byte(`<?php
class AdminerController extends AbstractController {
  #[Route(path: '/adminer', name: 'administration.frosh_adminer', defaults: ['auth_required' => false], methods: ['GET', 'POST'])]
  public function index(): Response
  {
      chdir(__DIR__ . '/../Adminer');
      unset($_POST['auth']);
      require __DIR__ . '/../Adminer/Adminer.php';
      return new Response('');
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
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.function.context" && strings.Contains(n.Prop("str_args"), "name=index") {
			args := n.Prop("str_args")
			for _, want := range []string{
				"annotation:Route",
				"annotation_arg:Route:path:'/adminer'",
				"annotation_arg:Route:defaults:['auth_required'=>false]",
				"call_path:chdir",
				"call_path:include",
			} {
				if !strings.Contains(args, want) {
					t.Fatalf("PHP Adminer route context missing %q; context=%q", want, args)
				}
			}
			return
		}
	}
	t.Fatalf("analysis.function.context for index not found")
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

func TestPHPSimplexmlLoaderObservationRequiresScopedRestore(t *testing.T) {
	dir := t.TempDir()
	vuln := filepath.Join(dir, "vuln.php")
	fixed := filepath.Join(dir, "fixed.php")
	if err := os.WriteFile(vuln, []byte(`<?php
function XML2array($XMLstring) {
    libxml_disable_entity_loader(true);
    return simplexml_load_string($XMLstring);
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixed, []byte(`<?php
function XML2array($XMLstring) {
    $loader = libxml_disable_entity_loader(true);
    $xml = simplexml_load_string($XMLstring, 'SimpleXMLElement', LIBXML_NOENT);
    libxml_disable_entity_loader($loader);
    return $xml;
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{vuln, fixed}, dir)
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
	seenVuln := false
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.php.simplexml_unscoped_entity_loader" {
			continue
		}
		if strings.Contains(n.Prop("loc"), "fixed.php") {
			t.Fatalf("fixed scoped loader emitted unscoped observation at %s", n.Prop("loc"))
		}
		if strings.Contains(n.Prop("loc"), "vuln.php") {
			seenVuln = true
		}
	}
	if !seenVuln {
		t.Fatalf("vulnerable unscoped loader observation not found; nodes=%#v", nodes)
	}
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

func TestPHPReviewContextMarksRenamedGPGOptionDelimiter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "GPG.php")
	src := []byte(`<?php
class Crypt_GPG {
  public function deletePublicKey($fingerprint) {
    $cmd = '--delete-key ' . escapeshellarg($fingerprint);
  }
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !phpProgramHasContextToken(t, prog, "php_review:gpg_option_arg_missing_delimiter") {
		t.Fatalf("PHP GPG delimiter review token missing for renamed assignment: %#v", prog.Modules)
	}
}

func TestPHPReviewContextDoesNotMarkGPGOptionWithDelimiter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "GPG.php")
	src := []byte(`<?php
class Crypt_GPG {
  public function deletePublicKey($fingerprint) {
    $cmd = '--delete-key -- ' . escapeshellarg($fingerprint);
  }
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if phpProgramHasContextToken(t, prog, "php_review:gpg_option_arg_missing_delimiter") {
		t.Fatalf("PHP GPG delimiter review token should not appear for guarded command: %#v", prog.Modules)
	}
}

func TestPHPReviewContextMarksRenamedAbsolutePathDisclosure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Driver.php")
	src := []byte(`<?php
class LocalDriver {
  public function addFile($source, $folder, $name) {
    $target = $this->getAbsolutePath($folder . '/' . $name);
    return rename($source, $target);
  }
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !phpProgramHasContextToken(t, prog, "php_review:absolute_path_disclosure_rename") {
		t.Fatalf("PHP absolute path disclosure review token missing: %#v", prog.Modules)
	}
}

func TestPHPReviewContextDoesNotMarkSuppressedAbsolutePathDisclosure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Driver.php")
	src := []byte(`<?php
class LocalDriver {
  public function addFile($source, $folder, $name) {
    $target = $this->getAbsolutePath($folder . '/' . $name);
    return @rename($source, $target);
  }
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if phpProgramHasContextToken(t, prog, "php_review:absolute_path_disclosure_rename") {
		t.Fatalf("PHP absolute path disclosure review token should not appear for suppressed call: %#v", prog.Modules)
	}
}

func TestPHPReviewContextMarksTempPathJoinBeforeSeparatorCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "TempLinks.php")
	src := []byte(`<?php
class LinkFactory {
  public function createTemporaryLink($displayName = null) {
    if ($this->tmpLinkPath) {
      if (! $displayName) {
        $displayName = 'temp_' . md5($_SERVER['REMOTE_ADDR'] . microtime(true));
      } else if (substr($displayName, 0, 5) !== 'temp_') {
        $displayName = 'temp_' . $displayName;
      }
      return array(
        'path' => $path = $this->tmpLinkPath . DIRECTORY_SEPARATOR . $displayName,
        'url' => $this->tmpLinkUrl . '/' . $displayName
      );
    }
    return false;
  }
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !phpProgramHasContextToken(t, prog, "php_review:temp_path_join_before_separator_check") {
		t.Fatalf("PHP temp path separator review token missing: %#v", prog.Modules)
	}
}

func TestPHPReviewContextMarksTempPathMethodJoinBeforeSeparatorCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "TempArchive.php")
	src := []byte(`<?php
function downloadTempArchive($args) {
  $targets = $args['targets'];
  $entryName = $targets[1];
  $path = $volume->getTempPath() . DIRECTORY_SEPARATOR . $entryName;
  $GLOBALS['tempFiles'][$path] = true;
  return fopen($path, 'rb');
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !phpProgramHasContextToken(t, prog, "php_review:temp_path_join_before_separator_check") {
		t.Fatalf("PHP temp path method review token missing: %#v", prog.Modules)
	}
}

func TestPHPReviewContextDoesNotMarkTempPathJoinWithSeparatorGuard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "TempLinks.php")
	src := []byte(`<?php
class LinkFactory {
  public function createTemporaryLink($displayName) {
    if (strpos($displayName, DIRECTORY_SEPARATOR) !== false) {
      return false;
    }
    return $this->tmpLinkPath . DIRECTORY_SEPARATOR . $displayName;
  }
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if phpProgramHasContextToken(t, prog, "php_review:temp_path_join_before_separator_check") {
		t.Fatalf("PHP temp path separator review token should not appear for guarded join: %#v", prog.Modules)
	}
}

func TestPHPReviewContextDoesNotMarkTempPathJoinWithSeparatorNormalization(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "TempLinks.php")
	src := []byte(`<?php
class LinkFactory {
  public function createTemporaryLink($displayName) {
    $displayName = str_replace(array('/', '\\'), '_', $displayName);
    return $this->tmpLinkPath . DIRECTORY_SEPARATOR . $displayName;
  }
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if phpProgramHasContextToken(t, prog, "php_review:temp_path_join_before_separator_check") {
		t.Fatalf("PHP temp path separator review token should not appear for normalized join: %#v", prog.Modules)
	}
}

func TestPHPReviewContextMarksFatFreeClearEvalCompileParam(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Base.php")
	src := []byte(`<?php
final class Base {
  function compile($expr) {
    return $expr;
  }
  function clear($key) {
    eval('unset('.$this->compile('@this->hive.'.$key).');');
  }
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !phpProgramHasContextToken(t, prog, "php_review:fatfree_clear_eval_compile_without_key_validation") {
		t.Fatalf("PHP Fat-Free clear eval review token missing: %#v", prog.Modules)
	}
}

func TestPHPReviewContextDoesNotMarkGuardedFatFreeClearEvalCompileParam(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Base.php")
	src := []byte(`<?php
final class Base {
  function compile($expr) {
    return $expr;
  }
  function clear($key) {
    $key = preg_replace('/(\)\W*\w+.*$)/', '', $key);
    eval('unset('.$this->compile('@this->hive.'.$key).');');
  }
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if phpProgramHasContextToken(t, prog, "php_review:fatfree_clear_eval_compile_without_key_validation") {
		t.Fatalf("PHP Fat-Free clear eval review token should not appear for guarded key: %#v", prog.Modules)
	}
}

func TestPHPReviewContextMarksCurlAndCorsSemantics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.php")
	src := []byte(`<?php
function configure($ch) {
  curl_setopt_array($ch, [
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => 0,
  ]);
  header('Access-Control-Allow-Origin: *');
}`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"php_review:curl_ssl_verifypeer_disabled",
		"php_review:curl_ssl_verifyhost_disabled",
		"php_review:permissive_cors_header",
	} {
		if !phpProgramHasContextToken(t, prog, want) {
			t.Fatalf("PHP review token %q missing: %#v", want, prog.Modules)
		}
	}
}

func TestPHPReviewContextMarksAuthCookieAndTemplateSemantics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "review.php")
	src := []byte(`<?php
class BackendController {
  public function deleteUserAction() {
    $this->redirect($this->deleteBy($this->request));
  }
  public function process() {
    $this->getRequiredBodyParam('bucket');
    $this->loadBucketList();
    return $this->asJson([]);
  }
}
function renderTemplate($type, $language, $name) {
  return "templates/{$type}/{$language}/{$name}.tpl";
}
function boot($x) {
  setcookie('sid', $x, ['secure' => false, 'httponly' => false]);
  header('X-Frame-Options: ALLOWALL');
}
foreach ($_GET as $key => $value) {
  $$key = $value;
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"php_review:state_changing_action_missing_method_assertion_delete_by",
		"php_review:credentialed_endpoint_missing_admin_bucket_list",
		"php_review:template_path_component_traversal_type",
		"php_review:template_path_component_traversal_language",
		"php_review:template_path_component_traversal_name",
		"php_review:cookie_secure_false",
		"php_review:cookie_httponly_false",
		"php_review:missing_frame_protection_allowall",
		"php_review:request_variable_variable_assignment",
	} {
		if !phpProgramHasContextToken(t, prog, want) {
			t.Fatalf("PHP review token %q missing: %#v", want, prog.Modules)
		}
	}
}

func TestPHPBackendCalendarEventsMissingAuthorizationReviewToken(t *testing.T) {
	dir := t.TempDir()
	vuln := filepath.Join(dir, "vuln.php")
	fixed := filepath.Join(dir, "fixed.php")
	if err := os.WriteFile(vuln, []byte(`<?php
class Backend_api {
  public function ajax_get_calendar_events() {
    $response = [
      'appointments' => $this->appointments_model->get_batch([
        'is_unavailable' => FALSE,
        'start_datetime >=' => $this->input->post('startDate'),
        'end_datetime <=' => $this->input->post('endDate')
      ])
    ];
    foreach ($response['appointments'] as &$appointment) {
      $appointment['provider'] = $this->providers_model->get_row($appointment['id_users_provider']);
      $appointment['service'] = $this->services_model->get_row($appointment['id_services']);
      $appointment['customer'] = $this->customers_model->get_row($appointment['id_users_customer']);
    }
    $this->output->set_output(json_encode($response));
  }
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixed, []byte(`<?php
class Backend_api {
  public function ajax_get_calendar_events() {
    if ($this->privileges[PRIV_APPOINTMENTS]['view'] == FALSE) {
      throw new Exception('You do not have the required privileges for this task.');
    }
    $response = [
      'appointments' => $this->appointments_model->get_batch([
        'is_unavailable' => FALSE,
        'start_datetime >=' => $this->input->post('startDate'),
        'end_datetime <=' => $this->input->post('endDate')
      ])
    ];
    foreach ($response['appointments'] as &$appointment) {
      $appointment['provider'] = $this->providers_model->get_row($appointment['id_users_provider']);
      $appointment['service'] = $this->services_model->get_row($appointment['id_services']);
      $appointment['customer'] = $this->customers_model->get_row($appointment['id_users_customer']);
    }
    $this->output->set_output(json_encode($response));
  }
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{vuln, fixed}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !phpProgramFileHasContextToken(t, prog, "vuln.php", "php_review:backend_calendar_events_missing_authorization") {
		t.Fatalf("vulnerable backend calendar events handler missing review token: %#v", prog.Modules)
	}
	if !phpProgramFileHasCallPath(t, prog, "vuln.php", "analysis.php.backend_calendar_events_missing_authorization") {
		t.Fatalf("vulnerable backend calendar events handler missing analysis observation: %#v", prog.Modules)
	}
	if phpProgramFileHasContextToken(t, prog, "fixed.php", "php_review:backend_calendar_events_missing_authorization") {
		t.Fatalf("fixed backend calendar events handler should not emit review token: %#v", prog.Modules)
	}
	if phpProgramFileHasCallPath(t, prog, "fixed.php", "analysis.php.backend_calendar_events_missing_authorization") {
		t.Fatalf("fixed backend calendar events handler should not emit analysis observation: %#v", prog.Modules)
	}
}

func phpProgramHasContextToken(t *testing.T, prog nir.Program, want string) bool {
	t.Helper()
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if strings.Contains(n.Prop("str_args"), want) {
			return true
		}
	}
	return false
}

func phpProgramFileHasContextToken(t *testing.T, prog nir.Program, file, want string) bool {
	t.Helper()
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if strings.Contains(n.Prop("loc"), file) && strings.Contains(n.Prop("str_args"), want) {
			return true
		}
	}
	return false
}

func phpProgramFileHasCallPath(t *testing.T, prog nir.Program, file, want string) bool {
	t.Helper()
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type == "code.Call" && strings.Contains(n.Prop("loc"), file) && n.Prop("callee_path") == want {
			return true
		}
	}
	return false
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
