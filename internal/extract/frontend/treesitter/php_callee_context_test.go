package treesitter_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
)

// phpFunctionContextOf extracts files as one program and returns the str_args of
// fn's analysis.function.context node. The frontend mints that node per function
// with `lang=php` first; lowering mints a second one from the FuncDef's own
// tokens, which for PHP is the declaration name alone, so the match keys on the
// pair only the frontend's node carries.
func phpFunctionContextOf(t *testing.T, files map[string]string, fn string) string {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for name, src := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	prog, err := treesitter.ExtractPHP(paths, dir)
	if err != nil {
		t.Fatalf("ExtractPHP: %v", err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatalf("Lower: %v", err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	key := "lang=php\x00name=" + fn + "\x00"
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		if strings.HasPrefix(n.Prop("str_args"), key) {
			return n.Prop("str_args")
		}
	}
	t.Fatalf("no function context for %s", fn)
	return ""
}

// The options class this test uses is the CVE's own: the write reaches
// update_option through a same-class helper, so `$this->update_all()` is the
// call the hop has to resolve for a binding to read one hop past `set`.
const phpOptionsClass = `<?php
class WP_Auth0_Options {

	private $_options_name = 'wp_auth0';

	public function set( $key, $value ) {
		$options         = $this->get_options();
		$options[ $key ] = $value;
		return $this->update_all();
	}

	public function get_options() {
		return get_option( $this->_options_name );
	}

	public function update_all() {
		return update_option( $this->_options_name, $this->get_options() );
	}
}
`

func TestPHPFunctionContextIncludesDelegatedCalleeFacts(t *testing.T) {
	files := map[string]string{"lib/WP_Auth0_Options.php": phpOptionsClass}
	// `set` delegates the write to update_all, which performs it.
	set := phpFunctionContextOf(t, files, "set")
	for _, want := range []string{
		"callee:call_path=update_option",
		"callee:call=update_option",
		"callee:call_path=get_option",
		// the member paths the helper reads cross with it
		"callee:selector=$this._options_name",
	} {
		if !strings.Contains(set, want) {
			t.Fatalf("set's context lacks delegated fact %q; tokens=%q", want, set)
		}
	}
	// The re-keyed facts must not merge into the caller's own families: asking
	// what set itself does still cannot be answered by what update_all does.
	// The spellings differ on the separator, so the substring test is exact.
	for _, own := range []string{"call_path:update_option", "call:update_option", "selector:$this._options_name"} {
		if strings.Contains(set, own) {
			t.Fatalf("delegated fact leaked into set's own family %q; tokens=%q", own, set)
		}
	}
	// update_all performs the write itself, so its context is unchanged in kind:
	// the fact is its own, not a delegated one.
	updateAll := phpFunctionContextOf(t, files, "update_all")
	if !strings.Contains(updateAll, "call_path:update_option") {
		t.Fatalf("update_all's own context lost its own call; tokens=%q", updateAll)
	}
	if strings.Contains(updateAll, "callee:call=update_option") {
		t.Fatalf("update_all carries a delegated copy of its own call; tokens=%q", updateAll)
	}
}

func TestPHPDelegatedCalleeFactsCoverTheBareNameIdiom(t *testing.T) {
	tokens := phpFunctionContextOf(t, map[string]string{
		"handler.php": `<?php
function wp_auth0_verify_nonce( $nonce ) {
	return wp_verify_nonce( $nonce, 'wp_auth0_callback_step1' );
}

function wp_auth0_save_domain( $nonce ) {
	if ( ! wp_auth0_verify_nonce( $nonce ) ) {
		wp_nonce_ays( 'wp_auth0_callback_step1' );
		exit;
	}
	$domain = $_REQUEST['domain'];
	update_option( 'wp_auth0', $domain );
}
`,
	}, "wp_auth0_save_domain")
	for _, want := range []string{
		"callee:call_path=wp_verify_nonce",
		"callee:call=wp_verify_nonce",
	} {
		if !strings.Contains(tokens, want) {
			t.Fatalf("the handler's context lacks the delegated nonce check %q; tokens=%q", want, tokens)
		}
	}
	if strings.Contains(tokens, "call_path:wp_verify_nonce") {
		t.Fatalf("the delegated check leaked into the handler's own call family; tokens=%q", tokens)
	}
}

func TestPHPDelegatedCalleeFactsAreOneHopAndReceiverResolved(t *testing.T) {
	tokens := phpFunctionContextOf(t, map[string]string{
		"nested.php": `<?php
class Base {
	public function inherited() { wp_die( 'no' ); }
}

class Handler extends Base {

	public function deepest() {
		return update_option( 'wp_auth0', array() );
	}

	public function middle() {
		return $this->deepest();
	}

	public function outer( $obj ) {
		$this->middle();
		self::middle();
		static::middle();
		$obj->middle();
		$this->inherited();
		return $this->missing();
	}
}
`,
	}, "outer")
	// One link: middle's own behaviour crosses, and the call deepest makes
	// crosses only as a call path, never as deepest's behaviour.
	if !strings.Contains(tokens, "callee:call=deepest") {
		t.Fatalf("outer's context lacks the first hop's fact; tokens=%q", tokens)
	}
	if strings.Contains(tokens, "callee:call=update_option") {
		t.Fatalf("the hop recursed past its first link; tokens=%q", tokens)
	}
	// `$obj->middle()` needs the receiver's type, which the hop does not resolve;
	// `parent::inherited()` names the base clause, a different and unresolved
	// target; and a method this file does not declare resolves to nothing.
	for _, unwanted := range []string{"callee:call=inherited", "callee:call=missing"} {
		if strings.Contains(tokens, unwanted) {
			t.Fatalf("a call the hop cannot resolve contributed %q; tokens=%q", unwanted, tokens)
		}
	}
}

func TestPHPDelegatedCalleeFactsSeparateCheckingFromNonCheckingHelpers(t *testing.T) {
	// The two handlers differ only in what the helper they call does, which is
	// the discrimination the delegated facts exist to carry: before them, these
	// two contexts were identical apart from the helpers' names.
	files := map[string]string{
		"admin.php": `<?php
function wp_auth0_verify_nonce( $nonce ) {
	return wp_verify_nonce( $nonce, 'wp_auth0_callback_step1' );
}

function wp_auth0_log( $what ) {
	wp_debug_log( $what );
}

function wp_auth0_guarded_save( $nonce ) {
	if ( ! wp_auth0_verify_nonce( $nonce ) ) {
		exit;
	}
	update_option( 'wp_auth0', $_REQUEST['domain'] );
}

function wp_auth0_unguarded_save( $nonce ) {
	wp_auth0_log( $nonce );
	update_option( 'wp_auth0', $_REQUEST['domain'] );
}
`,
	}
	guarded := phpFunctionContextOf(t, files, "wp_auth0_guarded_save")
	unguarded := phpFunctionContextOf(t, files, "wp_auth0_unguarded_save")
	if !strings.Contains(guarded, "callee:call=wp_verify_nonce") {
		t.Fatalf("the guarded handler's context lacks the delegated nonce fact; tokens=%q", guarded)
	}
	if strings.Contains(unguarded, "callee:call=wp_verify_nonce") {
		t.Fatalf("the unguarded handler's context carries a nonce fact no helper it calls performs; tokens=%q", unguarded)
	}
}

func TestPHPDelegatedCalleeFactsResolveTheFormsPHPResolves(t *testing.T) {
	tokens := phpFunctionContextOf(t, map[string]string{
		"forms.php": `<?php
namespace Sub {
	function helper() { wp_verify_nonce( 'a', 'b' ); }
}

class Options {
	public function update_all() {
		return update_option( 'wp_auth0', array() );
	}
}

function wp_auth0_static_caller() {
	return Options::update_all();
}

function wp_auth0_qualified_caller() {
	return Sub\helper();
}

function twice() { check_admin_referer( 'a' ); }
function twice() { check_admin_referer( 'b' ); }

function wp_auth0_ambiguous_caller() {
	return twice();
}
`,
	}, "wp_auth0_static_caller")
	if !strings.Contains(tokens, "callee:call=update_option") {
		t.Fatalf("a class named outright did not resolve; tokens=%q", tokens)
	}
	// A qualified name resolves through a namespace this index does not carry.
	qualified := phpFunctionContextOf(t, map[string]string{
		"forms.php": `<?php
namespace Sub {
	function helper() { wp_verify_nonce( 'a', 'b' ); }
}
function wp_auth0_qualified_caller() {
	return Sub\helper();
}
`,
	}, "wp_auth0_qualified_caller")
	if strings.Contains(qualified, "callee:call=wp_verify_nonce") {
		t.Fatalf("a namespace-qualified callee crossed the hop; tokens=%q", qualified)
	}
	// A name the file declares twice names either declaration, so neither.
	ambiguous := phpFunctionContextOf(t, map[string]string{
		"forms.php": `<?php
function twice() { check_admin_referer( 'a' ); }
function twice() { check_admin_referer( 'b' ); }
function wp_auth0_ambiguous_caller() {
	return twice();
}
`,
	}, "wp_auth0_ambiguous_caller")
	if strings.Contains(ambiguous, "callee:call=check_admin_referer") {
		t.Fatalf("an ambiguous callee crossed the hop; tokens=%q", ambiguous)
	}
}

func TestPHPDelegatedCalleeFactsSkipSelfRecursionAndCrossFileCallees(t *testing.T) {
	tokens := phpFunctionContextOf(t, map[string]string{
		// The helper lives in another file, which is the boundary the hop draws:
		// the converter lowers one file at a time, so a callee another file
		// declares spends no budget.
		"other.php": `<?php
function wp_auth0_verify_nonce( $nonce ) {
	return wp_verify_nonce( $nonce, 'action' );
}
`,
		"caller.php": `<?php
function wp_auth0_recursive_save( $key ) {
	if ( $key ) {
		return wp_auth0_recursive_save( $key - 1 );
	}
	return update_option( 'wp_auth0', $key );
}

function wp_auth0_caller( $nonce ) {
	wp_auth0_verify_nonce( $nonce );
	return update_option( 'wp_auth0', $nonce );
}
`,
	}, "wp_auth0_recursive_save")
	if strings.Contains(tokens, "callee:call=update_option") {
		t.Fatalf("a self-call attributed the function's own behaviour back to it; tokens=%q", tokens)
	}
	caller := phpFunctionContextOf(t, map[string]string{
		"other.php": `<?php
function wp_auth0_verify_nonce( $nonce ) {
	return wp_verify_nonce( $nonce, 'action' );
}
`,
		"caller.php": `<?php
function wp_auth0_caller( $nonce ) {
	wp_auth0_verify_nonce( $nonce );
	return update_option( 'wp_auth0', $nonce );
}
`,
	}, "wp_auth0_caller")
	if strings.Contains(caller, "callee:call=wp_verify_nonce") {
		t.Fatalf("a callee another file declares crossed the hop; tokens=%q", caller)
	}
}

func TestPHPDelegatedCalleeFactsAreBounded(t *testing.T) {
	// Nine same-file helpers, each doing something distinct: the budget is eight
	// resolved callees, so the ninth contributes nothing even though it resolves.
	src := "<?php\n"
	for i := 0; i < 9; i++ {
		src += "function helper_" + strconv.Itoa(i) + "( $v ) {\n\tdistinct_" + strconv.Itoa(i) + "( $v );\n}\n"
	}
	src += "function wp_auth0_many_helpers( $v ) {\n"
	for i := 0; i < 9; i++ {
		src += "\thelper_" + strconv.Itoa(i) + "( $v );\n"
	}
	src += "}\n"
	tokens := phpFunctionContextOf(t, map[string]string{"many.php": src}, "wp_auth0_many_helpers")
	if !strings.Contains(tokens, "callee:call=distinct_7") {
		t.Fatalf("the eighth resolved callee did not contribute; tokens=%q", tokens)
	}
	if strings.Contains(tokens, "callee:call=distinct_8") {
		t.Fatalf("the ninth resolved callee crossed the callee budget; tokens=%q", tokens)
	}
	if got := strings.Count(tokens, "callee:"); got > 64 {
		t.Fatalf("delegated token budget exceeded: %d callee tokens; tokens=%q", got, tokens)
	}
}
