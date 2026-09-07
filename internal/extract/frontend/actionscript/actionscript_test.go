package actionscript

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// jplayerShape is the ActionScript this frontend exists for: CVE-2013-1942's
// Jplayer.as, cut down to the flash-vars read, the concatenation it feeds, and the
// ExternalInterface.call the built string reaches. Every construct in it is one the
// JavaScript grammar rejects outright — the package block, the typed member, the
// typed parameter, `for each`, and the `:void` return annotation.
const jplayerShape = `package happyworm.jPlayer {
	import flash.external.ExternalInterface;
	import flash.system.Security;

	public class Jplayer extends Sprite {
		private var jQuery:String;
		private var securityIssue:Boolean = false;

		public function Jplayer() {
			Security.allowDomain("*");
			checkFlashVars(loaderInfo.parameters);
			if(!securityIssue) {
				jQuery = loaderInfo.parameters.jQuery + "('#" + loaderInfo.parameters.id + "').jPlayer";
			}
		}
		private function checkFlashVars(p:Object):void {
			for each (var s:String in p) {
				if(illegalChar(s)) {
					securityIssue = true;
				}
			}
		}
		private function init(e:TimerEvent):void {
			if(ExternalInterface.available && !securityIssue) {
				ExternalInterface.call(jQuery, "jPlayerFlashEvent");
			}
		}
	}
}
`

func parse(t *testing.T, name, code string) nir.Module {
	t.Helper()
	return parseModule([]byte(code), "/src/"+name, name)
}

// calls returns every Call in the module, flattened, so a test can ask whether one
// callee path was reached at all.
func calls(m nir.Module) []nir.Call {
	var out []nir.Call
	walkModule(m, func(e nir.Expr) {
		if c, ok := e.(nir.Call); ok {
			out = append(out, c)
		}
	}, nil)
	return out
}

func attrs(m nir.Module) []nir.Attr {
	var out []nir.Attr
	walkModule(m, func(e nir.Expr) {
		if a, ok := e.(nir.Attr); ok {
			out = append(out, a)
		}
	}, nil)
	return out
}

func stmts(m nir.Module) []nir.Stmt {
	var out []nir.Stmt
	walkModule(m, nil, func(s nir.Stmt) { out = append(out, s) })
	return out
}

func walkModule(m nir.Module, onExpr func(nir.Expr), onStmt func(nir.Stmt)) {
	var expr func(nir.Expr)
	var body func([]nir.Stmt)
	expr = func(e nir.Expr) {
		if e == nil {
			return
		}
		if onExpr != nil {
			onExpr(e)
		}
		switch x := e.(type) {
		case nir.Call:
			expr(x.Callee)
			for _, a := range x.Args {
				expr(a)
			}
		case nir.Attr:
			expr(x.Base)
		case nir.Index:
			expr(x.Base)
			expr(x.Key)
		case nir.Format:
			for _, p := range x.Parts {
				expr(p)
			}
		case nir.Seq:
			for _, p := range x.Parts {
				expr(p)
			}
		case nir.Pair:
			expr(x.Value)
		case nir.Thru:
			expr(x.Inner)
		case nir.BinOp:
			expr(x.Left)
			expr(x.Right)
		case nir.Unary:
			expr(x.Operand)
		case nir.Ternary:
			expr(x.Cond)
			expr(x.Then)
			expr(x.Else)
		case nir.Lambda:
			body(x.Body)
		}
	}
	body = func(sts []nir.Stmt) {
		for _, st := range sts {
			if onStmt != nil {
				onStmt(st)
			}
			switch s := st.(type) {
			case nir.ClassDef:
				body(s.Body)
			case nir.FuncDef:
				body(s.Body)
			case nir.Assign:
				expr(s.Value)
			case nir.AugAssign:
				expr(s.Value)
			case nir.ExprStmt:
				expr(s.Value)
			case nir.Return:
				expr(s.Value)
			case nir.Terminate:
				expr(s.Value)
			case nir.Block:
				body(s.Stmts)
			case nir.If:
				expr(s.Cond)
				body(s.Then)
				body(s.Else)
			case nir.Loop:
				expr(s.Cond)
				expr(s.Iter)
				body(s.Body)
			case nir.Switch:
				expr(s.Subject)
				for _, c := range s.Cases {
					body(c)
				}
				body(s.Default)
			case nir.Try:
				body(s.Body)
				for _, h := range s.Handlers {
					body(h)
				}
				body(s.Finally)
			}
		}
	}
	body(m.Body)
}

func hasCall(m nir.Module, path string) bool {
	for _, c := range calls(m) {
		if c.Path == path {
			return true
		}
	}
	return false
}

func hasAttr(m nir.Module, path string) bool {
	for _, a := range attrs(m) {
		if a.Path == path {
			return true
		}
	}
	return false
}

// The gap this frontend closes: a call in a Flash .as file has to be reachable as a
// labelable node, on both the source and the sink side of the flow.
func TestFlashVarsReadAndExternalInterfaceCallAreBothLabelable(t *testing.T) {
	m := parse(t, "Jplayer.as", jplayerShape)
	for _, path := range []string{"loaderInfo.parameters", "loaderInfo.parameters.jQuery", "loaderInfo.parameters.id"} {
		if !hasAttr(m, path) {
			t.Errorf("no Attr with path %q; the flash-vars read is not labelable as a source", path)
		}
	}
	for _, path := range []string{"ExternalInterface.call", "Security.allowDomain", "checkFlashVars"} {
		if !hasCall(m, path) {
			t.Errorf("no Call with path %q; the call is not labelable as a sink", path)
		}
	}
	for _, c := range calls(m) {
		if c.Path != "ExternalInterface.call" {
			continue
		}
		if c.Method != "call" {
			t.Errorf("ExternalInterface.call has method %q, want %q", c.Method, "call")
		}
		if len(c.Args) != 2 {
			t.Fatalf("ExternalInterface.call got %d args, want 2", len(c.Args))
		}
		if nm, ok := c.Args[0].(nir.Name); !ok || nm.ID != "jQuery" {
			t.Errorf("ExternalInterface.call arg0 = %#v, want the jQuery member reference", c.Args[0])
		}
	}
}

// The callback name is built by concatenation, which is the step the taint has to
// survive: a `+` chain lowers to a Format whose parts include the tainted read.
func TestStringConcatenationCarriesTheFlashVar(t *testing.T) {
	m := parse(t, "Jplayer.as", jplayerShape)
	var found bool
	for _, st := range stmts(m) {
		a, ok := st.(nir.Assign)
		if !ok || len(a.Targets) != 1 || a.Targets[0] != "jQuery" || a.Decl {
			continue
		}
		if _, ok := a.Value.(nir.Format); !ok {
			t.Fatalf("jQuery assigned %T, want a Format for the `+` chain", a.Value)
		}
		found = true
	}
	if !found {
		t.Fatal("no assignment of the built callback name to jQuery")
	}
}

// A member reference with no `this.` is how ActionScript is written, so the class has
// to declare what its members are for one to resolve.
func TestClassDeclaresItsMembersAndBase(t *testing.T) {
	m := parse(t, "Jplayer.as", jplayerShape)
	var cd nir.ClassDef
	for _, st := range stmts(m) {
		if c, ok := st.(nir.ClassDef); ok {
			cd = c
		}
	}
	if cd.Name != "Jplayer" {
		t.Fatalf("class name = %q, want Jplayer", cd.Name)
	}
	if len(cd.Bases) != 1 || cd.Bases[0] != "Sprite" {
		t.Errorf("bases = %v, want [Sprite]", cd.Bases)
	}
	want := map[string]bool{"jQuery": true, "securityIssue": true}
	got := map[string]bool{}
	for _, mem := range cd.Members {
		got[mem] = true
	}
	for mem := range want {
		if !got[mem] {
			t.Errorf("member %q missing from ClassDef.Members %v", mem, cd.Members)
		}
	}
}

// A module is keyed by its DECLARED package plus its own file name, because that is
// the name a sibling file's `import` writes.
func TestModuleKeyAndImportsComeFromTheSource(t *testing.T) {
	m := parse(t, "Jplayer.as", jplayerShape)
	if m.Key != "happyworm.jPlayer.Jplayer" {
		t.Errorf("module key = %q, want happyworm.jPlayer.Jplayer", m.Key)
	}
	want := map[string]string{
		"ExternalInterface": "flash.external.ExternalInterface",
		"Security":          "flash.system.Security",
	}
	got := map[string]string{}
	for _, im := range m.Imports {
		got[im.Local] = im.Module
	}
	for local, mod := range want {
		if got[local] != mod {
			t.Errorf("import %q = %q, want %q", local, got[local], mod)
		}
	}
}

// `for each (v in obj)` iterates VALUES, and it is the loop the flash-vars check runs;
// binding its variable is what lets a value read inside the body carry the taint.
func TestForEachBindsTheLoopVariableToTheIterable(t *testing.T) {
	m := parse(t, "Jplayer.as", jplayerShape)
	var loops []nir.Loop
	for _, st := range stmts(m) {
		if l, ok := st.(nir.Loop); ok {
			loops = append(loops, l)
		}
	}
	if len(loops) != 1 {
		t.Fatalf("got %d loops, want 1", len(loops))
	}
	if len(loops[0].Vars) != 1 || loops[0].Vars[0] != "s" {
		t.Errorf("loop vars = %v, want [s]", loops[0].Vars)
	}
	if nm, ok := loops[0].Iter.(nir.Name); !ok || nm.ID != "p" {
		t.Errorf("loop iterable = %#v, want the parameter p", loops[0].Iter)
	}
}

// A declared type on a parameter or a field is what receiver resolution keys on, and
// the `:T` annotation must not be mistaken for an expression.
func TestDeclaredTypesAreRecordedAndNotParsedAsExpressions(t *testing.T) {
	m := parse(t, "Jplayer.as", jplayerShape)
	sawParam, sawField := false, false
	for _, st := range stmts(m) {
		fn, ok := st.(nir.FuncDef)
		if !ok || fn.Name != "checkFlashVars" {
			continue
		}
		sawParam = true
		if len(fn.Params) != 1 || fn.Params[0] != "p" {
			t.Fatalf("checkFlashVars params = %v, want [p]", fn.Params)
		}
		if fn.ParamTypes["p"] != "Object" {
			t.Errorf("param p declared type = %q, want Object", fn.ParamTypes["p"])
		}
	}
	for _, st := range stmts(m) {
		a, ok := st.(nir.Assign)
		if !ok || !a.Decl || len(a.Targets) != 1 || a.Targets[0] != "jQuery" {
			continue
		}
		sawField = true
		if a.Type != "String" {
			t.Errorf("jQuery declared type = %q, want String", a.Type)
		}
	}
	if !sawParam || !sawField {
		t.Fatalf("declarations not found (param %v, field %v)", sawParam, sawField)
	}
}

// A member write is modelled as a Method-less path call, the shape the lowering reads
// as "this value was stored into that field".
func TestMemberWriteIsModelledAsAFieldWriteCall(t *testing.T) {
	m := parse(t, "Status.as", `package {
	public class Status {
		public function apply(v:String):void {
			myStatus.src = v;
			myStatus.list[0] = v;
			count += 1;
		}
	}
}
`)
	var writes []nir.Call
	for _, c := range calls(m) {
		if c.Method == "" {
			writes = append(writes, c)
		}
	}
	seen := map[string]bool{}
	for _, w := range writes {
		seen[w.Path] = true
		if len(w.Args) != 1 {
			t.Errorf("field write %q got %d args, want the assigned value only", w.Path, len(w.Args))
		}
	}
	if !seen["myStatus.src"] {
		t.Errorf("no field-write call for myStatus.src, got %v", seen)
	}
	if !seen["myStatus.list[]"] {
		t.Errorf("no field-write call for the indexed target, got %v", seen)
	}
	var augs int
	for _, st := range stmts(m) {
		if _, ok := st.(nir.AugAssign); ok {
			augs++
		}
	}
	if augs != 1 {
		t.Errorf("got %d AugAssign statements, want 1 for `count += 1`", augs)
	}
}

// ActionScript's own type operators: `as` is a cast and passes taint through, `is` is
// a predicate. Neither may swallow the expression it is written on.
func TestTypeOperators(t *testing.T) {
	m := parse(t, "E.as", `package {
	public class E {
		public function h(event:Object):void {
			if (event.error is Error) {
				var err:Error = event.error as Error;
				report(err);
			}
		}
	}
}
`)
	if !hasAttr(m, "event.error") {
		t.Error("the `event.error` read was lost")
	}
	if !hasCall(m, "report") {
		t.Error("the call after the cast was lost")
	}
	cast := false
	for _, st := range stmts(m) {
		a, ok := st.(nir.Assign)
		if !ok || !a.Decl || a.Targets[0] != "err" {
			continue
		}
		cast = true
		if _, ok := a.Value.(nir.Thru); !ok {
			t.Errorf("`x as T` lowered to %T, want a Thru so the cast is transparent to taint", a.Value)
		}
	}
	if !cast {
		t.Fatal("the `event.error as Error` declaration was not parsed")
	}
}

// A construct the parser has no rule for costs one statement, not the file. Anything
// else means one line of E4X or a truncated method hides every call below it.
func TestUnparsableConstructDoesNotLoseTheRestOfTheFile(t *testing.T) {
	m := parse(t, "Odd.as", `package {
	public class Odd {
		public function h():void {
			var doc:XML = <root><item id="1"/></root>;
			var ns:Namespace = my::weird ~~~ ;
			ExternalInterface.call("after");
		}
	}
}
`)
	if !hasCall(m, "ExternalInterface.call") {
		t.Error("the call after an unparsable statement was lost")
	}
}

// Metadata and attribute keywords decorate a declaration; neither may be read as the
// declaration itself.
func TestMetadataAndAttributesDecorateRatherThanReplace(t *testing.T) {
	m := parse(t, "Meta.as", `package {
	[Bindable]
	public dynamic class Meta {
		[Embed(source="a.png")]
		public static var icon:Class;
		override public final function go():void {
			doIt();
		}
	}
}
`)
	var cd nir.ClassDef
	var fn nir.FuncDef
	for _, st := range stmts(m) {
		switch s := st.(type) {
		case nir.ClassDef:
			cd = s
		case nir.FuncDef:
			fn = s
		}
	}
	if cd.Name != "Meta" || len(cd.Annotations) != 1 || cd.Annotations[0] != "Bindable" {
		t.Errorf("class = %q annotations %v, want Meta [Bindable]", cd.Name, cd.Annotations)
	}
	if fn.Name != "go" || !fn.Exported {
		t.Errorf("function = %q exported=%v, want go exported", fn.Name, fn.Exported)
	}
	if !hasCall(m, "doIt") {
		t.Error("the body of a function behind attribute keywords was lost")
	}
}

// A function carries its own text as syntax-level evidence, which is how a binding
// reaches a defect whose shape is the statement rather than the API.
func TestFunctionContextCarriesItsOwnText(t *testing.T) {
	m := parse(t, "Jplayer.as", jplayerShape)
	for _, st := range stmts(m) {
		fn, ok := st.(nir.FuncDef)
		if !ok || fn.Name != "init" {
			continue
		}
		joined := strings.Join(fn.ContextTokens, "\n")
		if !strings.Contains(joined, "lang=actionscript") {
			t.Error("function context does not name the language")
		}
		if !strings.Contains(joined, "ExternalInterface.call(jQuery") {
			t.Errorf("function context does not carry the body text: %q", joined)
		}
		return
	}
	t.Fatal("no FuncDef named init")
}

// Comments, string literals and regular expressions must not be mistaken for code.
func TestLexerSkipsCommentsAndKeepsLiteralsWhole(t *testing.T) {
	m := parse(t, "Lex.as", `package {
	public class Lex {
		// ExternalInterface.call("in a line comment");
		/* ExternalInterface.call("in a block comment"); */
		public function h(a:Number, b:Number):void {
			var s:String = "ExternalInterface.call(not a call)";
			var re:RegExp = /a\/b[/]c/g;
			var q:Number = a / b;
			sink(s, re, q);
		}
	}
}
`)
	if hasCall(m, "ExternalInterface.call") {
		t.Error("a call written inside a comment or a string literal was parsed as code")
	}
	if !hasCall(m, "sink") {
		t.Error("the call after a regex literal and a division was lost")
	}
	var lit string
	for _, st := range stmts(m) {
		if a, ok := st.(nir.Assign); ok && a.Decl && a.Targets[0] == "s" {
			if c, ok := a.Value.(nir.Const); ok {
				lit = c.Value
			}
		}
	}
	if lit != "ExternalInterface.call(not a call)" {
		t.Errorf("string literal value = %q, want the unquoted text", lit)
	}
}

// The line a node reports is the line a reviewer opens, so it has to survive the
// comments and multi-line constructs above it.
func TestLocationsAreTheSourceLines(t *testing.T) {
	m := parse(t, "Loc.as", "package {\n\t// one\n\t/* two\n\t   three */\n\tpublic class Loc {\n\t\tpublic function h():void {\n\t\t\tsink(\"x\");\n\t\t}\n\t}\n}\n")
	for _, c := range calls(m) {
		if c.Path == "sink" && c.Loc != "Loc.as:7" {
			t.Errorf("sink call loc = %q, want Loc.as:7", c.Loc)
		}
	}
}

// AS2-era files declare a class with no package block at all; they still have to parse.
func TestPackagelessClassStillParses(t *testing.T) {
	m := parse(t, "Legacy.as", `class Legacy {
	function Legacy() {
		ExternalInterface.call(_root.cb);
	}
}
`)
	if m.Key != "Legacy" {
		t.Errorf("module key = %q, want Legacy", m.Key)
	}
	if !hasCall(m, "ExternalInterface.call") {
		t.Error("a class outside a package block yielded no calls")
	}
}

// A scanner reads whatever is on disk, including a file that is only NAMED .as. The
// frontend has to answer with a truncated parse rather than a hang, a panic or a
// blown stack, because one such file would otherwise take the whole scan with it.
func TestArbitraryInputTerminatesWithoutPanicking(t *testing.T) {
	alphabet := []byte("{}()[];,.:=+-*/<>\"'\\\n\tabcXYZ019 package class function var import for each new as is return if else switch case try catch/*\xff")
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 500; i++ {
		b := make([]byte, r.Intn(3000))
		for j := range b {
			b[j] = alphabet[r.Intn(len(alphabet))]
		}
		parseModule(b, "/src/R.as", "R.as")
	}
	nested := make([]byte, 20000)
	for i := range nested {
		nested[i] = '('
	}
	parseModule(nested, "/src/Nested.as", "Nested.as")

	unary := append([]byte("var x = "), make([]byte, 20000)...)
	for i := len("var x = "); i < len(unary); i++ {
		unary[i] = '-'
	}
	parseModule(append(unary, '1', ';'), "/src/Unary.as", "Unary.as")
}
