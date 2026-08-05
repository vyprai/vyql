package treesitter_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// TestFrontendCapabilityMatrix probes every frontend with small syntax-flow snippets and
// reports, per (language × capability), whether the frontend produces the expected graph
// evidence. java/python/javascript are the reference (most complete). Run with:
//
//	go test ./extract/frontend/treesitter -run TestFrontendCapabilityMatrix -v
func TestFrontendCapabilityMatrix(t *testing.T) {
	type lang struct {
		name    string
		ext     string
		extract func([]string, string) (nir.Program, error)
	}
	langs := []lang{
		{"java", "java", treesitter.ExtractJava},
		{"python", "py", treesitter.ExtractPython},
		{"javascript", "js", treesitter.ExtractJavaScript},
		{"csharp", "cs", treesitter.ExtractCSharp},
		{"php", "php", treesitter.ExtractPHP},
		{"ruby", "rb", treesitter.ExtractRuby},
		{"rust", "rs", treesitter.ExtractRust},
		{"kotlin", "kt", treesitter.ExtractKotlin},
		{"scala", "scala", treesitter.ExtractScala},
		{"swift", "swift", treesitter.ExtractSwift},
		{"dart", "dart", treesitter.ExtractDart},
		{"groovy", "groovy", treesitter.ExtractGroovy},
		{"elixir", "ex", treesitter.ExtractElixir},
		{"lua", "lua", treesitter.ExtractLua},
		{"perl", "pl", treesitter.ExtractPerl},
		{"c", "c", treesitter.ExtractC},
		{"cpp", "cpp", treesitter.ExtractCPP},
		{"objc", "m", treesitter.ExtractObjC},
	}

	// Each capability: a per-language snippet + a predicate over the lowered graph. A snippet
	// of "" means "not applicable / not yet authored" → reported as "-".
	type cap struct {
		name  string
		check func(usg.Store) bool
		snip  map[string]string
	}

	// graph predicates --------------------------------------------------------------------
	hasCall := func(method string) func(usg.Store) bool {
		return func(g usg.Store) bool {
			ns, _ := g.NodesOfType("code.Call")
			for _, id := range ns {
				n, _, _ := g.GetNode(id)
				if strings.Contains(n.Prop("callee_path"), method) || n.Prop("method") == method {
					return true
				}
			}
			return false
		}
	}
	_ = func(g usg.Store) bool { ns, _ := g.NodesOfType("code.Format"); return len(ns) > 0 }
	hasStrArg := func(tok string) func(usg.Store) bool {
		lt := strings.ToLower(tok)
		return func(g usg.Store) bool {
			ns, _ := g.NodesOfType("code.Call")
			for _, id := range ns {
				n, _, _ := g.GetNode(id)
				if strings.Contains(strings.ToLower(n.Prop("str_args")), lt) {
					return true
				}
			}
			return false
		}
	}
	// hasNodeType: the frontend emits at least one node of the given USG type.
	hasNodeType := func(typ string) func(usg.Store) bool {
		return func(g usg.Store) bool { ns, _ := g.NodesOfType(typ); return len(ns) > 0 }
	}
	// flowReaches: a source-ish read flows (FLOWS*) into a sink-ish call's arg.
	flowToSink := func(srcSub, sinkMethod string) func(usg.Store) bool {
		return func(g usg.Store) bool {
			all, _ := g.AllNodes()
			var srcs, sinks []string
			// the tainted input is the function parameter (every probe snippet takes `p`/`a`):
			// start from code.Param nodes (reliable) plus any node naming srcSub.
			params, _ := g.NodesOfType("code.Param")
			srcs = append(srcs, params...)
			for _, n := range all {
				path := n.Prop("callee_path") + " " + n.Prop("loc")
				if strings.Contains(path, srcSub) || strings.Contains(n.Prop("method"), srcSub) {
					srcs = append(srcs, n.ID)
				}
				if n.Prop("method") == sinkMethod || strings.Contains(n.Prop("callee_path"), sinkMethod) {
					sinks = append(sinks, n.ID)
				}
			}
			sink := map[string]bool{}
			for _, s := range sinks {
				sink[s] = true
			}
			for _, s := range srcs {
				seen := map[string]bool{s: true}
				q := []string{s}
				for len(q) > 0 {
					cur := q[0]
					q = q[1:]
					if sink[cur] {
						return true
					}
					es, _ := g.OutEdges(cur, "FLOWS")
					for _, e := range es {
						if !seen[e.Dst] {
							seen[e.Dst] = true
							q = append(q, e.Dst)
						}
					}
				}
			}
			return false
		}
	}

	caps := []cap{
		{"call(method)", hasCall("doit"), map[string]string{
			"java":       "class T { void r(String p){ db.doit(p); } }",
			"python":     "def r(p):\n    db.doit(p)",
			"javascript": "function r(p){ db.doit(p); }",
			"csharp":     "class T { void R(string p){ db.doit(p); } }",
			"php":        "<?php function r($p){ $db->doit($p); }",
			"ruby":       "def r(p)\n  db.doit(p)\nend",
			"rust":       "fn r(p: &str){ db.doit(p); }",
			"kotlin":     "fun r(p: String){ db.doit(p) }",
			"scala":      "object T { def r(p: String): Unit = { db.doit(p) } }",
			"swift":      "func r(p: String){ db.doit(p) }",
			"dart":       "void r(String p){ db.doit(p); }",
			"groovy":     "void r(p){ db.doit(p) }",
			"elixir":     "defmodule T do\n  def r(p), do: Db.doit(p)\nend",
			"lua":        "function r(p)\n  db.doit(p)\nend",
			"perl":       "sub r { my $p=shift; $db->doit($p); }",
			"c":          "void r(char* p){ doit(p); }",
			"cpp":        "void r(char* p){ db.doit(p); }",
			"objc":       "void r(NSString* p){ [db doit:p]; }",
		}},
		{"concat taint", flowToSink("p", "sink"), map[string]string{
			"java":       `class T { void r(String p){ String q = "a" + p; sink(q); } }`,
			"python":     "def r(p):\n    q = 'a' + p\n    sink(q)",
			"javascript": `function r(p){ var q = "a" + p; sink(q); }`,
			"csharp":     `class T { void R(string p){ var q = "a" + p; sink(q); } }`,
			"php":        `<?php function r($p){ $q = "a" . $p; sink($q); }`,
			"ruby":       "def r(p)\n  q = 'a' + p\n  sink(q)\nend",
			"rust":       `fn r(p: &str){ let q = format!("a{}", p); sink(q); }`,
			"kotlin":     `fun r(p: String){ val q = "a" + p; sink(q) }`,
			"scala":      `object T { def r(p: String): Unit = { val q = "a" + p; sink(q) } }`,
			"swift":      `func r(p: String){ let q = "a" + p; sink(q) }`,
			"dart":       `void r(String p){ var q = "a" + p; sink(q); }`,
			"groovy":     `void r(p){ def q = "a" + p; sink(q) }`,
			"elixir":     "defmodule T do\n  def r(p), do: sink(\"a\" <> p)\nend",
			"lua":        "function r(p)\n  local q = 'a' .. p\n  sink(q)\nend",
			"perl":       `sub r { my $p=shift; my $q = "a" . $p; sink($q); }`,
			"c":          `void r(char* p){ char* q = join("a", p); sink(q); }`,
			"cpp":        `void r(std::string p){ auto q = "a" + p; sink(q); }`,
			"objc":       `void r(NSString* p){ NSString* q = [@"a" stringByAppendingString:p]; sink(q); }`,
		}},
		{"splat arg taint", flowToSink("p", "sink"), map[string]string{
			"python": "def r(p):\n    sink(*p)",
		}},
		{"vararg splat taint", flowToSink("args", "sink"), map[string]string{
			"python": "def r(*args):\n    sink(*args)",
		}},
		{"new T(x)→Call", hasCall("File"), map[string]string{
			"java":       `class T { void r(String p){ new File(p); } }`,
			"javascript": `function r(p){ new File(p); }`,
			"csharp":     `class T { void R(string p){ new File(p); } }`,
			"rust":       "", // no `new`
			"kotlin":     `fun r(p: String){ File(p) }`,
			"scala":      `object T { def r(p: String): Unit = { new File(p) } }`,
			"swift":      `func r(p: String){ File(p) }`,
			"dart":       `void r(String p){ new File(p); }`,
			"groovy":     `void r(p){ new File(p) }`,
			"cpp":        `void r(char* p){ File f(p); }`,
		}},
		{"member/subscript write", func(g usg.Store) bool {
			// the assignment value is captured in a write node (a code.Call with an incoming
			// FLOWS edge) — how JS path-based writes and python __setitem__ both model it.
			cs, _ := g.NodesOfType("code.Call")
			for _, id := range cs {
				if es, _ := g.InEdges(id, "FLOWS"); len(es) > 0 {
					return true
				}
			}
			return false
		}, map[string]string{
			"java":       `class T { void r(String p){ obj.value = p; } }`,
			"python":     "def r(p):\n    s = {}\n    s['value'] = p",
			"javascript": `function r(p){ obj.value = p; }`,
			"csharp":     `class T { void R(string p){ obj.value = p; } }`,
			"php":        `<?php function r($p){ $obj->value = $p; }`,
			"ruby":       "def r(p)\n  obj.value = p\nend",
			"kotlin":     `fun r(p: String){ obj.value = p }`,
			"scala":      `object T { def r(p: String): Unit = { obj.value = p } }`,
		}},
		{"bool literal token", hasStrArg("false"), map[string]string{
			"java":       `class T { void r(){ c.setEnabled(false); } }`,
			"python":     "def r():\n    c.configure(enabled=False)",
			"javascript": `function r(){ c.setEnabled(false); }`,
			"csharp":     `class T { void R(){ c.SetEnabled(false); } }`,
			"php":        `<?php function r(){ configure('mode', false); }`,
			"ruby":       "def r()\n  configure(enabled: false)\nend",
			"kotlin":     `fun r(){ c.setEnabled(false) }`,
			"scala":      `object T { def r(): Unit = { c.setEnabled(false) } }`,
			"swift":      `func r(){ c.setEnabled(false) }`,
			"dart":       `void r(){ c.setEnabled(false); }`,
			"groovy":     `void r(){ c.setEnabled(false) }`,
		}},
		{"interproc src→sink", flowToSink("p", "sink"), map[string]string{
			"java":       `class T { String wrap(String p){ return p; } void r(String p){ sink(wrap(p)); } }`,
			"python":     "def wrap(p):\n    return p\ndef r(p):\n    sink(wrap(p))",
			"javascript": `function wrap(p){ return p; } function r(p){ sink(wrap(p)); }`,
			"csharp":     `class T { string wrap(string p){ return p; } void R(string p){ sink(wrap(p)); } }`,
			"php":        `<?php function wrap($p){ return $p; } function r($p){ sink(wrap($p)); }`,
			"ruby":       "def wrap(p)\n  p\nend\ndef r(p)\n  sink(wrap(p))\nend",
			"kotlin":     `fun wrap(p: String): String { return p }` + "\n" + `fun r(p: String){ sink(wrap(p)) }`,
			"scala":      `object T { def wrap(p: String): String = p; def r(p: String): Unit = { sink(wrap(p)) } }`,
			"go":         "",
		}},
		{"if→CFG region", func(g usg.Store) bool {
			all, _ := g.AllNodes()
			for _, n := range all {
				if strings.Contains(n.Prop("region"), "if") {
					return true
				}
			}
			return false
		}, map[string]string{
			"java":       `class T { void r(String p){ if (p.length() > 0) { sink(p); } } }`,
			"python":     "def r(p):\n    if len(p) > 0:\n        sink(p)",
			"javascript": `function r(p){ if (p.length > 0) { sink(p); } }`,
			"csharp":     `class T { void R(string p){ if (p.Length > 0) { sink(p); } } }`,
			"php":        `<?php function r($p){ if (strlen($p) > 0) { sink($p); } }`,
			"ruby":       "def r(p)\n  if p.length > 0\n    sink(p)\n  end\nend",
			"kotlin":     `fun r(p: String){ if (p.length > 0) { sink(p) } }`,
			"scala":      `object T { def r(p: String): Unit = { if (p.length > 0) { sink(p) } } }`,
			"swift":      `func r(p: String){ if p.count > 0 { sink(p) } }`,
			"dart":       `void r(String p){ if (p.length > 0) { sink(p); } }`,
		}},
		{"index read a[k]", hasNodeType("code.Index"), map[string]string{
			"java":       `class T { void r(String[] a){ sink(a[0]); } }`,
			"python":     "def r(a):\n    sink(a[0])",
			"javascript": `function r(a){ sink(a[0]); }`,
			"php":        `<?php function r($a){ sink($a[0]); }`,
			"ruby":       "def r(a)\n  sink(a[0])\nend",
			"kotlin":     `fun r(a: List<String>){ sink(a[0]) }`,
			"scala":      `object T { def r(a: Array[String]): Unit = { sink(a(0)) } }`,
		}},
		{"lambda/closure", hasNodeType("code.Func"), map[string]string{
			"java":       `class T { void r(){ run(() -> sink(1)); } }`,
			"python":     "def r():\n    run(lambda: sink(1))",
			"javascript": `function r(){ run(() => sink(1)); }`,
			"csharp":     `class T { void R(){ run(() => sink(1)); } }`,
			"php":        `<?php function r(){ run(function(){ sink(1); }); }`,
			"ruby":       "def r()\n  run { sink(1) }\nend",
			"kotlin":     `fun r(){ run { sink(1) } }`,
			"scala":      `object T { def r(): Unit = { run(() => sink(1)) } }`,
			"swift":      `func r(){ run({ sink(1) }) }`,
			"dart":       `void r(){ run(() => sink(1)); }`,
		}},
		{"ternary→Phi", hasNodeType("code.Phi"), map[string]string{
			"java":       `class T { String r(String p){ return p != null ? p : "x"; } }`,
			"python":     "def r(p):\n    return p if p else 'x'",
			"javascript": `function r(p){ return p ? p : "x"; }`,
			"csharp":     `class T { string R(string p){ return p != null ? p : "x"; } }`,
			"php":        `<?php function r($p){ return $p ? $p : "x"; }`,
			"ruby":       "def r(p)\n  p ? p : 'x'\nend",
			"kotlin":     `fun r(p: String): String { return if (p.isEmpty()) "x" else p }`,
			"scala":      `object T { def r(p: String): String = if (p.isEmpty) "x" else p }`,
		}},
		{"field-sensitivity", flowToSink("p", "sink"), map[string]string{
			"java":       `class T { void r(String p){ o.f = p; sink(o.f); } }`,
			"python":     "def r(p):\n    o.f = p\n    sink(o.f)",
			"javascript": `function r(p){ var o = {}; o.f = p; sink(o.f); }`,
			"csharp":     `class T { void R(string p){ o.f = p; sink(o.f); } }`,
			"php":        `<?php function r($p){ $o->f = $p; sink($o->f); }`,
			"ruby":       "def r(p)\n  o.f = p\n  sink(o.f)\nend",
			"kotlin":     `fun r(p: String){ o.f = p; sink(o.f) }`,
		}},
		{"callback taint flow", flowToSink("a", "sink"), map[string]string{
			"javascript": `function r(a){ a.forEach(function(v){ sink(v); }); }`,
			"python":     "def r(a):\n    for v in a:\n        sink(v)",
			"java":       `class T { void r(java.util.List a){ a.forEach(v -> sink(v)); } }`,
			"kotlin":     `fun r(a: List<String>){ a.forEach { sink(it) } }`,
			"ruby":       "def r(a)\n  a.each { |v| sink(v) }\nend",
		}},
		{"regex char-filter", func(g usg.Store) bool {
			ns, _ := g.NodesOfType("code.Call")
			for _, id := range ns {
				n, _, _ := g.GetNode(id)
				if (n.Prop("method") == "replace" || strings.Contains(n.Prop("callee_path"), "sub")) && strings.Contains(n.Prop("lit0"), "<") {
					return true
				}
			}
			return false
		}, map[string]string{
			"javascript": `function r(p){ return p.replace(/[<>]/g, ""); }`,
			"python":     "def r(p):\n    return re.sub('[<>]', '', p)",
			"ruby":       "def r(p)\n  p.gsub(/[<>]/, '')\nend",
			"java":       `class T { String r(String p){ return p.replaceAll("[<>]", ""); } }`,
		}},
		{"chain a().b(x)", hasCall("doit"), map[string]string{
			"java":       `class T { void r(String p){ Factory.get().doit(p); } }`,
			"javascript": `function r(p){ obj.get().doit(p); }`,
			"kotlin":     `fun r(p: String){ Factory.get().doit(p) }`,
			"scala":      `object T { def r(p: String): Unit = { Factory.get().doit(p) } }`,
			"groovy":     `void r(p){ Factory.get().doit(p) }`,
			"swift":      `func r(p: String){ obj.get().doit(p) }`,
			"dart":       `void r(String p){ obj.get().doit(p); }`,
		}},
	}

	dir := t.TempDir()
	// header
	var capNames []string
	for _, c := range caps {
		capNames = append(capNames, c.name)
	}
	fmt.Printf("\n%-12s | %s\n", "language", strings.Join(capNames, " | "))
	for _, lg := range langs {
		cells := make([]string, len(caps))
		for i, c := range caps {
			src, ok := c.snip[lg.name]
			if !ok || src == "" {
				cells[i] = pad("-", c.name)
				continue
			}
			p := filepath.Join(dir, lg.name+"_"+fmt.Sprint(i)+"."+lg.ext)
			os.WriteFile(p, []byte(src), 0o644)
			prog, err := lg.extract([]string{p}, dir)
			if err != nil {
				cells[i] = pad("ERR", c.name)
				continue
			}
			g, err := lowering.Lower(prog, false)
			if err != nil || g == nil {
				cells[i] = pad("ERR", c.name)
				continue
			}
			if c.check(g) {
				cells[i] = pad("OK", c.name)
			} else {
				cells[i] = pad("MISS", c.name)
			}
		}
		fmt.Printf("%-12s | %s\n", lg.name, strings.Join(cells, " | "))
	}

	// gap summary
	fmt.Println("\n== GAPS (MISS, excluding N/A) ==")
	_ = sort.Strings
}

func TestPythonClassBasesAreRecorded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.py")
	if err := os.WriteFile(path, []byte("class Child(Base):\n    pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPython([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, mod := range prog.Modules {
		for _, st := range mod.Body {
			if cls, ok := st.(nir.ClassDef); ok && cls.Name == "Child" {
				if len(cls.Bases) != 1 || cls.Bases[0] != "Base" {
					t.Fatalf("Child bases = %#v, want [Base]", cls.Bases)
				}
				return
			}
		}
	}
	t.Fatal("Child class not found")
}

func TestJavaScriptIIFELowersBody(t *testing.T) {
	cases := map[string]string{
		"postfix_call": `(function($) {
  $(document).on('nested:fieldAdded', 'form', function(content) {
    nav.append('<li>' + content.field.children('.object-infos').data('object-label') + '</li>');
  });
})(jQuery);`,
		"paren_call": `(function($) {
  $(document).on('nested:fieldAdded', 'form', function(content) {
    nav.append('<li>' + content.field.children('.object-infos').data('object-label') + '</li>');
  });
}(jQuery));`,
		"unary_plus_call": `+function($) {
  $(document).on('nested:fieldAdded', 'form', function(content) {
    nav.append('<li>' + content.field.children('.object-infos').data('object-label') + '</li>');
  });
}(jQuery);`,
	}
	for name, code := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "wrapped.js")
			if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
				t.Fatal(err)
			}
			prog, err := treesitter.ExtractJavaScript([]string{src}, dir)
			if err != nil {
				t.Fatal(err)
			}
			g, err := lowering.Lower(prog, true)
			if err != nil {
				t.Fatal(err)
			}
			if !func() bool {
				nodes, _ := g.AllNodes()
				for _, n := range nodes {
					if n.Prop("method") == "append" && strings.Contains(n.Prop("callee_path"), "nav.append") {
						return true
					}
				}
				return false
			}() {
				t.Fatalf("expected jQuery IIFE body to be lowered through nav.append")
			}
		})
	}
}

func pad(s, col string) string {
	for len(s) < len(col) {
		s += " "
	}
	return s
}
