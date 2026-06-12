package treesitter_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/extract/nir"
	"github.com/vyprai/vyql/usg"
)

// TestFrontendCapabilityMatrix probes every frontend with security-critical snippets and
// reports, per (language × capability), whether the frontend produces the expected graph
// evidence. java/python/javascript are the reference (most complete). Run with:
//   go test ./extract/frontend/treesitter -run TestFrontendCapabilityMatrix -v
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
	hasFormat := func(g usg.Store) bool { ns, _ := g.NodesOfType("code.Format"); return len(ns) > 0 }
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
			for _, n := range all {
				p := n.Prop("callee_path") + " " + n.Prop("loc")
				if strings.Contains(p, srcSub) || strings.Contains(n.Prop("method"), srcSub) {
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
		{"call(method)", hasCall("exec"), map[string]string{
			"java":   "class T { void r(String p){ db.exec(p); } }",
			"python": "def r(p):\n    db.exec(p)",
			"javascript": "function r(p){ db.exec(p); }",
			"csharp": "class T { void R(string p){ db.exec(p); } }",
			"php":    "<?php function r($p){ $db->exec($p); }",
			"ruby":   "def r(p)\n  db.exec(p)\nend",
			"rust":   "fn r(p: &str){ db.exec(p); }",
			"kotlin": "fun r(p: String){ db.exec(p) }",
			"scala":  "object T { def r(p: String): Unit = { db.exec(p) } }",
			"swift":  "func r(p: String){ db.exec(p) }",
			"dart":   "void r(String p){ db.exec(p); }",
			"groovy": "void r(p){ db.exec(p) }",
			"elixir": "defmodule T do\n  def r(p), do: Db.exec(p)\nend",
			"lua":    "function r(p)\n  db.exec(p)\nend",
			"perl":   "sub r { my $p=shift; $db->exec($p); }",
			"c":      "void r(char* p){ exec(p); }",
			"cpp":    "void r(char* p){ db.exec(p); }",
			"objc":   "void r(NSString* p){ [db exec:p]; }",
		}},
		{"concat→Format", hasFormat, map[string]string{
			"java":   `class T { void r(String p){ String q = "a" + p; sink(q); } }`,
			"python": "def r(p):\n    q = 'a' + p\n    sink(q)",
			"javascript": `function r(p){ var q = "a" + p; sink(q); }`,
			"csharp": `class T { void R(string p){ var q = "a" + p; sink(q); } }`,
			"php":    `<?php function r($p){ $q = "a" . $p; sink($q); }`,
			"ruby":   "def r(p)\n  q = 'a' + p\n  sink(q)\nend",
			"rust":   `fn r(p: &str){ let q = format!("a{}", p); sink(q); }`,
			"kotlin": `fun r(p: String){ val q = "a" + p; sink(q) }`,
			"scala":  `object T { def r(p: String): Unit = { val q = "a" + p; sink(q) } }`,
			"swift":  `func r(p: String){ let q = "a" + p; sink(q) }`,
			"dart":   `void r(String p){ var q = "a" + p; sink(q); }`,
			"groovy": `void r(p){ def q = "a" + p; sink(q) }`,
			"elixir": "defmodule T do\n  def r(p), do: sink(\"a\" <> p)\nend",
			"lua":    "function r(p)\n  local q = 'a' .. p\n  sink(q)\nend",
			"perl":   `sub r { my $p=shift; my $q = "a" . $p; sink($q); }`,
			"c":      `void r(char* p){ char* q = strcat("a", p); sink(q); }`,
			"cpp":    `void r(std::string p){ auto q = "a" + p; sink(q); }`,
			"objc":   `void r(NSString* p){ NSString* q = [@"a" stringByAppendingString:p]; sink(q); }`,
		}},
		{"new T(x)→Call", hasCall("File"), map[string]string{
			"java":   `class T { void r(String p){ new File(p); } }`,
			"javascript": `function r(p){ new File(p); }`,
			"csharp": `class T { void R(string p){ new File(p); } }`,
			"rust":   "", // no `new`
			"kotlin": `fun r(p: String){ File(p) }`,
			"scala":  `object T { def r(p: String): Unit = { new File(p) } }`,
			"swift":  `func r(p: String){ File(p) }`,
			"dart":   `void r(String p){ new File(p); }`,
			"groovy": `void r(p){ new File(p) }`,
			"cpp":    `void r(char* p){ File f(p); }`,
		}},
		{"member/subscript write", func(g usg.Store) bool {
			// the assignment value is captured in a write node (a code.Call with an incoming
			// FLOWS edge) — how JS path-sink-writes and python __setitem__ both model it.
			cs, _ := g.NodesOfType("code.Call")
			for _, id := range cs {
				if es, _ := g.InEdges(id, "FLOWS"); len(es) > 0 {
					return true
				}
			}
			return false
		}, map[string]string{
			"java":   `class T { void r(String p){ obj.role = p; } }`,
			"python": "def r(p):\n    s = {}\n    s['role'] = p",
			"javascript": `function r(p){ obj.role = p; }`,
			"csharp": `class T { void R(string p){ obj.role = p; } }`,
			"php":    `<?php function r($p){ $obj->role = $p; }`,
			"ruby":   "def r(p)\n  obj.role = p\nend",
			"kotlin": `fun r(p: String){ obj.role = p }`,
			"scala":  `object T { def r(p: String): Unit = { obj.role = p } }`,
		}},
		{"bool literal token", hasStrArg("false"), map[string]string{
			"java":   `class T { void r(){ c.setSecure(false); } }`,
			"python": "def r():\n    c.set_cookie('x', secure=False)",
			"javascript": `function r(){ c.setSecure(false); }`,
			"csharp": `class T { void R(){ c.SetSecure(false); } }`,
			"php":    `<?php function r(){ setcookie('x', 'v', false); }`,
			"ruby":   "def r()\n  set_cookie('x', secure: false)\nend",
			"kotlin": `fun r(){ c.setSecure(false) }`,
			"scala":  `object T { def r(): Unit = { c.setSecure(false) } }`,
			"swift":  `func r(){ c.setSecure(false) }`,
			"dart":   `void r(){ c.setSecure(false); }`,
			"groovy": `void r(){ c.setSecure(false) }`,
		}},
		{"interproc src→sink", flowToSink("p", "sink"), map[string]string{
			"java":   `class T { String wrap(String p){ return p; } void r(String p){ sink(wrap(p)); } }`,
			"python": "def wrap(p):\n    return p\ndef r(p):\n    sink(wrap(p))",
			"javascript": `function wrap(p){ return p; } function r(p){ sink(wrap(p)); }`,
			"csharp": `class T { string wrap(string p){ return p; } void R(string p){ sink(wrap(p)); } }`,
			"php":    `<?php function wrap($p){ return $p; } function r($p){ sink(wrap($p)); }`,
			"ruby":   "def wrap(p)\n  p\nend\ndef r(p)\n  sink(wrap(p))\nend",
			"kotlin": `fun wrap(p: String): String { return p }` + "\n" + `fun r(p: String){ sink(wrap(p)) }`,
			"scala":  `object T { def wrap(p: String): String = p; def r(p: String): Unit = { sink(wrap(p)) } }`,
			"go":     "",
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
			"java":   `class T { void r(String p){ if (p.length() > 0) { sink(p); } } }`,
			"python": "def r(p):\n    if len(p) > 0:\n        sink(p)",
			"javascript": `function r(p){ if (p.length > 0) { sink(p); } }`,
			"csharp": `class T { void R(string p){ if (p.Length > 0) { sink(p); } } }`,
			"php":    `<?php function r($p){ if (strlen($p) > 0) { sink($p); } }`,
			"ruby":   "def r(p)\n  if p.length > 0\n    sink(p)\n  end\nend",
			"kotlin": `fun r(p: String){ if (p.length > 0) { sink(p) } }`,
			"scala":  `object T { def r(p: String): Unit = { if (p.length > 0) { sink(p) } } }`,
			"swift":  `func r(p: String){ if p.count > 0 { sink(p) } }`,
			"dart":   `void r(String p){ if (p.length > 0) { sink(p); } }`,
		}},
		{"index read a[k]", hasNodeType("code.Index"), map[string]string{
			"java":   `class T { void r(String[] a){ sink(a[0]); } }`,
			"python": "def r(a):\n    sink(a[0])",
			"javascript": `function r(a){ sink(a[0]); }`,
			"php":    `<?php function r($a){ sink($a[0]); }`,
			"ruby":   "def r(a)\n  sink(a[0])\nend",
			"kotlin": `fun r(a: List<String>){ sink(a[0]) }`,
			"scala":  `object T { def r(a: Array[String]): Unit = { sink(a(0)) } }`,
		}},
		{"chain a().b(x)", hasCall("exec"), map[string]string{
			"java":   `class T { void r(String p){ Runtime.getRuntime().exec(p); } }`,
			"javascript": `function r(p){ obj.get().exec(p); }`,
			"kotlin": `fun r(p: String){ Runtime.getRuntime().exec(p) }`,
			"scala":  `object T { def r(p: String): Unit = { Runtime.getRuntime().exec(p) } }`,
			"groovy": `void r(p){ Runtime.getRuntime().exec(p) }`,
			"swift":  `func r(p: String){ obj.get().exec(p) }`,
			"dart":   `void r(String p){ obj.get().exec(p); }`,
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

func pad(s, col string) string {
	for len(s) < len(col) {
		s += " "
	}
	return s
}
