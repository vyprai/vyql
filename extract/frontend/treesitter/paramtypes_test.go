package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	gofrontend "github.com/vyprai/vyql/extract/frontend/golang"
	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/nir"
)

func TestFrontendsExtractDeclaredParameterTypes(t *testing.T) {
	type extractor func([]string, string) (nir.Program, error)
	cases := []struct {
		name    string
		ext     string
		src     string
		extract extractor
		fn      string
		param   string
		want    string
	}{
		{
			name:    "c",
			ext:     "c",
			src:     `typedef struct Widget Widget; void h(Widget *incoming) {}`,
			extract: treesitter.ExtractC,
			fn:      "h",
			param:   "incoming",
			want:    "Widget",
		},
		{
			name:    "cpp",
			ext:     "cpp",
			src:     `class Widget { public: void value(); }; void h(Widget& incoming) { incoming.value(); }`,
			extract: treesitter.ExtractCPP,
			fn:      "h",
			param:   "incoming",
			want:    "Widget",
		},
		{
			name:    "csharp",
			ext:     "cs",
			src:     `class T { void H(Widget incoming) { var q = incoming.Value; } }`,
			extract: treesitter.ExtractCSharp,
			fn:      "H",
			param:   "incoming",
			want:    "Widget",
		},
		{
			name:    "dart",
			ext:     "dart",
			src:     `void h(Widget incoming) { incoming.value; }`,
			extract: treesitter.ExtractDart,
			fn:      "h",
			param:   "incoming",
			want:    "Widget",
		},
		{
			name:    "go",
			ext:     "go",
			src:     `package app; type Widget struct{}; func h(incoming *Widget) { incoming.Read("x") }`,
			extract: gofrontend.Extract,
			fn:      "h",
			param:   "incoming",
			want:    "Widget",
		},
		{
			name:    "groovy",
			ext:     "groovy",
			src:     `def h(Widget incoming) { incoming.read("x") }`,
			extract: treesitter.ExtractGroovy,
			fn:      "h",
			param:   "incoming",
			want:    "Widget",
		},
		{
			name:    "java",
			ext:     "java",
			src:     `class T { void h(Widget incoming) { incoming.read("x"); } }`,
			extract: treesitter.ExtractJava,
			fn:      "h",
			param:   "incoming",
			want:    "Widget",
		},
		{
			name:    "javascript-typescript",
			ext:     "js",
			src:     `function h(incoming: Widget) { incoming.value; }`,
			extract: treesitter.ExtractJavaScript,
			fn:      "h",
			param:   "incoming",
			want:    "Widget",
		},
		{
			name:    "kotlin",
			ext:     "kt",
			src:     `fun h(incoming: Widget) { incoming.read("x") }`,
			extract: treesitter.ExtractKotlin,
			fn:      "h",
			param:   "incoming",
			want:    "Widget",
		},
		{
			name:    "objc",
			ext:     "m",
			src:     `@implementation T - (void)h:(Widget *)incoming { [incoming value]; } @end`,
			extract: treesitter.ExtractObjC,
			fn:      "h",
			param:   "incoming",
			want:    "Widget",
		},
		{
			name:    "php",
			ext:     "php",
			src:     `<?php function h(Widget $incoming) { $incoming->read('x'); }`,
			extract: treesitter.ExtractPHP,
			fn:      "h",
			param:   "$incoming",
			want:    "Widget",
		},
		{
			name:    "powershell",
			ext:     "ps1",
			src:     `function h { param([Widget]$incoming) $incoming.Value }`,
			extract: treesitter.ExtractPowerShell,
			fn:      "h",
			param:   "incoming",
			want:    "Widget",
		},
		{
			name:    "python",
			ext:     "py",
			src:     "def h(incoming: Widget):\n    incoming.value\n",
			extract: treesitter.ExtractPython,
			fn:      "h",
			param:   "incoming",
			want:    "Widget",
		},
		{
			name:    "rust",
			ext:     "rs",
			src:     `fn h(incoming: Widget) { incoming.value(); }`,
			extract: treesitter.ExtractRust,
			fn:      "h",
			param:   "incoming",
			want:    "Widget",
		},
		{
			name:    "scala",
			ext:     "scala",
			src:     `def h(incoming: Widget) = { incoming.value("x") }`,
			extract: treesitter.ExtractScala,
			fn:      "h",
			param:   "incoming",
			want:    "Widget",
		},
		{
			name:    "solidity",
			ext:     "sol",
			src:     `contract T { function h(uint incoming) public { uint x = incoming; } }`,
			extract: treesitter.ExtractSolidity,
			fn:      "h",
			param:   "incoming",
			want:    "uint",
		},
		{
			name:    "swift",
			ext:     "swift",
			src:     `func h(incoming: Widget) { _ = incoming.value }`,
			extract: treesitter.ExtractSwift,
			fn:      "h",
			param:   "incoming",
			want:    "Widget",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "sample."+tc.ext)
			if err := os.WriteFile(p, []byte(tc.src), 0o644); err != nil {
				t.Fatal(err)
			}
			prog, err := tc.extract([]string{p}, dir)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := findFuncParamType(prog, tc.fn, tc.param)
			if !ok {
				t.Fatalf("%s.%s ParamTypes missing %q; program=%#v", tc.fn, tc.param, tc.want, prog)
			}
			if got != tc.want {
				t.Fatalf("%s.%s type = %q, want %q", tc.fn, tc.param, got, tc.want)
			}
		})
	}
}

func findFuncParamType(prog nir.Program, fn, param string) (string, bool) {
	for _, mod := range prog.Modules {
		if got, ok := findParamTypeInStmts(mod.Body, fn, param); ok {
			return got, true
		}
	}
	return "", false
}

func findParamTypeInStmts(stmts []nir.Stmt, fn, param string) (string, bool) {
	for _, st := range stmts {
		switch s := st.(type) {
		case nir.FuncDef:
			if s.Name == fn {
				got, ok := s.ParamTypes[param]
				return got, ok
			}
			if got, ok := findParamTypeInStmts(s.Body, fn, param); ok {
				return got, true
			}
		case nir.ClassDef:
			if got, ok := findParamTypeInStmts(s.Body, fn, param); ok {
				return got, true
			}
		case nir.Block:
			if got, ok := findParamTypeInStmts(s.Stmts, fn, param); ok {
				return got, true
			}
		case nir.If:
			if got, ok := findParamTypeInStmts(s.Then, fn, param); ok {
				return got, true
			}
			if got, ok := findParamTypeInStmts(s.Else, fn, param); ok {
				return got, true
			}
		case nir.Loop:
			if got, ok := findParamTypeInStmts(s.Body, fn, param); ok {
				return got, true
			}
		case nir.Try:
			if got, ok := findParamTypeInStmts(s.Body, fn, param); ok {
				return got, true
			}
			for _, h := range s.Handlers {
				if got, ok := findParamTypeInStmts(h, fn, param); ok {
					return got, true
				}
			}
		}
	}
	return "", false
}
