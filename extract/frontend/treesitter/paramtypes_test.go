package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
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

func TestCPPStructMethodsExtractFunctionContext(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.cpp")
	src := `
struct WireHelpers {
  static ListReader readListPointer(SegmentReader* segment, const WirePointer* ref) {
    ElementSize elementSize = ref->listRef.elementSize();
    if (elementSize == ElementSize::INLINE_COMPOSITE) {
      ElementCount size = ref->inlineCompositeListElementCount();
      return ListReader(segment, ref, size);
    }
    return ListReader();
  }
};
`
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractCPP([]string{p}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := findFunc(prog, "readListPointer")
	if !ok {
		t.Fatalf("readListPointer not extracted from C++ struct; program=%#v", prog)
	}
	context := strings.Join(fn.ContextTokens, "\x00")
	for _, want := range []string{"lang=cpp", "name=readListPointer", "inlineCompositeListElementCount", "ListReader"} {
		if !strings.Contains(context, want) {
			t.Fatalf("function context missing %q; context=%q", want, context)
		}
	}
}

func TestScalaFunctionContextIncludesStructuredTokens(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.scala")
	src := `
object JsonGenerateUtils {
  private def generateRowConverter(ctx: CodeGeneratorContext, rowType: LogicalType): String = {
    val fieldNames = toScala(LogicalTypeChecks.getFieldNames(rowType)).map(EncodingUtils.escapeJava)
    val populateObjectCode = fieldNames.zipWithIndex.map {
      case (fieldName, idx) =>
        objNode.set(fieldName, createNullableNodeTerm(ctx, "rowData", idx.toString, fieldType))
    }.mkString
    ctx.addReusableMember(populateObjectCode.stripMargin)
    "convertRow"
  }
}
`
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractScala([]string{p}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := findFunc(prog, "generateRowConverter")
	if !ok {
		t.Fatalf("generateRowConverter not extracted; program=%#v", prog)
	}
	context := strings.Join(fn.ContextTokens, "\x00")
	for _, want := range []string{
		"lang=scala",
		"function_name:generateRowConverter",
		"call_path:LogicalTypeChecks.getFieldNames",
		"call_path:fieldNames.zipWithIndex.map",
		"call_path:createNullableNodeTerm",
		"call_path:ctx.addReusableMember",
		"selector:EncodingUtils.escapeJava",
	} {
		if !strings.Contains(context, want) {
			t.Fatalf("Scala function context missing %q; context=%q", want, context)
		}
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

func findFunc(prog nir.Program, fn string) (nir.FuncDef, bool) {
	for _, mod := range prog.Modules {
		if got, ok := findFuncInStmts(mod.Body, fn); ok {
			return got, true
		}
	}
	return nir.FuncDef{}, false
}

func findFuncInStmts(stmts []nir.Stmt, fn string) (nir.FuncDef, bool) {
	for _, st := range stmts {
		switch s := st.(type) {
		case nir.FuncDef:
			if s.Name == fn {
				return s, true
			}
			if got, ok := findFuncInStmts(s.Body, fn); ok {
				return got, true
			}
		case nir.ClassDef:
			if got, ok := findFuncInStmts(s.Body, fn); ok {
				return got, true
			}
		case nir.Block:
			if got, ok := findFuncInStmts(s.Stmts, fn); ok {
				return got, true
			}
		case nir.If:
			if got, ok := findFuncInStmts(s.Then, fn); ok {
				return got, true
			}
			if got, ok := findFuncInStmts(s.Else, fn); ok {
				return got, true
			}
		case nir.Loop:
			if got, ok := findFuncInStmts(s.Body, fn); ok {
				return got, true
			}
		case nir.Try:
			if got, ok := findFuncInStmts(s.Body, fn); ok {
				return got, true
			}
			for _, h := range s.Handlers {
				if got, ok := findFuncInStmts(h, fn); ok {
					return got, true
				}
			}
			if got, ok := findFuncInStmts(s.Finally, fn); ok {
				return got, true
			}
		}
	}
	return nir.FuncDef{}, false
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
