// Package frontend is the extraction layer: the registry of which technologies exist and
// what files each claims, and the loading of frontend-facing binding data. The binding
// layer itself lives in internal/bindings.
package frontend

import (
	"os"
	"strings"
	"sync"

	"github.com/vyprai/vyql/internal/bindings"
	cfgfront "github.com/vyprai/vyql/internal/extract/frontend/config"
	"github.com/vyprai/vyql/internal/extract/frontend/golang"
	"github.com/vyprai/vyql/internal/extract/frontend/textpattern"
	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/nir"
)

// The technology registry: which technologies exist, what files each claims, and which binding set
// labels its graph.
//
// This is extractor-layer knowledge and lives with the extractors. It sat in package main, which
// meant adding a language was a change to the CLI, and that the one table naming every supported
// technology could not be read by anything that was not the command.

// Language ties a file extension set to its source->NIR frontend and the binding applicators that
// label the resulting graph. Adding a language is a frontend plus a binding entry; lowering,
// resolution and rules are untouched (docs/20).
type Language struct {
	Name     string
	Exts     map[string]bool
	Extract  func(files []string, root string) (nir.Program, error)
	Bindings func() []bindings.Applicator
}

// languages is built on first use rather than at package initialization, because
// the textpattern entry derives its extensions from the vyql/ data directory.
// Reading that during init puts it before main, where a missing data directory
// escapes as a goroutine dump instead of the diagnostic the CLI is written to
// print -- and before any flag that says where the directory is has been parsed.
var languages = sync.OnceValue(func() []Language {
	return []Language{
	{"go", map[string]bool{".go": true}, golang.Extract, bindings.GoBindings},
	{"python", map[string]bool{".py": true}, treesitter.ExtractPython, bindings.PythonBindings},
	{"javascript", map[string]bool{".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true, ".vue": true, ".html": true, ".htm": true},
		treesitter.ExtractJavaScript, bindings.JsBindings},
	{"ruby", map[string]bool{".rb": true, ".erb": true}, treesitter.ExtractRuby, bindings.RubyBindings},
	{"java", map[string]bool{".java": true}, treesitter.ExtractJava, bindings.JavaBindings},
	{"php", map[string]bool{".php": true, ".phtml": true, ".inc": true, ".module": true, ".install": true, ".profile": true, ".theme": true, ".engine": true, ".test": true}, treesitter.ExtractPHP, bindings.PHPBindings},
	{"csharp", map[string]bool{".cs": true}, treesitter.ExtractCSharp, bindings.CSharpBindings},
	{"c", map[string]bool{".c": true, ".h": true, ".xs": true}, treesitter.ExtractC, bindings.CBindings},
	{"cpp", map[string]bool{".cpp": true, ".cc": true, ".cxx": true, ".c++": true, ".hpp": true}, treesitter.ExtractCPP, bindings.CPPBindings},
	{"rust", map[string]bool{".rs": true}, treesitter.ExtractRust, bindings.RustBindings},
	{"bash", map[string]bool{".sh": true, ".bash": true}, treesitter.ExtractBash, bindings.BashBindings},
	{"scala", map[string]bool{".scala": true, ".sc": true}, treesitter.ExtractScala, bindings.ScalaBindings},
	{"lua", map[string]bool{".lua": true}, treesitter.ExtractLua, bindings.LuaBindings},
	{"kotlin", map[string]bool{".kt": true, ".kts": true}, treesitter.ExtractKotlin, bindings.KotlinBindings},
	{"powershell", map[string]bool{".ps1": true, ".psm1": true}, treesitter.ExtractPowerShell, bindings.PowerShellBindings},
	{"swift", map[string]bool{".swift": true}, treesitter.ExtractSwift, bindings.SwiftBindings},
	{"perl", map[string]bool{".pl": true, ".pm": true, ".cgi": true}, treesitter.ExtractPerl, bindings.PerlBindings},
	{"solidity", map[string]bool{".sol": true}, treesitter.ExtractSolidity, bindings.SolidityBindings},
	{"objc", map[string]bool{".m": true}, treesitter.ExtractObjC, bindings.ObjCBindings},
	{"elixir", map[string]bool{".ex": true, ".exs": true}, treesitter.ExtractElixir, bindings.ElixirBindings},
	{"dart", map[string]bool{".dart": true}, treesitter.ExtractDart, bindings.DartBindings},
	{"groovy", map[string]bool{".groovy": true, ".gradle": true}, treesitter.ExtractGroovy, bindings.GroovyBindings},
	// config / IaC files (AndroidManifest.xml, Info.plist, Dockerfile, K8s YAML, Terraform,
	// Python setup.cfg, JSP/Jelly templates) — a non-tree-sitter frontend; non-matching files
	// yield no nodes so other repos are unaffected. "dockerfile" matches by basename.
	{"config", map[string]bool{".xml": true, ".plist": true, ".yaml": true, ".yml": true,
		".tf": true, ".cfg": true, ".json": true, ".jelly": true, ".jsp": true, ".tag": true, ".jst": true, ".def": true, ".svelte": true, ".html": true, ".erb": true, ".pest": true, ".sch": true, ".php": true, "dockerfile": true}, cfgfront.Extract, bindings.ConfigBindings},
		{"textpattern", textpattern.Extensions(), textpattern.Extract, bindings.TextPatternBindings},
	}
})

// Languages returns the registry in extraction order.
func Languages() []Language { return languages() }

// EntryClass records the content-derived facts an extension alone cannot settle: whether a `.h` is
// C++ rather than C, and whether an extension-less file is a Python script.
//
// It exists because both answers require READING the file, and the per-language filter runs once
// per technology. Computing them inside that filter re-read every header 24 times per scan and
// every extension-less file 24 times, regardless of which language was being filtered for. They
// are now derived once per directory and consulted 24 times.
type EntryClass struct {
	cppHeader     map[string]bool
	pythonShebang map[string]bool
}

// ClassifyEntries inspects the entries whose language cannot be decided from the extension.
func ClassifyEntries(entries []treesitter.Entry) EntryClass {
	c := EntryClass{cppHeader: map[string]bool{}, pythonShebang: map[string]bool{}}
	for _, e := range entries {
		switch e.Ext {
		case ".h":
			c.cppHeader[e.Path] = headerLooksCPP(e.Path)
		case "":
			c.pythonShebang[e.Path] = fileHasPythonShebang(e.Path)
		}
	}
	return c
}

// FilesFor returns the entries this language claims, using the pre-computed classification.
func (lg Language) FilesFor(entries []treesitter.Entry, class EntryClass) []string {
	var out []string
	for _, e := range entries {
		if e.Ext == ".h" {
			isCPP := class.cppHeader[e.Path]
			if lg.Name == "cpp" && isCPP {
				out = append(out, e.Path)
			}
			if lg.Name == "c" && !isCPP && lg.Exts[e.Ext] {
				out = append(out, e.Path)
			}
			continue
		}
		if lg.Name == "python" && e.Ext == "" && class.pythonShebang[e.Path] {
			out = append(out, e.Path)
			continue
		}
		if lg.Exts[e.Ext] || lg.Exts[e.Base] {
			out = append(out, e.Path)
		}
	}
	return out
}

func fileHasPythonShebang(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }() // read-only; a close error is not actionable
	buf := make([]byte, 160)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return false
	}
	first := string(buf[:n])
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	first = strings.ToLower(strings.TrimSpace(first))
	return strings.HasPrefix(first, "#!") && strings.Contains(first, "python")
}

func headerLooksCPP(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	text := string(b)
	for _, marker := range []string{
		"namespace ",
		"class ",
		"template<",
		"template <",
		"std::",
		"::",
		"public:",
		"private:",
		"protected:",
		"new ",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}
