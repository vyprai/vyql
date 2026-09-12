// Package frontend is the extraction layer: the registry of which technologies exist and
// what files each claims, and the loading of frontend-facing binding data. The binding
// layer itself lives in internal/bindings.
package frontend

import (
	"os"
	"strings"
	"sync"

	"github.com/vyprai/vyql/internal/bindings"
	"github.com/vyprai/vyql/internal/extract/frontend/actionscript"
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
		{"haskell", map[string]bool{".hs": true}, treesitter.ExtractHaskell, bindings.HaskellBindings},
		// ActionScript (Flash/AIR). Its own hand-written frontend: no tree-sitter grammar
		// parses `package a.b { … }` or `private var x:String`, and the JavaScript grammar
		// reads a whole .as file as one error.
		{"actionscript", map[string]bool{".as": true}, actionscript.Extract, bindings.ActionScriptBindings},
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

// graphWeights is how much graph a byte of each language's source lowers to,
// in hundredths of a JavaScript byte — the corpus the scan memory constants are
// calibrated on. 100 means "lowers like JavaScript", 500 means "a byte of this
// language is five JavaScript bytes of graph".
//
// Measured as lowered nodes per KB of source, reference javascript = 298 n/KB,
// over each language's OWASP port corpus (BenchmarkJava for java, this
// repository for go, a large private Python monorepo as a real-world python
// cross-check):
//
//	python 1405 · php 697 · ruby 494 · csharp 389 · rust 312 · c 304
//	javascript 298 · typescript 288 · swift 246 · cpp 196 · groovy 167
//	lua 151 · objc 136 · powershell 135 · elixir 121 · go 121 · scala 115
//	kotlin 104 · bash 84 · dart 78 · perl 73 · solidity 54 · java 35
//
// Each weight is the measured ratio rounded UP, and a language that lowers
// lighter than JavaScript still gets 100: the constants already mean
// JavaScript, and under-weighting is the direction that overflows a ceiling —
// over-weighting only costs partitions. A real-world Python file was seen at
// 1179 n/KB against the port's 1405, so python carries margin rather than the
// exact ratio. A language with no corpus behind it (haskell, actionscript)
// takes the heaviest measured weight rather than the lightest, via GraphWeight's
// default: a frontend nobody has measured must not plan partitions as though it
// were the sparsest language measured.
var graphWeights = map[string]int64{
	"python":     500,
	"php":        250,
	"ruby":       175,
	"csharp":     140,
	"rust":       110,
	"c":          110,
	"javascript": 100, // the reference corpus
	"typescript": 100,
	"swift":      100,
	"cpp":        100,
	"groovy":     100,
	"lua":        100,
	"objc":       100,
	"powershell": 100,
	"elixir":     100,
	"go":         100,
	"scala":      100,
	"kotlin":     100,
	"bash":       100,
	"dart":       100,
	"perl":       100,
	"solidity":   100,
	"java":       100,
	// Non-tree-sitter frontends: pattern and config extraction emit a handful of
	// nodes per file regardless of its size, so the byte-for-byte reference weight
	// already over-states them.
	"config":      100,
	"textpattern": 100,
}

// graphWeightDefault is what an unmeasured language weighs: the heaviest
// measured weight, so a new frontend partitions as cautiously as the densest
// language until someone measures it.
const graphWeightDefault int64 = 500

// GraphWeight returns the partition weight of one byte of name's source, in
// hundredths of a JavaScript byte. See graphWeights for where the figures come
// from and which way they round.
func GraphWeight(name string) int64 {
	if w, ok := graphWeights[name]; ok && w >= 100 {
		return w
	}
	return graphWeightDefault
}

// BundleKinds returns the extension set of the frontend that parses bundled web
// code — the JavaScript family, with .html for the scripts inlined in it.
//
// A minified bundle is that family's build output, and only there is one
// enormous line a hazard: in JavaScript it is a megabyte of code, where every
// token becomes analysis state. Another language's one-line file is a data blob
// behind a single literal, which parses to one node and carries none of a
// bundle's cost — so a gate over line shape must not reach it.
func BundleKinds() map[string]bool {
	for _, lg := range Languages() {
		if lg.Name == "javascript" {
			return lg.Exts
		}
	}
	return nil
}

// EntryClass records the content-derived facts an extension alone cannot settle: whether a `.h` is
// C++ rather than C, whether an extension-less file is a Python script, and whether a file named
// like Perl reads as Perl — the `.pl` name is shared with documentation prose (README.pl is the
// Polish README by convention), and the Perl grammar parsing prose costs gigabytes of resident
// memory per few hundred kilobytes of file.
//
// It exists because these answers require READING the file, and the per-language filter runs once
// per technology. Computing them inside that filter re-read every header 24 times per scan and
// every extension-less file 24 times, regardless of which language was being filtered for. They
// are now derived once per directory and consulted 24 times.
type EntryClass struct {
	cppHeader     map[string]bool
	pythonShebang map[string]bool
	perlSource    map[string]bool
}

// ClassifyEntries inspects the entries whose language cannot be decided from the extension.
func ClassifyEntries(entries []treesitter.Entry) EntryClass {
	c := EntryClass{cppHeader: map[string]bool{}, pythonShebang: map[string]bool{}, perlSource: map[string]bool{}}
	var perlExts map[string]bool
	for _, lg := range languages() {
		if lg.Name == "perl" {
			perlExts = lg.Exts
		}
	}
	for _, e := range entries {
		switch {
		case e.Ext == ".h":
			c.cppHeader[e.Path] = headerLooksCPP(e.Path)
		case e.Ext == "":
			c.pythonShebang[e.Path] = fileHasPythonShebang(e.Path)
		case perlExts[e.Ext]:
			c.perlSource[e.Path] = treesitter.ReadsAsPerl(e.Path)
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
		// The Perl claim carries a content check the other two facts do not: a
		// file made of no Perl construct is documentation prose rather than Perl,
		// and reading it as Perl is the several-thousand-fold memory
		// amplification described at ReadsAsPerl. Only an affirmative rejection
		// narrows the claim — a file that was never checked keeps the
		// extension-only claim, so a caller that skipped classification cannot
		// silently unclaim a language's files.
		if lg.Name == "perl" {
			if parses, probed := class.perlSource[e.Path]; probed && !parses {
				continue
			}
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
