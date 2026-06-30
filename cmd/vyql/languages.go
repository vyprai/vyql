package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/vyprai/vyql/bindings"
	"github.com/vyprai/vyql/extract/frontend"
	cfgfront "github.com/vyprai/vyql/extract/frontend/config"
	"github.com/vyprai/vyql/extract/frontend/golang"
	"github.com/vyprai/vyql/extract/frontend/textpattern"
	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/nir"
)

// language ties a file extension set to its real source->NIR frontend and the
// v2 binding applicators that label its graph. Adding a language is a frontend +
// binding entry only; lowering, resolution, and rules are unchanged (docs/20).
type language struct {
	name     string
	exts     map[string]bool
	extract  func(files []string, root string) (nir.Program, error)
	bindings func() []bindings.Applicator
}

var languages = []language{
	{"go", map[string]bool{".go": true}, golang.Extract, frontend.GoBindings},
	{"python", map[string]bool{".py": true}, treesitter.ExtractPython, frontend.PythonBindings},
	{"javascript", map[string]bool{".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true, ".vue": true, ".html": true, ".htm": true},
		treesitter.ExtractJavaScript, frontend.JsBindings},
	{"ruby", map[string]bool{".rb": true, ".erb": true}, treesitter.ExtractRuby, frontend.RubyBindings},
	{"java", map[string]bool{".java": true}, treesitter.ExtractJava, frontend.JavaBindings},
	{"php", map[string]bool{".php": true, ".phtml": true, ".inc": true, ".module": true, ".install": true, ".profile": true, ".theme": true, ".engine": true, ".test": true}, treesitter.ExtractPHP, frontend.PHPBindings},
	{"csharp", map[string]bool{".cs": true}, treesitter.ExtractCSharp, frontend.CSharpBindings},
	{"c", map[string]bool{".c": true, ".h": true, ".xs": true}, treesitter.ExtractC, frontend.CBindings},
	{"cpp", map[string]bool{".cpp": true, ".cc": true, ".cxx": true, ".c++": true, ".hpp": true}, treesitter.ExtractCPP, frontend.CPPBindings},
	{"rust", map[string]bool{".rs": true}, treesitter.ExtractRust, frontend.RustBindings},
	{"bash", map[string]bool{".sh": true, ".bash": true}, treesitter.ExtractBash, frontend.BashBindings},
	{"scala", map[string]bool{".scala": true, ".sc": true}, treesitter.ExtractScala, frontend.ScalaBindings},
	{"lua", map[string]bool{".lua": true}, treesitter.ExtractLua, frontend.LuaBindings},
	{"kotlin", map[string]bool{".kt": true, ".kts": true}, treesitter.ExtractKotlin, frontend.KotlinBindings},
	{"powershell", map[string]bool{".ps1": true, ".psm1": true}, treesitter.ExtractPowerShell, frontend.PowerShellBindings},
	{"swift", map[string]bool{".swift": true}, treesitter.ExtractSwift, frontend.SwiftBindings},
	{"perl", map[string]bool{".pl": true, ".pm": true, ".cgi": true}, treesitter.ExtractPerl, frontend.PerlBindings},
	{"solidity", map[string]bool{".sol": true}, treesitter.ExtractSolidity, frontend.SolidityBindings},
	{"objc", map[string]bool{".m": true}, treesitter.ExtractObjC, frontend.ObjCBindings},
	{"elixir", map[string]bool{".ex": true, ".exs": true}, treesitter.ExtractElixir, frontend.ElixirBindings},
	{"dart", map[string]bool{".dart": true}, treesitter.ExtractDart, frontend.DartBindings},
	{"groovy", map[string]bool{".groovy": true, ".gradle": true}, treesitter.ExtractGroovy, frontend.GroovyBindings},
	// config / IaC files (AndroidManifest.xml, Info.plist, Dockerfile, K8s YAML,
	// Terraform, Python setup.cfg, JSP/Jelly templates) — a non-tree-sitter frontend; non-matching files yield no nodes so
	// other repos are unaffected. "dockerfile" matches by basename (no extension).
	{"config", map[string]bool{".xml": true, ".plist": true, ".yaml": true, ".yml": true,
		".tf": true, ".cfg": true, ".json": true, ".jelly": true, ".jsp": true, ".tag": true, ".jst": true, ".def": true, ".svelte": true, ".html": true, ".erb": true, ".pest": true, ".sch": true, ".php": true, "dockerfile": true}, cfgfront.Extract, frontend.ConfigBindings},
	{"textpattern", textpattern.Extensions(), textpattern.Extract, frontend.TextPatternBindings},
}

// scanStats reports per-language file counts for the run summary.
type scanStats struct {
	files     map[string]int // language -> files parsed
	languages []string       // languages actually present
}

// extractAll routes every path to the right frontend(s), merges into one NIR
// Program, and returns the union of binding applicators + constructor→type
// tables for the languages present.
func extractAll(paths []string) (nir.Program, []bindings.Applicator, map[string]string, scanStats, error) {
	var prog nir.Program
	present := map[string]bool{}
	stats := scanStats{files: map[string]int{}}

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return prog, nil, nil, stats, err
		}
		// Walk a directory ONCE and bucket files by language, instead of one full tree walk per
		// language (24+ walks dominated extraction on a large tree).
		var entries []treesitter.Entry
		root := p
		if info.IsDir() {
			entries = treesitter.ListAllFiles(p)
		} else {
			root = filepath.Dir(p)
			entries = []treesitter.Entry{{Path: p, Ext: strings.ToLower(filepath.Ext(p)), Base: strings.ToLower(filepath.Base(p))}}
		}
		if props := propertiesFromEntries(entries); len(props) > 0 {
			if prog.Properties == nil {
				prog.Properties = map[string]string{}
			}
			for k, v := range props {
				prog.Properties[k] = v
			}
		}
		for _, lg := range languages {
			files := filterEntriesForLanguage(entries, lg)
			if len(files) == 0 {
				continue
			}
			sub, err := lg.extract(files, root)
			if err != nil {
				return prog, nil, nil, stats, err
			}
			prog.Modules = append(prog.Modules, sub.Modules...)
			present[lg.name] = true
			stats.files[lg.name] += len(files)
		}
	}

	var bindingApps []bindings.Applicator
	ctorTypes := map[string]string{}
	for _, lg := range languages {
		if present[lg.name] {
			bindingApps = append(bindingApps, lg.bindings()...)
			for k, v := range frontend.CtorTypesFor(lg.name) {
				ctorTypes[k] = v
			}
			stats.languages = append(stats.languages, lg.name)
		}
	}
	if len(prog.Modules) > 0 {
		bindingApps = append(bindingApps, frontend.AutoBindings()...)
	}
	return prog, bindingApps, ctorTypes, stats, nil
}

func filterEntriesForLanguage(entries []treesitter.Entry, lg language) []string {
	var out []string
	for _, e := range entries {
		if e.Ext == ".h" {
			isCPP := headerLooksCPP(e.Path)
			if lg.name == "cpp" && isCPP {
				out = append(out, e.Path)
			}
			if lg.name == "c" && !isCPP && lg.exts[e.Ext] {
				out = append(out, e.Path)
			}
			continue
		}
		if lg.name == "python" && e.Ext == "" && fileHasPythonShebang(e.Path) {
			out = append(out, e.Path)
			continue
		}
		if lg.exts[e.Ext] || lg.exts[e.Base] {
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
	defer f.Close()
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

// propertiesFromEntries parses `.properties` files from the already-built source inventory.
// Last value wins on duplicate keys (adequate for const-folding).
func propertiesFromEntries(entries []treesitter.Entry) map[string]string {
	out := map[string]string{}
	for _, e := range entries {
		if e.Ext != ".properties" {
			continue
		}
		b, err := os.ReadFile(e.Path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
				continue
			}
			eq := strings.IndexAny(line, "=:")
			if eq <= 0 {
				continue
			}
			k := strings.TrimSpace(line[:eq])
			v := strings.TrimSpace(line[eq+1:])
			if k != "" {
				out[k] = v
			}
		}
	}
	return out
}
