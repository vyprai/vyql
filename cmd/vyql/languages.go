package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/extract/frontend"
	cfgfront "github.com/vyprai/vyql/extract/frontend/config"
	"github.com/vyprai/vyql/extract/frontend/golang"
	"github.com/vyprai/vyql/extract/frontend/textpattern"
	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/nir"
)

// language ties a file extension set to its real source→NIR frontend and the
// framework adapters that label its graph. Adding a language is a frontend +
// adapter entry only — lowering, resolution, and rules are unchanged (docs/20).
type language struct {
	name     string
	exts     map[string]bool
	extract  func(files []string, root string) (nir.Program, error)
	adapters func() []adapters.Adapter
}

var languages = []language{
	{"go", map[string]bool{".go": true}, golang.Extract, frontend.GoAdapters},
	{"python", map[string]bool{".py": true}, treesitter.ExtractPython, frontend.PythonAdapters},
	{"javascript", map[string]bool{".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true, ".vue": true, ".html": true, ".htm": true},
		treesitter.ExtractJavaScript, frontend.JsAdapters},
	{"ruby", map[string]bool{".rb": true, ".erb": true}, treesitter.ExtractRuby, frontend.RubyAdapters},
	{"java", map[string]bool{".java": true}, treesitter.ExtractJava, frontend.JavaAdapters},
	{"php", map[string]bool{".php": true, ".phtml": true, ".inc": true}, treesitter.ExtractPHP, frontend.PHPAdapters},
	{"csharp", map[string]bool{".cs": true}, treesitter.ExtractCSharp, frontend.CSharpAdapters},
	{"c", map[string]bool{".c": true, ".h": true, ".xs": true}, treesitter.ExtractC, frontend.CAdapters},
	{"cpp", map[string]bool{".cpp": true, ".cc": true, ".cxx": true, ".c++": true, ".hpp": true}, treesitter.ExtractCPP, frontend.CPPAdapters},
	{"rust", map[string]bool{".rs": true}, treesitter.ExtractRust, frontend.RustAdapters},
	{"bash", map[string]bool{".sh": true, ".bash": true}, treesitter.ExtractBash, frontend.BashAdapters},
	{"scala", map[string]bool{".scala": true, ".sc": true}, treesitter.ExtractScala, frontend.ScalaAdapters},
	{"lua", map[string]bool{".lua": true}, treesitter.ExtractLua, frontend.LuaAdapters},
	{"kotlin", map[string]bool{".kt": true, ".kts": true}, treesitter.ExtractKotlin, frontend.KotlinAdapters},
	{"powershell", map[string]bool{".ps1": true, ".psm1": true}, treesitter.ExtractPowerShell, frontend.PowerShellAdapters},
	{"swift", map[string]bool{".swift": true}, treesitter.ExtractSwift, frontend.SwiftAdapters},
	{"perl", map[string]bool{".pl": true, ".pm": true, ".cgi": true}, treesitter.ExtractPerl, frontend.PerlAdapters},
	{"solidity", map[string]bool{".sol": true}, treesitter.ExtractSolidity, frontend.SolidityAdapters},
	{"objc", map[string]bool{".m": true}, treesitter.ExtractObjC, frontend.ObjCAdapters},
	{"elixir", map[string]bool{".ex": true, ".exs": true}, treesitter.ExtractElixir, frontend.ElixirAdapters},
	{"dart", map[string]bool{".dart": true}, treesitter.ExtractDart, frontend.DartAdapters},
	{"groovy", map[string]bool{".groovy": true, ".gradle": true}, treesitter.ExtractGroovy, frontend.GroovyAdapters},
	// config / IaC files (AndroidManifest.xml, Info.plist, Dockerfile, K8s YAML,
	// Terraform, Python setup.cfg, JSP/Jelly templates) — a non-tree-sitter frontend; non-matching files yield no nodes so
	// other repos are unaffected. "dockerfile" matches by basename (no extension).
	{"config", map[string]bool{".xml": true, ".plist": true, ".yaml": true, ".yml": true,
		".tf": true, ".cfg": true, ".jelly": true, ".jsp": true, ".tag": true, ".jst": true, ".def": true, ".svelte": true, ".html": true, ".erb": true, ".pest": true, ".php": true, "dockerfile": true}, cfgfront.Extract, frontend.ConfigAdapters},
	{"textpattern", textpattern.Extensions(), textpattern.Extract, frontend.TextPatternAdapters},
}

// scanStats reports per-language file counts for the run summary.
type scanStats struct {
	files     map[string]int // language -> files parsed
	languages []string       // languages actually present
}

// extractAll routes every path to the right frontend(s), merges into one NIR
// Program, and returns the union of adapters + constructor→type tables for the
// languages present.
func extractAll(paths []string) (nir.Program, []adapters.Adapter, map[string]string, scanStats, error) {
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
		for _, lg := range languages {
			files := treesitter.FilterEntries(entries, lg.exts)
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

	var ads []adapters.Adapter
	ctorTypes := map[string]string{}
	for _, lg := range languages {
		if present[lg.name] {
			ads = append(ads, lg.adapters()...)
			for k, v := range frontend.CtorTypesFor(lg.name) {
				ctorTypes[k] = v
			}
			stats.languages = append(stats.languages, lg.name)
		}
	}
	if len(prog.Modules) > 0 {
		ads = append(ads, frontend.AutoAdapters()...)
	}
	// Bundled .properties config is resolved to a flat key->value map so frontends can
	// preserve configuration constants through lowering.
	if props := collectProperties(paths); len(props) > 0 {
		prog.Properties = props
	}
	return prog, ads, ctorTypes, stats, nil
}

// collectProperties parses every `.properties` file reachable from the scan paths into a
// flat key→value map. Last value wins on duplicate keys (a coarse but adequate model;
// values are only used for const-folding config reads, not for precise per-file scoping).
func collectProperties(paths []string) map[string]string {
	out := map[string]string{}
	parse := func(file string) {
		b, err := os.ReadFile(file)
		if err != nil {
			return
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
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if strings.HasSuffix(p, ".properties") {
				parse(p)
			}
			continue
		}
		filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(path, ".properties") {
				parse(path)
			}
			return nil
		})
	}
	return out
}
