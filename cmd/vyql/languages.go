package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/extract/frontend"
	cfgfront "github.com/vyprai/vyql/extract/frontend/config"
	"github.com/vyprai/vyql/extract/frontend/golang"
	"github.com/vyprai/vyql/extract/frontend/secretscan"
	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/nir"
)

// secretscanExts: source + config/env formats where hardcoded secrets commonly live.
// secretscan runs ALONGSIDE the real frontend (extractAll runs every matching language),
// adding HardcodedSecret nodes without affecting the source parse.
var secretscanExts = map[string]bool{
	".go": true, ".py": true, ".js": true, ".jsx": true, ".ts": true, ".tsx": true,
	".rb": true, ".java": true, ".php": true, ".cs": true, ".c": true, ".cpp": true,
	".rs": true, ".sh": true, ".bash": true, ".scala": true, ".kt": true, ".kts": true,
	".swift": true, ".pl": true, ".ex": true, ".exs": true, ".dart": true, ".groovy": true,
	".env": true, ".yaml": true, ".yml": true, ".properties": true, ".json": true,
	".toml": true, ".ini": true, ".cfg": true, ".conf": true, ".tf": true,
}

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
	{"javascript", map[string]bool{".js": true, ".jsx": true, ".ts": true, ".tsx": true},
		treesitter.ExtractJavaScript, frontend.JsAdapters},
	{"ruby", map[string]bool{".rb": true}, treesitter.ExtractRuby, frontend.RubyAdapters},
	{"java", map[string]bool{".java": true}, treesitter.ExtractJava, frontend.JavaAdapters},
	{"php", map[string]bool{".php": true, ".phtml": true}, treesitter.ExtractPHP, frontend.PHPAdapters},
	{"csharp", map[string]bool{".cs": true}, treesitter.ExtractCSharp, frontend.CSharpAdapters},
	{"c", map[string]bool{".c": true, ".h": true}, treesitter.ExtractC, frontend.CAdapters},
	{"cpp", map[string]bool{".cpp": true, ".cc": true, ".cxx": true, ".hpp": true}, treesitter.ExtractCPP, frontend.CPPAdapters},
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
	// Terraform) — a non-tree-sitter frontend; non-matching files yield no nodes so
	// other repos are unaffected. "dockerfile" matches by basename (no extension).
	{"config", map[string]bool{".xml": true, ".plist": true, ".yaml": true, ".yml": true,
		".tf": true, "dockerfile": true}, cfgfront.Extract, frontend.ConfigAdapters},
	// hardcoded-secret scanner — runs over source + config/env files (alongside the real
	// frontend), emitting HardcodedSecret nodes from provider tokens / secret literals.
	{"secretscan", secretscanExts, secretscan.Extract, frontend.SecretscanAdapters},
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
		for _, lg := range languages {
			var files []string
			var root string
			if info.IsDir() {
				files, _ = treesitter.ListFiles(p, lg.exts)
				root = p
			} else if lg.exts[strings.ToLower(filepath.Ext(p))] || lg.exts[strings.ToLower(filepath.Base(p))] {
				files = []string{p}
				root = filepath.Dir(p)
			}
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
	return prog, ads, ctorTypes, stats, nil
}
