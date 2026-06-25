package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/extract/nir"
)

func TestRubySingletonClassMethodsAreExtracted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bibliography.rb")
	src := []byte(`class Bibliography
  class << self
    def open(path, options = {})
      parse(Kernel.open(path, 'r:UTF-8').read, options)
    end
  end
end
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractRuby([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rubyHasFuncWithParam(prog.Modules, "open", "path") {
		t.Fatalf("singleton class method open(path) was not extracted; program=%#v", prog)
	}
}

func TestRubyModuleContextIncludesStructuredTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret_token.rb")
	src := []byte(`if defined?(FatFreeCRM::Application)
  if Rails.env == 'test'
    FatFreeCRM::Application.config.secret_token = '51aa366864a80316a85cff0d3762347f4ae3d029d548bef034d56e82b1a2ffac5353ee6719d9b64e4354e2a0b1a901679f46a851c360a2ea377188e4b196b6b6'
  end
end
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractRuby([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.module.context" {
			continue
		}
		args := n.Prop("str_args")
		for _, want := range []string{
			"lang=ruby",
			"assign:FatFreeCRM.Application.config.secret_token=51aa366864a80316a85cff0d3762347f4ae3d029d548bef034d56e82b1a2ffac5353ee6719d9b64e4354e2a0b1a901679f46a851c360a2ea377188e4b196b6b6",
			"assign:config.secret_token=51aa366864a80316a85cff0d3762347f4ae3d029d548bef034d56e82b1a2ffac5353ee6719d9b64e4354e2a0b1a901679f46a851c360a2ea377188e4b196b6b6",
			"selector:FatFreeCRM.Application.config.secret_token",
			"selector:config.secret_token",
			"expr:Rails.env=='test'",
			"literal:test",
		} {
			if !strings.Contains(args, want) {
				t.Fatalf("ruby module context missing %q; context=%q", want, args)
			}
		}
		return
	}
	t.Fatalf("analysis.module.context not found; nodes=%#v", nodes)
}

func TestRubyFunctionContextIncludesStructuredTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "library.rb")
	src := []byte(`module FFI
  module Library
    def ffi_lib(*names)
      names.each do |libname|
        begin
          FFI::DynamicLibrary.open(libname, lib_flags)
        rescue Exception => ex
          unless libname.start_with?("/") || FFI::Platform.windows?
            path = ['/usr/lib/','/usr/local/lib/'].find do |pth|
              File.exist?(pth + libname)
            end
          end
        end
      end
    end
  end
end
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractRuby([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" || !strings.Contains(n.Prop("str_args"), "name=ffi_lib") {
			continue
		}
		args := n.Prop("str_args")
		for _, want := range []string{
			"call_path:FFI.DynamicLibrary.open",
			"call_path:FFI.Platform.windows?",
			"call_path:File.exist?",
			"literal:/usr/lib/",
			"literal:/usr/local/lib/",
		} {
			if !strings.Contains(args, want) {
				t.Fatalf("ruby function context missing %q; context=%q", want, args)
			}
		}
		return
	}
	t.Fatalf("analysis.function.context for ffi_lib not found; nodes=%#v", nodes)
}

func rubyHasFuncWithParam(mods []nir.Module, name, param string) bool {
	var walk func([]nir.Stmt) bool
	walk = func(stmts []nir.Stmt) bool {
		for _, st := range stmts {
			switch x := st.(type) {
			case nir.FuncDef:
				if x.Name == name {
					for _, p := range x.Params {
						if p == param {
							return true
						}
					}
				}
				if walk(x.Body) {
					return true
				}
			case nir.ClassDef:
				if walk(x.Body) {
					return true
				}
			case nir.Block:
				if walk(x.Stmts) {
					return true
				}
			}
		}
		return false
	}
	for _, mod := range mods {
		if walk(mod.Body) {
			return true
		}
	}
	return false
}
