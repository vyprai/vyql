package frontend_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend"
	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/nir"
)

// A Flash .as file has to be claimed by a registered frontend and parsed into calls.
// Until one was, the file was left entirely unparsed: it fell through every language
// filter, contributed no module, and nothing in it could be labelled a source or a
// sink — so no binding and no rule could reach CVE-2013-1942's ExternalInterface.call.
func TestActionScriptFilesAreClaimedAndParsedIntoCalls(t *testing.T) {
	dir := t.TempDir()
	src := `package happyworm.jPlayer {
	import flash.external.ExternalInterface;
	public class Jplayer extends Sprite {
		private var jQuery:String;
		public function Jplayer() {
			jQuery = loaderInfo.parameters.jQuery + "('#" + loaderInfo.parameters.id + "').jPlayer";
			ExternalInterface.call(jQuery, "jPlayerFlashEvent");
		}
	}
}
`
	path := filepath.Join(dir, "Jplayer.as")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	entries := treesitter.ListAllFiles(dir)
	class := frontend.ClassifyEntries(entries)
	var claimed []string
	var lang frontend.Language
	for _, lg := range frontend.Languages() {
		for _, f := range lg.FilesFor(entries, class) {
			if f == path {
				claimed = append(claimed, lg.Name)
				lang = lg
			}
		}
	}
	if len(claimed) == 0 {
		t.Fatalf("no registered frontend claims %s; a .as file is left unparsed", filepath.Base(path))
	}

	prog, err := lang.Extract([]string{path}, dir)
	if err != nil {
		t.Fatalf("%s frontend: %v", lang.Name, err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("%s frontend produced %d modules, want 1", lang.Name, len(prog.Modules))
	}

	seen := map[string]bool{}
	var expr func(nir.Expr)
	var body func([]nir.Stmt)
	expr = func(e nir.Expr) {
		switch x := e.(type) {
		case nir.Call:
			seen["call "+x.Path] = true
			for _, a := range x.Args {
				expr(a)
			}
		case nir.Attr:
			seen["attr "+x.Path] = true
			expr(x.Base)
		case nir.Format:
			for _, p := range x.Parts {
				expr(p)
			}
		}
	}
	body = func(sts []nir.Stmt) {
		for _, st := range sts {
			switch s := st.(type) {
			case nir.ClassDef:
				body(s.Body)
			case nir.FuncDef:
				body(s.Body)
			case nir.Assign:
				expr(s.Value)
			case nir.ExprStmt:
				expr(s.Value)
			}
		}
	}
	body(prog.Modules[0].Body)

	for _, want := range []string{"call ExternalInterface.call", "attr loaderInfo.parameters.jQuery"} {
		if !seen[want] {
			t.Errorf("%s frontend did not produce %q; got %v", lang.Name, want, seen)
		}
	}
}

// A `.hh` header is where whole C++ projects keep their implementation — lepton's
// divide-by-zero fixes land in `uncompressed_components.hh` and `model.hh` — and
// the cpp extension set omitted it, so such a file fell through every language
// filter, contributed no module, and nothing written inside it could be labelled
// a source or a sink.
func TestHHFilesAreClaimedByTheCppFrontend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "codec.hh")
	src := `class Codec {
    int m_frameSize;
public:
    void Init(FILE *fp) {
        m_frameSize = read_int(fp);
        sink_int(100 / m_frameSize);
    }
};
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	entries := treesitter.ListAllFiles(dir)
	class := frontend.ClassifyEntries(entries)
	var claimed []string
	var lang frontend.Language
	for _, lg := range frontend.Languages() {
		for _, f := range lg.FilesFor(entries, class) {
			if f == path {
				claimed = append(claimed, lg.Name)
				lang = lg
			}
		}
	}
	if len(claimed) != 1 || claimed[0] != "cpp" {
		t.Fatalf("the cpp frontend alone must claim %s (claimed by %v); a .hh file is left unparsed", filepath.Base(path), claimed)
	}

	prog, err := lang.Extract([]string{path}, dir)
	if err != nil {
		t.Fatalf("cpp frontend: %v", err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("cpp frontend produced %d modules, want 1", len(prog.Modules))
	}
	seen := map[string]bool{}
	var expr func(nir.Expr)
	var body func([]nir.Stmt)
	expr = func(e nir.Expr) {
		switch x := e.(type) {
		case nir.Call:
			seen["call "+x.Path] = true
			for _, a := range x.Args {
				expr(a)
			}
		}
	}
	body = func(sts []nir.Stmt) {
		for _, st := range sts {
			switch s := st.(type) {
			case nir.ClassDef:
				body(s.Body)
			case nir.FuncDef:
				body(s.Body)
			case nir.Assign:
				expr(s.Value)
			case nir.ExprStmt:
				expr(s.Value)
			}
		}
	}
	body(prog.Modules[0].Body)
	for _, want := range []string{"call read_int", "call sink_int"} {
		if !seen[want] {
			t.Errorf("cpp frontend did not produce %q from the .hh file; got %v", want, seen)
		}
	}
}

// A CakePHP view template is a `.ctp` file — Croogo keeps almost all of CVE-2019-7168's
// dataflow in them (21 of the fix's 23 changed files): node titles echoed unescaped, the
// helper calls that wrap them. Until the php extension set claimed `.ctp`, such a file
// fell through every language filter, contributed no module, and nothing written inside
// it could be labelled a source or a sink.
func TestCTPFilesAreClaimedByThePHPFrontend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "view.ctp")
	src := `<div class="node view-mode">
	<h2><?php echo $node['Node']['title']; ?></h2>
	<?php echo $this->Html->link($node['Node']['title'], ['action' => 'view', $node['Node']['slug']]); ?>
	<?php echo h($node['Node']['title']); ?>
</div>
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	entries := treesitter.ListAllFiles(dir)
	class := frontend.ClassifyEntries(entries)
	var claimed []string
	var lang frontend.Language
	for _, lg := range frontend.Languages() {
		for _, f := range lg.FilesFor(entries, class) {
			if f == path {
				claimed = append(claimed, lg.Name)
				lang = lg
			}
		}
	}
	if len(claimed) != 1 || claimed[0] != "php" {
		t.Fatalf("the php frontend alone must claim %s (claimed by %v); a .ctp file is left unparsed", filepath.Base(path), claimed)
	}

	prog, err := lang.Extract([]string{path}, dir)
	if err != nil {
		t.Fatalf("php frontend: %v", err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("php frontend produced %d modules, want 1", len(prog.Modules))
	}
	seen := map[string]bool{}
	var expr func(nir.Expr)
	var body func([]nir.Stmt)
	expr = func(e nir.Expr) {
		switch x := e.(type) {
		case nir.Call:
			seen["call "+x.Path] = true
			for _, a := range x.Args {
				expr(a)
			}
		case nir.Attr:
			seen["attr "+x.Path] = true
			expr(x.Base)
		case nir.Format:
			for _, p := range x.Parts {
				expr(p)
			}
		}
	}
	body = func(sts []nir.Stmt) {
		for _, st := range sts {
			switch s := st.(type) {
			case nir.ClassDef:
				body(s.Body)
			case nir.FuncDef:
				body(s.Body)
			case nir.Assign:
				expr(s.Value)
			case nir.ExprStmt:
				expr(s.Value)
			}
		}
	}
	body(prog.Modules[0].Body)
	for _, want := range []string{"call echo", "call $this.Html.link", "call h"} {
		if !seen[want] {
			t.Errorf("php frontend did not produce %q from the .ctp file; got %v", want, seen)
		}
	}
}

// A TypeScript ES module is a `.mts`/`.cts` file, and CVE-2026-25931 lives entirely in
// them: packages/_server/src/config/documentSettings.mts reads cSpell.trustedWorkspace and
// forwards it into ConfigLoader.setIsTrusted. The JavaScript frontend already routes those
// extensions to the TypeScript grammar, but the registry never claimed them, so such a file
// fell through every language filter, contributed no module, and nothing written inside it
// could be labelled a source or a sink.
func TestMTSAndCTSFilesAreClaimedByTheJavaScriptFrontend(t *testing.T) {
	dir := t.TempDir()
	// The CVE's own shape: a class method reading a configuration value and handing it
	// to the loader's trust grant. The parameter type annotation is TypeScript, so the
	// assertions also prove the file reached the TypeScript grammar rather than the
	// JavaScript one reading it as one error.
	src := `import { ConfigLoader } from './configLoader';

export class DocumentSettings {
	private readonly loader: ConfigLoader;

	public _determineIsTrusted(config: WorkspaceConfiguration): void {
		const trusted = config.get('cSpell.trustedWorkspace');
		this.loader.setIsTrusted(!!trusted);
	}
}
`
	for _, name := range []string{"documentSettings.mts", "documentSettings.cts"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}

		entries := treesitter.ListAllFiles(dir)
		class := frontend.ClassifyEntries(entries)
		var claimed []string
		var lang frontend.Language
		for _, lg := range frontend.Languages() {
			for _, f := range lg.FilesFor(entries, class) {
				if f == path {
					claimed = append(claimed, lg.Name)
					lang = lg
				}
			}
		}
		if len(claimed) != 1 || claimed[0] != "javascript" {
			t.Fatalf("%s must be claimed by the javascript frontend alone (claimed by %v); a TypeScript ES module is left unparsed", name, claimed)
		}

		prog, err := lang.Extract([]string{path}, dir)
		if err != nil {
			t.Fatalf("javascript frontend: %v", err)
		}
		if len(prog.Modules) != 1 {
			t.Fatalf("%s: javascript frontend produced %d modules, want 1", name, len(prog.Modules))
		}

		seen := map[string]bool{}
		var expr func(nir.Expr)
		var body func([]nir.Stmt)
		expr = func(e nir.Expr) {
			switch x := e.(type) {
			case nir.Call:
				seen["call "+x.Path] = true
				for _, a := range x.Args {
					expr(a)
				}
			case nir.Attr:
				seen["attr "+x.Path] = true
				expr(x.Base)
			case nir.Name:
				seen["name "+x.ID] = true
			}
		}
		body = func(sts []nir.Stmt) {
			for _, st := range sts {
				switch s := st.(type) {
				case nir.ClassDef:
					body(s.Body)
				case nir.FuncDef:
					// `config: WorkspaceConfiguration` is a TypeScript annotation; the
					// JavaScript grammar has nowhere to put it, so this also proves the
					// file reached the grammar the frontend routes .mts/.cts to.
					if s.Name == "_determineIsTrusted" && s.ParamTypes["config"] != "" {
						seen["paramtype "+s.ParamTypes["config"]] = true
					}
					body(s.Body)
				case nir.Assign:
					expr(s.Value)
				case nir.ExprStmt:
					expr(s.Value)
				}
			}
		}
		body(prog.Modules[0].Body)

		for _, want := range []string{"call config.get", "call this.loader.setIsTrusted", "paramtype WorkspaceConfiguration"} {
			if !seen[want] {
				t.Errorf("%s: javascript frontend did not produce %q; got %v", name, want, seen)
			}
		}
	}
}

// proseDoc is documentation text of the kind a `.pl` name actually carries in the
// wild: a Polish README, with e-mail addresses, `%s` printf placeholders and
// `->` arrows in URLs — code-shaped tokens a loose shape check could mistake for
// code, and which the claim's marker set deliberately does not look at.
const proseDoc = `LMS - LAN Management System 1.11-git

   LMS Developers <lms@lists.lms.org.pl>
   Copyright (c) 2001-2013

   Spis treści
   1. Wstęp
        1.1. Czym jest LMS
   2. Instalacja i konfiguracja

   Moduły -> daemon -> konfiguracja %s %d @l @c
   Zobacz http://lms.org.pl/?page=module&action=info&id=%s po szczegóły.
   Plik konfiguracyjny: lms.ini, sekcja [daemon], opcje %s i %d.
`

// A `.pl` name is shared with documentation prose — README.pl is the Polish
// README by convention — and the Perl grammar reading prose is ruinous: the
// parse of a 338KB README peaked near 6GB of resident memory, which is how a
// bounded scan of a documentation-heavy clone died at its ceiling before the
// first rule ran. The claim asks what the file is made of, so prose is left
// unclaimed at any size and real Perl is claimed as before.
func TestPerlClaimDeclinesProseAndKeepsSource(t *testing.T) {
	dir := t.TempDir()
	var prose strings.Builder
	for prose.Len() < 64<<10 {
		prose.WriteString(proseDoc)
	}
	prosePath := filepath.Join(dir, "README.pl")
	if err := os.WriteFile(prosePath, []byte(prose.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(dir, "handler.pl")
	if err := os.WriteFile(sourcePath, []byte(`use strict;
use warnings;

sub handle {
  my ($self, $q) = @_;
  my $name = $q->param('name');
  print $q->header, $name;
}
1;
`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A shebang claims a script on its own: the minimal program, with no other
	// Perl construct anywhere in it, stays source exactly as a Python shebang
	// claims an extensionless script.
	scriptPath := filepath.Join(dir, "hello.pl")
	if err := os.WriteFile(scriptPath, []byte("#!/usr/bin/perl\nprint \"hello\\n\";\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries := treesitter.ListAllFiles(dir)
	class := frontend.ClassifyEntries(entries)
	claimedBy := map[string][]string{} // path -> claiming languages
	for _, lg := range frontend.Languages() {
		for _, f := range lg.FilesFor(entries, class) {
			claimedBy[f] = append(claimedBy[f], lg.Name)
		}
	}
	perlClaims := func(path string) bool {
		for _, name := range claimedBy[path] {
			if name == "perl" {
				return true
			}
		}
		return false
	}
	for _, p := range []string{sourcePath, scriptPath} {
		if !perlClaims(p) {
			t.Errorf("%s is not claimed by perl (claimed by %v); real Perl must stay source", filepath.Base(p), claimedBy[p])
		}
	}
	if perlClaims(prosePath) {
		t.Errorf("%s is claimed by perl (claimed by %v); prose is not Perl source, and parsing it as Perl is the memory failure this claim check exists for", filepath.Base(prosePath), claimedBy[prosePath])
	}
}

// A Twig template's output positions are the writes an engine has to see: `{{ … }}`
// is where a value reaches the page, and the filter on it (`|e`) is the escape that
// separates a patched revision from a vulnerable one. Until a frontend claimed the
// .twig extension the file fell through every language filter, so both were invisible.
func TestTwigFilesAreClaimedByTheConfigFrontend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "login.twig")
	src := `{% extends 'layouts/layoutAuth.twig' %}
<input type="text" name="username" value="{{ old.username }}">
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	entries := treesitter.ListAllFiles(dir)
	class := frontend.ClassifyEntries(entries)
	var claimed []string
	for _, lg := range frontend.Languages() {
		for _, f := range lg.FilesFor(entries, class) {
			if f == path {
				claimed = append(claimed, lg.Name)
			}
		}
	}
	if len(claimed) != 1 || claimed[0] != "config" {
		t.Fatalf("no single frontend claims %s (claimed by %v); a Twig template is left unparsed", filepath.Base(path), claimed)
	}
}

// A Grails template carries markup writes like any JSP, and until a frontend claimed
// the .gsp extension the file fell through every language filter: it contributed no
// module, and a markup write inside it produced no node for any binding to label.
func TestGSPFilesAreClaimedByTheConfigFrontend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "_edit.gsp")
	src := `<div class="error message">${flash.message}</div>
<div class="jobListTitle">${params.name}</div>
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	entries := treesitter.ListAllFiles(dir)
	class := frontend.ClassifyEntries(entries)
	var claimed []string
	for _, lg := range frontend.Languages() {
		for _, f := range lg.FilesFor(entries, class) {
			if f == path {
				claimed = append(claimed, lg.Name)
			}
		}
	}
	if len(claimed) != 1 || claimed[0] != "config" {
		t.Fatalf("no single frontend claims %s (claimed by %v); a Grails template is left unparsed", filepath.Base(path), claimed)
	}
}

// A `.cairo` file has to be claimed by a registered frontend and parsed into
// calls. Until one was, Starknet contracts fell through every language filter —
// the campaign evidence for the account-signature family counted 43 unread
// `.cairo` files in one repository — so nothing in them could be labelled a
// source or a sink and no rule could reach them. The corpus is Cairo 0
// (`func`/`end`, `@storage_var`), which is what the first block pins; the second
// pins Cairo 1 (`fn`, `#[attribute]`), which the same grammar reads.
func TestCairoFilesAreClaimedAndParsedIntoCalls(t *testing.T) {
	dir := t.TempDir()
	src := `%lang starknet
from starkware.starknet.common.syscalls import call_contract

@storage_var
func Balance(owner : felt) -> (res : felt):
end

namespace Account:
    func is_valid_signature(hash : felt, signature_len : felt, signature : felt*) -> (is_valid : felt):
        let (local sig_r : felt) = signature[0]
        let (_public_key) = Balance.read()
        return (is_valid=TRUE)
    end

    @view
    func execute{
            syscall_ptr : felt*,
            range_check_ptr,
        }(calldata_len : felt, calldata : felt*, nonce : felt):
        let (tx_info) = get_tx_info()
        let (local ecdsa_ptr : felt*) = alloc()
        let (is_valid) = is_valid_signature(tx_info.transaction_hash, tx_info.signature_len, tx_info.signature)
        assert is_valid = TRUE
        let (response) = call_contract(contract_address=tx_info.account_address, function_selector=nonce, calldata=calldata, calldata_len=calldata_len)
        Balance.write(nonce)
        return (response=response)
    end
end
`
	path := filepath.Join(dir, "library.cairo")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	entries := treesitter.ListAllFiles(dir)
	class := frontend.ClassifyEntries(entries)
	var claimed []string
	var lang frontend.Language
	for _, lg := range frontend.Languages() {
		for _, f := range lg.FilesFor(entries, class) {
			if f == path {
				claimed = append(claimed, lg.Name)
				lang = lg
			}
		}
	}
	if len(claimed) != 1 || claimed[0] != "cairo" {
		t.Fatalf("no single frontend claims %s (claimed by %v); a .cairo file is left unparsed", filepath.Base(path), claimed)
	}

	prog, err := lang.Extract([]string{path}, dir)
	if err != nil {
		t.Fatalf("%s frontend: %v", lang.Name, err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("%s frontend produced %d modules, want 1", lang.Name, len(prog.Modules))
	}
	mod := prog.Modules[0]
	var sawImport bool
	for _, im := range mod.Imports {
		if im.Local == "call_contract" && im.Module == "starkware.starknet.common.syscalls" {
			sawImport = true
		}
	}
	if !sawImport {
		t.Errorf("%s frontend recorded no import of call_contract; got %v", lang.Name, mod.Imports)
	}

	seen := map[string]bool{}
	funcs := map[string]nir.FuncDef{}
	var expr func(nir.Expr)
	var body func([]nir.Stmt)
	expr = func(e nir.Expr) {
		switch x := e.(type) {
		case nir.Call:
			seen["call "+x.Path] = true
			for _, a := range x.Args {
				expr(a)
			}
		case nir.Attr:
			seen["attr "+x.Path] = true
			expr(x.Base)
		case nir.Index:
			seen["index "+x.Path] = true
		case nir.Pair:
			expr(x.Value)
		}
	}
	body = func(sts []nir.Stmt) {
		for _, st := range sts {
			switch s := st.(type) {
			case nir.ClassDef:
				body(s.Body)
			case nir.FuncDef:
				funcs[s.Name] = s
				body(s.Body)
			case nir.Assign:
				expr(s.Value)
			case nir.ExprStmt:
				expr(s.Value)
			case nir.Return:
				expr(s.Value)
			}
		}
	}
	body(mod.Body)

	for _, want := range []string{
		"call Balance.read", "call Balance.write", "call call_contract",
		"call is_valid_signature", "call get_tx_info", "call alloc",
		"attr tx_info.transaction_hash", "attr tx_info.signature", "index signature",
	} {
		if !seen[want] {
			t.Errorf("%s frontend did not produce %q; got %v", lang.Name, want, seen)
		}
	}

	// The entry point's shape is what a binding names: its declared parameters,
	// the decorator it carries, and the storage accessor it writes through.
	exec, ok := funcs["execute"]
	if !ok {
		t.Fatalf("%s frontend produced no execute function; got %v", lang.Name, funcNames(funcs))
	}
	if want := []string{"calldata_len", "calldata", "nonce"}; !sameStrings(exec.Params, want) {
		t.Errorf("execute params = %v, want %v", exec.Params, want)
	}
	if len(exec.ParamEntries) != len(exec.Params) {
		t.Errorf("execute ParamEntries = %d, want one per parameter (%d)", len(exec.ParamEntries), len(exec.Params))
	} else {
		for i, pe := range exec.ParamEntries {
			if !containsString(pe.Tokens, "decorator:view") {
				t.Errorf("execute ParamEntries[%d].Tokens = %v, want the function's own decorator", i, pe.Tokens)
			}
		}
	}
	if !containsString(exec.ContextTokens, "implicit:syscall_ptr") {
		t.Errorf("execute ContextTokens = %v, want the implicit builtin segment recorded", exec.ContextTokens)
	}
	if !containsString(exec.ContextTokens, "lang=cairo") {
		t.Errorf("execute ContextTokens = %v, want lang=cairo", exec.ContextTokens)
	}
	// A signature check that does not reach the call it guards is still a call
	// site the graph must carry, and the underscore convention marks privacy.
	if priv, ok := funcs["_public_key"]; ok {
		t.Errorf("_public_key lowered as a function; underscore names are locals, got %+v", priv)
	}
	if sv, ok := funcs["Balance"]; !ok || !containsString(sv.Decorators, "storage_var") {
		t.Errorf("storage var Balance decorators = %v, want storage_var", sv.Decorators)
	}
}

// Cairo 1 is the same language after the 2023 migration: `fn` instead of `func`,
// `#[attribute]` instead of `@decorator`, blocks instead of `:`/`end`. The
// grammar reads both so one binding set labels either, and this pins the parts
// of the modern dialect a binding names: the attribute on the module, the
// storage struct's members, and `self.storage.write(...)` calls.
func TestCairoOneFilesAreClaimedAndParsedIntoCalls(t *testing.T) {
	dir := t.TempDir()
	src := `use starknet::get_caller_address;

#[starknet::component]
pub mod VaultComponent {
    #[storage]
    pub struct Storage {
        pub vault_balance: u256,
    }

    pub impl VaultImpl<TContractState> of interface::IVault<ComponentState<TContractState>> {
        pub fn withdraw(ref self: ComponentState<TContractState>, owner: ContractAddress, amount: u256) -> bool {
            let caller = get_caller_address();
            self.vault_balance.write(self.vault_balance.read() - amount);
            true
        }
    }
}
`
	path := filepath.Join(dir, "vault.cairo")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	entries := treesitter.ListAllFiles(dir)
	class := frontend.ClassifyEntries(entries)
	var claimed []string
	var lang frontend.Language
	for _, lg := range frontend.Languages() {
		for _, f := range lg.FilesFor(entries, class) {
			if f == path {
				claimed = append(claimed, lg.Name)
				lang = lg
			}
		}
	}
	if len(claimed) != 1 || claimed[0] != "cairo" {
		t.Fatalf("no single frontend claims %s (claimed by %v)", filepath.Base(path), claimed)
	}

	prog, err := lang.Extract([]string{path}, dir)
	if err != nil {
		t.Fatalf("%s frontend: %v", lang.Name, err)
	}

	calls := map[string]bool{}
	var classes []nir.ClassDef
	var funcs []nir.FuncDef
	var walk func([]nir.Stmt)
	walk = func(sts []nir.Stmt) {
		for _, st := range sts {
			switch s := st.(type) {
			case nir.ClassDef:
				classes = append(classes, s)
				walk(s.Body)
			case nir.FuncDef:
				funcs = append(funcs, s)
				walk(s.Body)
			case nir.Assign:
				if s.Value != nil {
					collectCalls(s.Value, calls)
				}
			case nir.ExprStmt:
				collectCalls(s.Value, calls)
			case nir.Return:
				collectCalls(s.Value, calls)
			case nir.Block:
				walk(s.Stmts)
			}
		}
	}
	walk(prog.Modules[0].Body)

	var vault nir.ClassDef
	for _, cd := range classes {
		if cd.Name == "Storage" {
			vault = cd
		}
	}
	if vault.Name != "Storage" {
		t.Fatalf("no Storage struct lowered; classes = %v", classNames(classes))
	}
	if !containsString(vault.Members, "vault_balance") {
		t.Errorf("Storage members = %v, want vault_balance", vault.Members)
	}
	if !containsString(vault.Annotations, "storage") {
		t.Errorf("Storage annotations = %v, want the #[storage] attribute", vault.Annotations)
	}
	var modClass nir.ClassDef
	for _, cd := range classes {
		if cd.Name == "VaultComponent" {
			modClass = cd
		}
	}
	if modClass.Name != "VaultComponent" || !containsString(modClass.Annotations, "starknet.component") {
		t.Errorf("VaultComponent annotations = %v, want starknet.component", modClass.Annotations)
	}
	var withdraw *nir.FuncDef
	for i := range funcs {
		if funcs[i].Name == "withdraw" {
			withdraw = &funcs[i]
		}
	}
	if withdraw == nil {
		t.Fatalf("no withdraw function lowered; funcs = %v", funcNames2(funcs))
	}
	// `self` is the receiver, not a parameter the caller supplies.
	if want := []string{"owner", "amount"}; !sameStrings(withdraw.Params, want) {
		t.Errorf("withdraw params = %v, want %v (self is the receiver)", withdraw.Params, want)
	}
	if !withdraw.Exported {
		t.Errorf("withdraw Exported = false; a pub fn is part of the public surface")
	}
	for _, want := range []string{"self.vault_balance.write", "self.vault_balance.read", "get_caller_address"} {
		if !calls[want] {
			t.Errorf("%s frontend did not produce call %q; got %v", lang.Name, want, calls)
		}
	}
}

func collectCalls(e nir.Expr, into map[string]bool) {
	switch x := e.(type) {
	case nir.Call:
		into[x.Path] = true
		for _, a := range x.Args {
			collectCalls(a, into)
		}
	case nir.Seq:
		for _, p := range x.Parts {
			collectCalls(p, into)
		}
	case nir.BinOp:
		collectCalls(x.Left, into)
		collectCalls(x.Right, into)
	case nir.Pair:
		collectCalls(x.Value, into)
	case nir.Attr:
		collectCalls(x.Base, into)
	case nir.Index:
		collectCalls(x.Base, into)
	case nir.Thru:
		collectCalls(x.Inner, into)
	}
}

func containsString(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func funcNames(m map[string]nir.FuncDef) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func funcNames2(fs []nir.FuncDef) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Name)
	}
	return out
}

func classNames(cs []nir.ClassDef) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}
