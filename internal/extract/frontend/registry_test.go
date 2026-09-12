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
