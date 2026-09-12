package extract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// proseDoc is documentation text of the kind a `.pl` name carries in the wild —
// README.pl is the Polish README by convention — including the tokens a shape
// check could mistake for code (`%s` placeholders, e-mail addresses, `->` in
// URLs), which is why the claim asks for Perl's own constructs and not for loose
// code-shaped tokens.
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

// writeProse writes size bytes of proseDoc content at rel and returns the path.
func writeProse(t *testing.T, dir, rel string, size int) string {
	t.Helper()
	var b strings.Builder
	for b.Len() < size {
		b.WriteString(proseDoc)
	}
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(b.String()[:size]), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A `.pl` file made of no Perl construct is documentation, not source. Reading
// it as Perl was anything but free: the parse of a 338KB README peaked near 6GB
// of resident memory, so a clone carrying one documentation README failed every
// bounded scan at its ceiling, before the first rule ran. The file must leave
// extraction unparsed — counted in the languages that do read it, never
// pretended into a module no frontend built.
//
// The fixtures are larger than perlSmallFileMax deliberately: ReadsAsPerl
// claims a small file outright (the amplification the check guards against
// needs bulk prose; a snippet cannot carry it), so only an above-threshold
// file exercises the marker test that separates documentation from source.
func TestProseNamedPlIsNeverLoweredAsPerl(t *testing.T) {
	dir := t.TempDir()
	writeProse(t, dir, "README.pl", 96<<10)
	writeProse(t, dir, filepath.Join("doc", "README.pl"), 96<<10)

	prog, _, _, stats, err := AllIn([]string{dir}, nil, nil)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, m := range prog.Modules {
		if strings.HasSuffix(m.File, ".pl") {
			t.Errorf("prose named %s was lowered as a module; no frontend should read it as source", m.File)
		}
	}
	if got := stats.Files["perl"]; got != 0 {
		t.Errorf("perl claimed %d prose file(s); the claim must not read documentation as source", got)
	}
}
