package treesitter

import (
	"strings"
	"testing"
)

// Blanking the `ref` of a `ref partial struct` header must not disturb anything else:
// it keeps byte offsets and line numbers, leaves comments, string literals and the `ref`
// a parameter or a ref expression carries alone, and does not touch a declaration the
// grammar already reads (`partial ref struct`) or identifiers that merely contain the
// words.
func TestCsBlankRefPartialKeywordLeavesTheRestOfTheFileAlone(t *testing.T) {
	const src = `using System;

namespace Clients
{
    // ref partial struct is the spelling the docs recommend
    public ref partial struct TokenBuffer
    {
        private const string Note = "ref partial struct declaration";
        private const char Unit = 'r';

        public ref partial class Inner
        {
            public void Copy(ref int partials)
            {
                var headline = $"ref partial struct {Note}";
                var verbatim = @"ref partial struct";
                var interpVerbatim = @$"ref partial struct {Note}";
                var raw = """ref partial struct""";
                ref int slot = ref partials;
                var prose = "reference partiality";
                partials++;
            }
        }
    }

    public partial ref struct AlreadyParsed { }
}`
	got := string(csBlankRefPartialKeyword([]byte(src)))
	if len(got) != len(src) {
		t.Fatalf("length changed: %d vs %d", len(got), len(src))
	}
	if strings.Count(got, "\n") != strings.Count(src, "\n") {
		t.Errorf("line count changed")
	}
	for _, want := range []string{
		"// ref partial struct is the spelling the docs recommend",
		`"ref partial struct declaration"`,
		`$"ref partial struct {Note}"`,
		`@"ref partial struct"`,
		`@$"ref partial struct {Note}"`,
		`"""ref partial struct"""`,
		"ref int partials",
		"ref int slot = ref partials",
		"public partial ref struct AlreadyParsed { }",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("blanked source lost %q:\n%s", want, got)
		}
	}
	for _, want := range []string{
		"public     partial struct TokenBuffer",
		"public     partial class Inner",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("declaration header was not blanked, wanted %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "ref partial struct TokenBuffer") || strings.Contains(got, "ref partial class Inner") {
		t.Errorf("a declaration header kept its `ref`:\n%s", got)
	}
}

// A file that never carries the words pays nothing: no copy, same slice.
func TestCsBlankRefPartialKeywordSkipsFilesWithoutTheWords(t *testing.T) {
	src := []byte("class C { void M() { } }")
	if got := csBlankRefPartialKeyword(src); &got[0] != &src[0] {
		t.Fatal("file without `ref`/`partial` was copied")
	}
}
