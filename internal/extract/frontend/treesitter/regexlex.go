package treesitter

// Lexing helpers shared by the frontends that scan regex literals out of raw source text.
//
// They live here rather than in one language's file because two frontends need them, and a
// frontend must not depend on another frontend: the languages are siblings, and a helper reached
// across that line couples two extractors that should be independently replaceable.

// isEscaped reports whether the byte at i is preceded by an odd number of backslashes, and is
// therefore escaped rather than syntactically significant.
func isEscaped(s string, i int) bool {
	esc := false
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		esc = !esc
	}
	return esc
}
