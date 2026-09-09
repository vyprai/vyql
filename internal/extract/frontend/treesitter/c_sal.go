package treesitter

// SAL — Microsoft's Source-code Annotation Language — decorates C/C++
// declarations with macros that <sal.h> expands to nothing: `_In_`,
// `_Out_writes_all_(n)`, `_Success_(return != FALSE)`, `__drv_freesMem(Mem)`.
// tree-sitter has no preprocessor, so it reads an annotation as a type or a
// declarator and mis-parses the declaration built around it. An annotated
// parameter loses its name to the annotation (`_In_ PCWSTR Name` yields the
// parameter "PCWSTR"), and an annotation standing before the return type
// (`_Success_(return != FALSE)` reads as a function declarator) collapses the
// whole definition into one ERROR node — the function, its params, its
// exported mark and its calls all disappear from the module.
//
// Neutralising the annotations the way <sal.h> does, before the parse,
// restores the declaration underneath them.

// ccSALPrefixLegacy is the SAL1/driver annotation family, which is spelled
// with two leading underscores and a lowercase name and so does not match the
// `_Uppercase…_` shape below.
const ccSALPrefixLegacy = "__drv_"

// ccIsSALAnnotation reports whether an identifier token is a SAL annotation.
// SAL2 spells every annotation with a leading underscore, an uppercase first
// letter and a trailing underscore (`_In_`, `_Out_writes_bytes_`, `_When_`),
// a shape no C or C++ keyword shares: the implementation-reserved names that
// are keywords (`_Bool`, `_Atomic`, `_Static_assert`, `_Pragma`, `_Generic`)
// all end in a letter, and the compiler builtins (`__func__`, `__attribute__`,
// `__int64`) have a lowercase or underscore second character.
func ccIsSALAnnotation(tok []byte) bool {
	if len(tok) >= len(ccSALPrefixLegacy) && string(tok[:len(ccSALPrefixLegacy)]) == ccSALPrefixLegacy {
		return true
	}
	if len(tok) < 4 || tok[0] != '_' || tok[len(tok)-1] != '_' {
		return false
	}
	return tok[1] >= 'A' && tok[1] <= 'Z'
}

// ccStripSAL blanks every SAL annotation — and the parenthesised argument list
// written immediately after it, when it has one — with spaces. Newlines are
// kept, so every byte offset, row and column in the returned source still
// addresses the same place in the file on disk: locations stay right and the
// raw-text observations that scan c.src keep seeing the original layout.
//
// Preprocessor directive lines are left alone: `#ifndef _MY_HEADER_H_` names an
// include guard that happens to share SAL's shape, and `#define _In_` is where
// a project defines the annotations in the first place.
func ccStripSAL(src []byte) []byte {
	spans := ccSALSpans(src)
	if len(spans) == 0 {
		return src
	}
	out := make([]byte, len(src))
	copy(out, src)
	for _, sp := range spans {
		for i := sp[0]; i < sp[1]; i++ {
			if out[i] != '\n' && out[i] != '\r' {
				out[i] = ' '
			}
		}
	}
	return out
}

// ccSALSpans returns the [start,end) byte ranges of the SAL annotations in src,
// skipping comments, string and character literals, and preprocessor lines.
func ccSALSpans(src []byte) [][2]int {
	var spans [][2]int
	atLineStart := true
	for i := 0; i < len(src); {
		switch {
		case src[i] == '\n':
			atLineStart = true
			i++
		case src[i] == ' ' || src[i] == '\t' || src[i] == '\r':
			i++
		case src[i] == '#' && atLineStart:
			i = ccSkipDirective(src, i)
			atLineStart = true
		case src[i] == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case src[i] == '/' && i+1 < len(src) && src[i+1] == '*':
			// a comment is whitespace to the preprocessor, so `/* c */ #define X`
			// is still a directive line
			i = ccSkipBlockComment(src, i)
		case src[i] == '"' || src[i] == '\'':
			atLineStart = false
			i = ccSkipQuoted(src, i)
		case ccNameStartByte(src[i]):
			atLineStart = false
			start := i
			for i < len(src) && (ccNameStartByte(src[i]) || (src[i] >= '0' && src[i] <= '9')) {
				i++
			}
			if !ccIsSALAnnotation(src[start:i]) {
				continue
			}
			end := i
			// Only an argument list written flush against the annotation belongs
			// to it; a space before `(` is some other expression's parenthesis.
			if i < len(src) && src[i] == '(' {
				end = ccSkipParens(src, i)
				i = end
			}
			spans = append(spans, [2]int{start, end})
		default:
			atLineStart = false
			i++
		}
	}
	return spans
}

// ccSkipDirective returns the offset just past a preprocessor line, following
// backslash line continuations.
func ccSkipDirective(src []byte, i int) int {
	for i < len(src) {
		if src[i] == '\\' && i+1 < len(src) {
			if src[i+1] == '\n' {
				i += 2
				continue
			}
			if src[i+1] == '\r' && i+2 < len(src) && src[i+2] == '\n' {
				i += 3
				continue
			}
		}
		if src[i] == '\n' {
			return i + 1
		}
		i++
	}
	return i
}

func ccSkipBlockComment(src []byte, i int) int {
	for i += 2; i+1 < len(src); i++ {
		if src[i] == '*' && src[i+1] == '/' {
			return i + 2
		}
	}
	return len(src)
}

// ccSkipQuoted returns the offset just past the string or character literal
// starting at src[i], honouring backslash escapes.
func ccSkipQuoted(src []byte, i int) int {
	quote := src[i]
	for i++; i < len(src); i++ {
		switch src[i] {
		case '\\':
			i++
		case quote:
			return i + 1
		case '\n':
			return i // unterminated: do not swallow the rest of the file
		}
	}
	return len(src)
}

// ccSkipParens returns the offset just past the parenthesis group starting at
// src[i], which the caller has checked is '('. An unbalanced group stops at the
// end of the file, which blanks no more than the annotation itself already was.
func ccSkipParens(src []byte, i int) int {
	depth := 0
	for i < len(src) {
		switch src[i] {
		case '"', '\'':
			i = ccSkipQuoted(src, i)
			continue
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
		i++
	}
	return len(src)
}
