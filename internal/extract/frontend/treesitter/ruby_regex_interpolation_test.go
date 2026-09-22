package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/nir"
)

// rubyCallArgs collects the constant arguments of every call with the given
// path, anywhere in the program — the shape of both the analysis facts the
// regex observation emits and the __regex.match synthesis the regex lowering
// performs.
func rubyCallArgs(prog nir.Program, path string) []string {
	var out []string
	var walkExpr func(e nir.Expr)
	var walkStmt func(s nir.Stmt)
	walkStmt = func(s nir.Stmt) {
		switch v := s.(type) {
		case nir.ExprStmt:
			walkExpr(v.Value)
		case nir.Assign:
			walkExpr(v.Value)
		case nir.Return:
			walkExpr(v.Value)
		case nir.ClassDef:
			for _, b := range v.Body {
				walkStmt(b)
			}
		case nir.FuncDef:
			for _, b := range v.Body {
				walkStmt(b)
			}
		case nir.Block:
			for _, b := range v.Stmts {
				walkStmt(b)
			}
		case nir.If:
			for _, b := range v.Then {
				walkStmt(b)
			}
			for _, b := range v.Else {
				walkStmt(b)
			}
		}
	}
	walkExpr = func(e nir.Expr) {
		switch v := e.(type) {
		case nir.Call:
			if v.Path == path {
				for _, a := range v.Args {
					if c, ok := a.(nir.Const); ok {
						out = append(out, c.Value)
					}
				}
			}
			walkExpr(v.Callee)
			for _, a := range v.Args {
				walkExpr(a)
			}
		case nir.Attr:
			walkExpr(v.Base)
		case nir.Format:
			for _, p := range v.Parts {
				walkExpr(p)
			}
		}
	}
	for _, m := range prog.Modules {
		for _, s := range m.Body {
			walkStmt(s)
		}
	}
	return out
}

func extractRubySource(t *testing.T, src string) nir.Program {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "template.rb")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractRuby([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	return prog
}

// A regex literal whose source text interpolates is judged on the pattern the
// interpolations assemble, so long as every fragment names a string value the
// file itself defines. The fragments fold in document order — the class of a
// name character is a concatenation of literals, the character run wraps it,
// and the VARNAME literal interpolates the run — and the assembled pattern is
// the one the shared ambiguity analysis reads.
func TestRubyInterpolatedRegexLiteralIsAnalysed(t *testing.T) {
	prog := extractRubySource(t, `module Addressable
  class Template
    variable_char_class =
      "a-zA-Z" + "0-9" + '_'

    var_char =
      "(?:(?:[#{variable_char_class}]|%[a-fA-F0-9][a-fA-F0-9])+)"
    variable =
      "(?:#{var_char}(?:\\.?#{var_char})*)"
    VARNAME =
      /^#{variable}$/

    def match(uri)
      VARNAME.match(uri)
    end
  end
end
`)
	obs := rubyCallArgs(prog, "analysis.dos.catastrophic_regex")
	if len(obs) != 1 {
		t.Fatalf("expected exactly one catastrophic-regex observation, got %d (%q)", len(obs), obs)
	}
	if want := "(?:(?:(?:[a-zA-Z0-9_]|%[a-fA-F0-9][a-fA-F0-9])+)(?:\\.?(?:(?:[a-zA-Z0-9_]|%[a-fA-F0-9][a-fA-F0-9])+))*)"; !strings.Contains(obs[0], want) {
		t.Errorf("observation carries %q, which does not hold the assembled pattern %q", obs[0], want)
	}
	synth := rubyCallArgs(prog, "__regex.match")
	if len(synth) != 1 {
		t.Fatalf("expected exactly one __regex.match synthesis, got %d (%q)", len(synth), synth)
	}
	if !strings.Contains(synth[0], "(?:(?:(?:[a-zA-Z0-9_]|%[a-fA-F0-9][a-fA-F0-9])+)(?:\\.?") {
		t.Errorf("synthesis carries %q, which does not hold the assembled pattern", synth[0])
	}
}

// The same constants with the inner run in an atomic group — CVE-2021-32740's
// fix — assemble a pattern the analysis must read as linear: an atomic group
// gives nothing back, so the outer loop cannot re-split the run.
func TestRubyInterpolatedRegexLiteralWithAtomicGroupStaysClean(t *testing.T) {
	prog := extractRubySource(t, `module Addressable
  class Template
    variable_char_class =
      "a-zA-Z" + "0-9" + '_'

    var_char =
      "(?>(?:[#{variable_char_class}]|%[a-fA-F0-9][a-fA-F0-9])+)"
    variable =
      "(?:#{var_char}(?:\\.?#{var_char})*)"
    VARNAME =
      /^#{variable}$/

    def match(uri)
      VARNAME.match(uri)
    end
  end
end
`)
	if obs := rubyCallArgs(prog, "analysis.dos.catastrophic_regex"); len(obs) != 0 {
		t.Errorf("atomic-group spelling reported %q, want none", obs)
	}
	if synth := rubyCallArgs(prog, "__regex.match"); len(synth) != 0 {
		t.Errorf("atomic-group spelling synthesised %q, want none", synth)
	}
}

// A fragment naming nothing the file defines — a parameter, a call — leaves the
// literal unanalysed, exactly as it always was: the fragment's quantifiers are
// not in the literal, and guessing at them would judge a pattern that does not
// exist.
func TestRubyInterpolatedRegexLiteralWithUnresolvedFragmentIsSkipped(t *testing.T) {
	prog := extractRubySource(t, `class Template
  suffix = "0-9"

  def match(uri)
    /^#{uri}[#{suffix}]+(,[#{suffix}]+)*$/.match(uri)
  end
end
`)
	if obs := rubyCallArgs(prog, "analysis.dos.catastrophic_regex"); len(obs) != 0 {
		t.Errorf("unresolved fragment reported %q, want none", obs)
	}
	if synth := rubyCallArgs(prog, "__regex.match"); len(synth) != 0 {
		t.Errorf("unresolved fragment synthesised %q, want none", synth)
	}
}
