package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// bladeLowerFile extracts and lowers one Blade template at the path it is written to
// inside the target, since a view's path is what names the flow it belongs to.
func bladeLowerFile(t *testing.T, rel, src string) usg.Store {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractPHP([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// bladeCalls returns every lowered call as "callee_path@loc".
func bladeCalls(t *testing.T, g usg.Store) []string {
	t.Helper()
	ids, err := g.NodesOfType("code.Call")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, id := range ids {
		n, _, err := g.GetNode(id)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, n.Prop("callee_path")+"@"+n.Loc)
	}
	return out
}

func bladeHasCall(got []string, want string) bool {
	for _, g := range got {
		if g == want {
			return true
		}
	}
	return false
}

const pixelfedResetView = `@extends('layouts.app')

@section('content')
<div class="card-body">
    {{-- the address is shown back only when the lookup failed: {{ ignored() }} --}}
    @if (session('status') || $errors->has('email'))
        <div class="alert alert-success">
            {{ session('status') ?? $errors->first('email') }}
        </div>
    @endif
    <span>@{{ clientSideTemplate }}</span>
    <form method="POST" action="{{ route('password.email') }}">
        @csrf
        <input id="email" type="email" name="email" placeholder="{{ __('E-Mail Address') }}" value="{{ old('email') }}" required>
    </form>
</div>
@endsection
`

// tree-sitter-php reads everything outside <?php … ?> as text, so a Blade view lowers to
// its module-context marker unless its echo tags are recovered — and those tags hold real
// PHP.
func TestBladeEchoTagsLowerAsCalls(t *testing.T) {
	const view = "resources/views/auth/passwords/email.blade.php"
	got := bladeCalls(t, bladeLowerFile(t, view, pixelfedResetView))
	for _, want := range []string{
		"route@" + view + ":12",        // the tag's own line, not the synthetic source's
		"__@" + view + ":14",           // two tags on one line, both lowered
		"old@" + view + ":14",          //
		"session@" + view + ":8",       // inside a @if, which is text to the PHP grammar
		"$errors.first@" + view + ":8", // a method call on a view variable
	} {
		if !bladeHasCall(got, want) {
			t.Errorf("missing call %q; got %v", want, got)
		}
	}
	// A Blade comment holds no expression, and @{{ … }} is emitted verbatim for a
	// client-side engine: neither may reach the graph.
	if bladeHasCall(got, "ignored@"+view+":5") {
		t.Errorf("lowered a call out of a Blade comment; got %v", got)
	}
}

// CVE-2023-0901: pixelfed's forgot-password view repopulated the submitted address from
// Laravel's flashed previous input, which the framework flashes only on the
// ValidationException branch an unknown account takes. The response therefore differs by
// account existence with no status code and no message written anywhere in the
// application, so the smell has to come from the echo itself.
func TestBladeRecoveryViewFlashedInputIsUserEnumSmell(t *testing.T) {
	const view = "resources/views/auth/passwords/email.blade.php"
	got := bladeCalls(t, bladeLowerFile(t, view, pixelfedResetView))
	if !bladeHasCall(got, "analysis.smell.user_enum@"+view+":14") {
		t.Fatalf("no account-enumeration smell for the vulnerable view; got %v", got)
	}
}

// The fix drops the value attribute, so the field is blank either way.
func TestBladeRecoveryViewWithoutFlashedInputIsClean(t *testing.T) {
	const view = "resources/views/auth/passwords/email.blade.php"
	fixed := `@extends('layouts.app')
@section('content')
<form method="POST" action="{{ route('password.email') }}">
    @csrf
    <input id="email" type="email" name="email" placeholder="{{ __('E-Mail Address') }}" required>
</form>
@endsection
`
	got := bladeCalls(t, bladeLowerFile(t, view, fixed))
	for _, c := range got {
		if len(c) >= len("analysis.smell.user_enum") && c[:len("analysis.smell.user_enum")] == "analysis.smell.user_enum" {
			t.Fatalf("fixed view still reports an account-enumeration smell: %v", got)
		}
	}
	if !bladeHasCall(got, "route@"+view+":3") {
		t.Fatalf("fixed view lost its other calls; got %v", got)
	}
}

// A plain .php file is not a Blade template: its braces are PHP, and nothing in it may
// be re-read as an echo tag.
func TestNonBladePhpFileIsUntouched(t *testing.T) {
	g := bladeLowerFile(t, "app/Http/Controllers/PasswordController.php", `<?php
class PasswordController {
    public function form() {
        $data = ['email' => old('email')];
        return $data;
    }
}
`)
	got := bladeCalls(t, g)
	if !bladeHasCall(got, "old@app/Http/Controllers/PasswordController.php:4") {
		t.Fatalf("plain PHP lowers its own calls; got %v", got)
	}
}
