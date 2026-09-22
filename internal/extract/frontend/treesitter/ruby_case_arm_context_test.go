package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// rubyFunctionContexts returns the context token string of every
// analysis.function.context node, keyed by the method's own name.
func rubyFunctionContexts(t *testing.T, g usg.Store) map[string]string {
	t.Helper()
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		args := n.Prop("str_args")
		for _, tok := range strings.Split(args, "\x00") {
			if name, ok := strings.CutPrefix(tok, "name="); ok {
				out[name] = args
				break
			}
		}
	}
	return out
}

// A value-position `case` is how a Ruby method says "when the subject is this label,
// the value is that". Foreman's action_permission override is the shape: `case
// params[:action] when 'play_roles' then :view; else super`. The arm results reached
// the graph as Const nodes with no path and an empty Seq with path=__object_literal,
// so nothing paired a label with the value its arm produces -- the override that maps
// a non-read action onto the read verb and the one that maps it onto an execute verb
// produced the same facts. Both spellings below are real code: master's own file
// returns :edit for add_ansible_role and remove_ansible_role.
func TestRubyFunctionContextCarriesCaseArmValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts_controller_extensions.rb")
	src := []byte(`module ForemanAnsible
  module Api
    module V2
      module HostsControllerExtensions
        def action_permission
          case params[:action]
          when 'play_roles', 'multiple_play_roles'
            :view
          else
            super
          end
        end

        def corrected_action_permission
          case params[:action]
          when 'add_ansible_role', 'remove_ansible_role' then :edit
          else
            super
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
	contexts := rubyFunctionContexts(t, g)
	shipped, ok := contexts["action_permission"]
	if !ok {
		t.Fatalf("analysis.function.context for action_permission not found: %#v", contexts)
	}
	for _, want := range []string{
		"case_arm:play_roles=view",
		"case_arm:multiple_play_roles=view",
		"case_else=super",
	} {
		if !strings.Contains(shipped, want) {
			t.Fatalf("action_permission context missing %q; context=%q", want, shipped)
		}
	}
	corrected, ok := contexts["corrected_action_permission"]
	if !ok {
		t.Fatalf("analysis.function.context for corrected_action_permission not found: %#v", contexts)
	}
	for _, want := range []string{
		"case_arm:add_ansible_role=edit",
		"case_arm:remove_ansible_role=edit",
		"case_else=super",
	} {
		if !strings.Contains(corrected, want) {
			t.Fatalf("corrected_action_permission context missing %q; context=%q", want, corrected)
		}
	}
	if strings.Contains(corrected, "case_arm:") && strings.Contains(corrected, "=view") {
		t.Fatalf("corrected override carries the read verb; context=%q", corrected)
	}
}

// Only an arm whose value the file states as a literal -- or as `super`, the arm that
// defers to the superclass -- is paired with its label. An arm whose value is computed
// is a call the context already carries as call_path:, and pairing it with the label
// would assert the method returns the call's result, which the file does not say.
func TestRubyCaseArmValueRequiresALiteralArm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reporting.rb")
	src := []byte(`class Reporter
  def verb_for(action)
    case action
    when 'summary' then 'view'
    when 'run' then run_verb(action)
    when 'reset', 'clear' then
      log(action)
      :destroy
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
	contexts := rubyFunctionContexts(t, g)
	ctx, ok := contexts["verb_for"]
	if !ok {
		t.Fatalf("analysis.function.context for verb_for not found: %#v", contexts)
	}
	for _, want := range []string{
		"case_arm:summary=view",
		"case_arm:reset=destroy",
		"case_arm:clear=destroy",
	} {
		if !strings.Contains(ctx, want) {
			t.Fatalf("verb_for context missing %q; context=%q", want, ctx)
		}
	}
	if strings.Contains(ctx, "case_arm:run=") {
		t.Fatalf("computed arm value was paired with its label; context=%q", ctx)
	}
}
