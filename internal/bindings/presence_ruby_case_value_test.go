package bindings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// A method that dispatches on one value to pick another -- Foreman's action_permission
// override, `case params[:action] when 'play_roles' then :view; else super` -- has to be
// separable from the same override returning an execute verb, and the discriminator is
// the value each arm produces, not the labels it dispatches on (those are already
// context literals). This is the whole route a binding has: the function's context node,
// its own name, and the arm values the frontend pairs with their labels.
func TestPresenceRubyCaseArmValueSeparatesReadVerbFromExecuteVerb(t *testing.T) {
	sets, err := compileV2BindingsForTest(`
module bindings.ruby.test;

binding readVerbOverride {
  query pattern presenceNode where node.scope == "function" and node.context.language == "ruby" and node.context.functionName == "action_permission" and node.context.caseArm contains "=view"
  emit issue custom.AuthorizationReadVerb at node
}
`)
	if err != nil {
		t.Fatalf("compile read-verb flag: %v", err)
	}
	spec := specFromBindingSet(firstBindingSet(t, sets))

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
          when 'add_ansible_role', 'remove_ansible_role'
            :edit
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
	store, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := store.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]usg.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}

	marked := map[string]bool{}
	for _, m := range spec.presenceApplicator().Apply(store) {
		n := byID[m.NodeID]
		for _, tok := range strings.Split(n.Prop("str_args"), "\x00") {
			if tok == "name=action_permission" {
				marked["shipped"] = true
			}
			if tok == "name=corrected_action_permission" {
				marked["corrected"] = true
			}
		}
	}
	if !marked["shipped"] {
		t.Fatal("the override mapping an arm onto the read verb was not labelled")
	}
	if marked["corrected"] {
		t.Fatal("the override mapping its arms onto an execute verb was labelled")
	}
}
