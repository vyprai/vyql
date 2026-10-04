package lowering

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/usg"
)

// railsViewProgram writes a controller and the view its action renders, the Rails layout
// convention naming the view after the controller (`app/views/links/show.html.erb` is what
// LinksController#show renders). The controller parks request data in an instance variable
// and the template reads it back — the only thing that joins the two is the framework
// copying the controller's instance variables into the view, so the write and the read
// share no lexical scope, no call edge and no file.
func railsViewProgram(t *testing.T) (dir, ctrl, view string) {
	t.Helper()
	dir = t.TempDir()
	ctrl = filepath.Join(dir, "app", "controllers", "links_controller.rb")
	view = filepath.Join(dir, "app", "views", "links", "show.html.erb")
	for p, src := range map[string]string{
		ctrl: `class LinksController < ApplicationController
  def show(q)
    @target_url = q[:url]
  end
end
`,
		view: `<%= link_to("Home", @target_url) %>
`,
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, ctrl, view
}

// viewIvarArg returns the view's link_to argument node that the `@target_url` read feeds —
// the argument slot at the template's line whose value is a name read.
func viewIvarArg(t *testing.T, g usg.Store, viewRel string) string {
	t.Helper()
	ids, err := g.NodesOfType("code.Arg")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		n, ok, err := g.GetNode(id)
		if err != nil || !ok {
			continue
		}
		if n.Loc == viewRel+":1" && n.Prop("vkind") == "Name" {
			return id
		}
	}
	t.Fatalf("no name-valued argument at %s:1", viewRel)
	return ""
}

// A controller's instance-variable write must reach the view that renders its action: the
// template's `@target_url` is storage the controller filled, so the value it holds is the
// one `q[:url]` produced. Before the view was lowered as a member of its controller, the
// template's read was a bare name in an anonymous module and the path dead-ended between
// the two files.
func TestRailsControllerIvarReachesTheViewThatRendersItsAction(t *testing.T) {
	dir, ctrl, view := railsViewProgram(t)
	prog, err := treesitter.ExtractRuby([]string{ctrl, view}, dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	reachable, err := usg.BFS(g, findNodeID(t, g, "code.Param", "name", "q", "func", "show"), "FLOWS", 60)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[viewIvarArg(t, g, "app/views/links/show.html.erb#erb.rb")] {
		t.Fatalf("the controller's @target_url write did not reach the view's link_to argument: " +
			"the template's read shares no node with the controller's field slot")
	}
}

// The join is the controller's own storage, not a global named `@target_url`: a view whose
// controller never declares the instance variable keeps reading a name nothing filled, and
// another controller's tainted `@target_url` must not reach it either.
func TestRailsViewIvarDoesNotReachAnotherControllersView(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		filepath.Join(dir, "app", "controllers", "links_controller.rb"): `class LinksController < ApplicationController
  def show(q)
    @target_url = q[:url]
  end
end
`,
		filepath.Join(dir, "app", "controllers", "other_controller.rb"): `class OtherController < ApplicationController
  def show
  end
end
`,
		filepath.Join(dir, "app", "views", "other", "show.html.erb"): `<%= link_to("Home", @target_url) %>
`,
	}
	for p, src := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var files_ []string
	for p := range files {
		files_ = append(files_, p)
	}
	prog, err := treesitter.ExtractRuby(files_, dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	reachable, err := usg.BFS(g, findNodeID(t, g, "code.Param", "name", "q", "func", "show"), "FLOWS", 60)
	if err != nil {
		t.Fatal(err)
	}
	if reachable[viewIvarArg(t, g, "app/views/other/show.html.erb#erb.rb")] {
		t.Fatalf("LinksController's @target_url reached OtherController's view, whose controller " +
			"declares no such instance variable")
	}
}
