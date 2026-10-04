package treesitter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// The controller a template renders from is spelled by the framework's layout convention,
// which is the only thing that names the pair: nested directories are the controller's
// namespace, snake_case segments its class name, and the `Controller` suffix is Rails' own.
func TestRBViewControllerClass(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"app/views/links/show.html.erb#erb.rb", "LinksController"},
		{"app/views/admin/links/show.html.erb#erb.rb", "Admin::LinksController"},
		{"app/views/admin_links/user_profiles/index.html.erb#erb.rb", "AdminLinks::UserProfilesController"},
		{"engines/blog/app/views/posts/index.html.erb#erb.rb", "PostsController"},
		{"src/app/views/v2_reports/show.text.erb#erb.rb", "V2ReportsController"},
		// outside the layout there is no controller to name
		{"config/initializers/banner.erb#erb.rb", ""},
		{"app/views/show.html.erb#erb.rb", ""},
		{"app/views/layouts/application.html.erb#erb.rb", "LayoutsController"},
	} {
		if got := rbViewControllerClass(tc.path); got != tc.want {
			t.Errorf("rbViewControllerClass(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// A template inside the layout lowers its statements as a method of the controller that
// renders it (Recv, the spelling of a method declared outside its type), so the `@ivar` it
// reads is a member of that class rather than a bare name of an anonymous module. A
// template outside the layout keeps its statements at the top level, where they always
// were — nothing names a controller for it.
func TestERBTemplateLowersAsAMethodOfItsController(t *testing.T) {
	dir := t.TempDir()
	inLayout := filepath.Join(dir, "app", "views", "links", "show.html.erb")
	outside := filepath.Join(dir, "config", "banner.erb")
	files := map[string]string{
		inLayout: "<%= link_to(\"Home\", @target_url) %>\n",
		outside:  "<%= banner_text %>\n",
	}
	for p, src := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prog, err := ExtractRuby([]string{inLayout, outside}, dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	var inLayoutFn, outsideFn *nir.FuncDef
	for _, m := range prog.Modules {
		for _, s := range m.Body {
			fn, ok := s.(nir.FuncDef)
			if !ok {
				continue
			}
			switch m.File {
			case "app/views/links/show.html.erb#erb.rb":
				inLayoutFn = &fn
			case "config/banner.erb#erb.rb":
				outsideFn = &fn
			}
		}
	}
	if inLayoutFn == nil {
		t.Fatalf("the layout's template lowered no method of its controller; bodies: %#v", prog.Modules)
	}
	if inLayoutFn.Recv != "LinksController" {
		t.Errorf("template method's receiver = %q, want LinksController", inLayoutFn.Recv)
	}
	if inLayoutFn.Name != "__view_show" {
		t.Errorf("template method's name = %q, want __view_show", inLayoutFn.Name)
	}
	if outsideFn != nil {
		t.Errorf("a template outside the layout lowered as a method (%q of %q); it has no controller",
			outsideFn.Name, outsideFn.Recv)
	}
}
