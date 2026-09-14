package treesitter_test

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// A `$this->render($req)` call in a PHP class body dispatches on the implicit receiver's
// type, which is the enclosing class. The lowering keyed the implicit receiver's type under
// the language-independent `this` while the call site spells the receiver `$this`, so the
// lookup found no type and the call fell to the unique-method-name fallback — which refuses
// when a second unrelated class declares the same name. Here `render` is declared on the
// controller AND on the renderer it uses, so the unresolved call routed the argument
// nowhere and the callee's return value never reached the call site.
func TestPHPThisReceiverCallResolvesThroughTheImplicitReceiverType(t *testing.T) {
	g := phpLowerFilesTyped(t, map[string]string{
		"controller.php": `<?php
class template_renderer {
    public function render($tpl) {
        return $tpl;
    }
}
class page_controller {
    public function render($tpl) {
        return htmlspecialchars($tpl);
    }
    public function handle($req) {
        return $this->render($req);
    }
}`,
	}, nil)

	all, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var reqParam, ownParam, otherParam, handleReturn string
	for _, n := range all {
		switch {
		case n.Type == "code.Param":
			switch {
			case n.Prop("name") == "$req" && strings.HasSuffix(n.ID, "page_controller.handle#param#$req"):
				reqParam = n.ID
			case n.Prop("name") == "$tpl" && strings.HasSuffix(n.ID, "page_controller.render#param#$tpl"):
				ownParam = n.ID
			case n.Prop("name") == "$tpl" && strings.HasSuffix(n.ID, "template_renderer.render#param#$tpl"):
				otherParam = n.ID
			}
		case n.Type == "code.Return" && n.Prop("func") == "handle":
			handleReturn = n.ID
		}
	}
	if reqParam == "" || ownParam == "" || otherParam == "" || handleReturn == "" {
		t.Fatalf("missing nodes: req=%q own=%q other=%q handleReturn=%q", reqParam, ownParam, otherParam, handleReturn)
	}

	reachable, err := usg.BFS(g, reqParam, "FLOWS", 80)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[ownParam] {
		t.Fatalf("the argument never reached the controller's own render declaration")
	}
	if reachable[otherParam] {
		t.Fatalf("the argument reached the unrelated renderer declaration of the same name")
	}

	returned, err := usg.BFS(g, ownParam, "FLOWS", 80)
	if err != nil {
		t.Fatal(err)
	}
	if !returned[handleReturn] {
		t.Fatalf("the callee's return value never reached the call site in handle")
	}
}
