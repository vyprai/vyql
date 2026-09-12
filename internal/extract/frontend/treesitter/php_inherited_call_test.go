package treesitter_test

import (
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// PHP dispatches a method call through the receiver's whole inheritance chain: a method
// declared only on a base class is the body a call on the subclass runs. The lowering's
// type-driven resolution stopped after one level of bases, so with the setter/getter pair a
// framework's validation plugin inherits from its base class -- and a plugin built two or more
// levels below the class that declares the pair -- the call fell through to the
// unique-method-name fallback. A tree that declares that name twice (an entity class and a
// validation class both declaring setValues) makes the fallback ambiguous, the call resolved
// to nothing, and the value a controller handed to the plugin never reached the inherited body.
func TestPHPMethodCallDispatchesToADeclarationTwoLevelsUpTheBaseChain(t *testing.T) {
	g := phpLowerFilesTyped(t, map[string]string{
		"validation.php": `<?php
class owa_validation_base {
    public $values;
    public function setValues($values) {
        $this->values = $values;
    }
    public function getValues() {
        return $this->values;
    }
}
class owa_entity {
    public $props;
    public function setValues($values) {
        $this->props = $values;
    }
    public function getByColumn($col, $value) {
        return $this->props;
    }
}
class owa_validation_middle extends owa_validation_base {
}
class owa_entityExistsValidation extends owa_validation_middle {
    public function validate() {
        $entity = new owa_entity();
        $entity->getByColumn('email_address', $this->getValues());
    }
}
function entry($email_address) {
    $v1 = new owa_entityExistsValidation();
    $v1->setValues(trim($email_address));
    return $v1->validate();
}`,
	}, nil)

	all, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var entryParam, setterParam, columnParam string
	for _, n := range all {
		if n.Type != "code.Param" {
			continue
		}
		switch {
		case n.Prop("name") == "$email_address":
			entryParam = n.ID
		case n.Prop("name") == "$values" && strings.HasSuffix(n.ID, "owa_validation_base.setValues#param#$values"):
			setterParam = n.ID
		case n.Prop("name") == "$value" && n.Prop("func") == "getByColumn":
			columnParam = n.ID
		}
	}
	if entryParam == "" || setterParam == "" || columnParam == "" {
		t.Fatalf("missing nodes: entry=%q setter=%q getByColumn=%q", entryParam, setterParam, columnParam)
	}
	reachable, err := usg.BFS(g, entryParam, "FLOWS", 80)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[setterParam] {
		t.Fatalf("the request value never reached the inherited setValues parameter")
	}
	// and back out again through the inherited getter, which is the half that carries the
	// value into the entity lookup the plugin performs
	returned, err := usg.BFS(g, setterParam, "FLOWS", 80)
	if err != nil {
		t.Fatal(err)
	}
	if !returned[columnParam] {
		t.Fatalf("the value stored by the inherited setter never reached getByColumn through the inherited getter")
	}
}
