package treesitter_test

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// The gap: taint is not carried through a Python object attribute store. `obj.attr = v` only
// rebinds the dotted name in the enclosing scope, so the later `obj.attr` read is a fresh Attr
// node joined to nothing — and a value that reaches a sink only by being parked on an object
// and read back off it is lost.

// pyCallReachesArgArg is pyParamReachesCallArg with the source moved from a parameter to a
// call: the shapes below start at a value the CONSTRUCTOR builds, which no parameter carries.
func pyCallReachesArg(t *testing.T, g usg.Store, fromCallee, callee, loc string) bool {
	t.Helper()
	reach, err := usg.BFS(g, pyOneNode(t, g, "code.Call", "callee_path", fromCallee), "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	call := pyOneNode(t, g, "code.Call", "callee_path", callee)
	n, ok, err := g.GetNode(call)
	if err != nil || !ok {
		t.Fatalf("call %s disappeared from the graph", callee)
	}
	if n.Loc != loc {
		t.Fatalf("call %s is at %s, want %s", callee, n.Loc, loc)
	}
	ins, err := g.InEdges(call, "FLOWS")
	if err != nil {
		t.Fatal(err)
	}
	for _, ed := range ins {
		src, ok, err := g.GetNode(ed.Src)
		if err != nil || !ok {
			t.Fatalf("call %s has an edge from a missing node", callee)
		}
		if src.Type == "code.Arg" && reach[src.ID] {
			return true
		}
	}
	return false
}

// The literal behaviour: a store and a later read of the same attribute in one function.
func TestPythonAttributeStoreReachesTheLaterReadOfThatAttribute(t *testing.T) {
	src := `def handler(param):
    box = Box()
    box.field = param
    return render(box.field)
`
	g := pyLocalsLower(t, "app.py", src)
	if !pyParamReachesCallArg(t, g, "param", "render", "app.py:4") {
		t.Fatalf("a value stored on an attribute did not reach the later read of that attribute")
	}
}

// The store and the read sit in two bodies that share the object only through a parameter, so
// the join has to survive the call boundary in both directions.
func TestPythonAttributeStoreCrossesTheFunctionThatFillsAndTheOneThatReads(t *testing.T) {
	src := `def fill(box, value):
    box.field = value

def drain(box):
    return box.field

def handler(param):
    box = Box()
    fill(box, param)
    return render(drain(box))
`
	g := pyLocalsLower(t, "app.py", src)
	if !pyParamReachesCallArg(t, g, "param", "render", "app.py:10") {
		t.Fatalf("a value one function stored on the caller's object did not reach the function that reads it back")
	}
}

// The shape the gap names: a value built inside the constructor, parked on `self`, and handed
// back out by a method of the same class. Neither the constructor's arguments nor the object's
// own taint carries it — only the field slot does.
func TestPythonAttributeStoreCarriesAValueTheConstructorStoredIntoTheMethodThatReadsIt(t *testing.T) {
	src := `class Client:
    def __init__(self, url):
        self.response = httpx.get(url)

    def body(self):
        return render(self.response)

def handler(url):
    client = Client(url)
    return client.body()
`
	g := pyLocalsLower(t, "app.py", src)
	if !pyCallReachesArg(t, g, "httpx.get", "render", "app.py:6") {
		t.Fatalf("a value the constructor stored on the object did not reach the method that reads it back")
	}
}

// Field sensitivity is the precision half: sharing an object across a store and a read must not
// make every attribute of it one slot.
func TestPythonAttributeStoreKeepsASiblingAttributeClean(t *testing.T) {
	src := `def handler(param):
    box = Box()
    box.written = param
    return render(box.other)
`
	g := pyLocalsLower(t, "app.py", src)
	if pyParamReachesCallArg(t, g, "param", "render", "app.py:4") {
		t.Fatalf("a read of a DIFFERENT attribute saw the stored attribute's slot")
	}
}

// The class-level slot a store through `self` fills is per class, so a sibling attribute read
// through `self` in another method of the same class stays clean.
func TestPythonAttributeStoreKeepsASiblingSelfAttributeClean(t *testing.T) {
	src := `class Client:
    def __init__(self, url):
        self.response = httpx.get(url)

    def other(self):
        return render(self.unrelated)

def handler(url):
    client = Client(url)
    return client.other()
`
	g := pyLocalsLower(t, "app.py", src)
	if pyCallReachesArg(t, g, "httpx.get", "render", "app.py:6") {
		t.Fatalf("a read of a DIFFERENT attribute of the class saw the stored attribute's slot")
	}
}

// The store must not make the base look like a container whose WRITES are modelled: a
// dynamic-key subscript read of the same name keeps the whole-base fallback it always had,
// instead of turning element-sensitive (and clean) because one attribute was stored.
func TestPythonAttributeStoreDoesNotMakeADynamicKeyReadOfTheBaseClean(t *testing.T) {
	src := `def handler(param, key):
    box = fetch(param)
    box.field = "constant"
    return render(box[key])
`
	g := pyLocalsLower(t, "app.py", src)
	if !pyParamReachesCallArg(t, g, "param", "render", "app.py:4") {
		t.Fatalf("a dynamic-key read lost the base's own taint after an attribute was stored on it")
	}
}
