package treesitter_test

import (
	"testing"

	"github.com/vyprai/vyql/internal/usg"
)

// The gap: taint is not carried through a Python object attribute store. `self.attr = v` only
// rebinds the dotted name in the enclosing scope, so the later `self.attr` read is a fresh Attr
// node joined to nothing — and a value that reaches a sink only by being parked on the object
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

// The literal behaviour: a store and a later read of the same attribute in one method. The
// value is DERIVED from the parameter (the call), not the parameter itself — the shape the
// slot is for.
func TestPythonAttributeStoreReachesTheLaterReadOfThatAttribute(t *testing.T) {
	src := `class Box:
    def fill(self, param):
        self.field = param.strip()
        return render(self.field)
`
	g := pyLocalsLower(t, "app.py", src)
	if !pyParamReachesCallArg(t, g, "param", "render", "app.py:4") {
		t.Fatalf("a value stored on an attribute did not reach the later read of that attribute")
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

// The rank's own spelling of it: the constructor splits the parameter into locals and stores
// one, and a DIFFERENT method joins the stored local into a path — the store and the read
// share nothing but the class.
func TestPythonAttributeStoreCarriesTheSplitLocalAcrossMethods(t *testing.T) {
	src := `class File:
    def __init__(self, name):
        base, ext = os.path.splitext(name)
        self._base = base

    def disk(self):
        return open(join(ROOT, self._base))

def handler(doc):
    return File(doc).disk()
`
	g := pyLocalsLower(t, "app.py", src)
	if !pyParamReachesCallArg(t, g, "name", "open", "app.py:7") {
		t.Fatalf("a local derived from a parameter and stored on the object did not reach the other method")
	}
}

// Field sensitivity is the precision half: a store through `self` must not make every
// attribute of the class one slot.
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

// A bare parameter as the stored value is the shape the slot refuses: the parameter's taint is
// the caller's whole-object approximation, and persisting it into a slot every method of the
// class reads launders one imprecise node class-wide. The parameter keeps its own arg→param
// route; only the class-wide parking is gone. (Measured: this is what carried the seeded
// corpora's form handlers, where the framework — not the repo — calls the reading method, so
// no receiver edge ties the two.)
func TestPythonAttributeStoreDoesNotPersistABareParameter(t *testing.T) {
	src := `class Client:
    def keep(self, value):
        self.token = value

    def read(self):
        return render(self.token)

def handler(param):
    client = Client()
    client.keep(param)
    return client.read()
`
	g := pyLocalsLower(t, "app.py", src)
	if pyParamReachesCallArg(t, g, "param", "render", "app.py:6") {
		t.Fatalf("a bare parameter stored on the object was persisted into the reading method")
	}
}

// The receiver's own taint — the wrapper rule puts every argument's taint on a constructed
// object — must not be read back out of `self` inside the constructor: the arguments already
// enter through their own parameter edges, and a value derived from such a read (here the
// never-stored `override`) would persist the blanket taint class-wide. The reading method is
// called on a DIFFERENT, untainted instance so the only possible route is the class-wide
// persistence — the slot is per class, which is exactly why persisting blanket taint into it
// is the multiplier this guards. This is the route that kept the fixed revision of the rank's
// repository firing after its sanitiser held.
func TestPythonAttributeStoreDoesNotPersistReceiverTaintReadOutOfSelf(t *testing.T) {
	src := `class Client:
    override = None

    def __init__(self, doc):
        self.name = self.override

    def read(self):
        return render(self.name)

def handler(param):
    tainted = Client(fetch(param))
    fresh = Client()
    return fresh.read()
`
	g := pyLocalsLower(t, "app.py", src)
	if pyParamReachesCallArg(t, g, "param", "render", "app.py:8") {
		t.Fatalf("receiver taint read out of `self` inside the constructor was persisted class-wide")
	}
}

// The store must not make the receiver look like a container whose WRITES are modelled: a
// dynamic-key subscript read of the object keeps the whole-base fallback it always had,
// instead of turning element-sensitive (and clean) because one attribute was stored. The
// receiver here is tainted by the wrapper rule alone — the constructor's own `self` edge is
// gone (see the receiver-taint test above), so this is also the pin that the wrapper rule and
// the method receiver edge still stand.
func TestPythonAttributeStoreDoesNotMakeADynamicKeyReadOfTheReceiverClean(t *testing.T) {
	src := `class Box:
    def __init__(self, data):
        self.field = "constant"

    def at(self, key):
        return render(self[key])

def handler(param, key):
    return Box(param).at(key)
`
	g := pyLocalsLower(t, "app.py", src)
	if !pyParamReachesCallArg(t, g, "param", "render", "app.py:6") {
		t.Fatalf("a dynamic-key read lost the receiver's own taint after an attribute was stored on it")
	}
}
