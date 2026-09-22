package treesitter_test

import (
	"testing"
)

// The shape CVE-2018-13423's flow crosses (rank 3282, the gap this change closes): a module
// builds a namespace object (Ns / Ns.Items), attaches its helpers by MEMBER ASSIGNMENT, and
// iterates a collection with $.each, reading the iterated element through `this`.
//
//	if (typeof Ns === 'undefined') { Ns = {} }
//	Ns.Items = {}
//	Ns.Items.addTags = function (tags) { $.each(tags.split(','), function () {
//	    Ns.Items.addTagElement($.trim(this)) }) }
//	Ns.Items.wire = function () { … Ns.Items.addTags($('#tags').val()) }
//
// Neither construct carried taint before: the member assignment registered no function
// definition, so the dotted call resolved to no body and the argument stopped at the call
// site; and the callback's `this` had no binding at all, so a callback with no named
// parameter received nothing from the iteration.
const namespaceEachThisSrc = `
if (typeof Ns === 'undefined') {
    Ns = {};
}
Ns.Items = {};

(function ($) {
    Ns.Items.addTagElement = function (tag) {
        var tagLi = $('<li/>');
        tagLi.prepend('<span class="tag">' + tag + '</span>');
        return false;
    };

    Ns.Items.addTags = function (tags) {
        var newTags = tags.split(',');
        $.each(newTags, function () {
            var tag = $.trim(this);
            if (tag) {
                Ns.Items.addTagElement(tag);
            }
        });
        return false;
    };

    Ns.Items.wire = function () {
        $('#add-tags-button').click(function (event) {
            Ns.Items.addTags($('#tags').val());
        });
    };
})(jQuery);
`

// The value read out of the form control must cross the dotted namespace call into the
// assigned body's parameter — the flow the unresolved call terminated at the call site.
func TestNamespaceMemberCallCarriesArgumentIntoAssignedBody(t *testing.T) {
	g := lowerJSFile(t, namespaceEachThisSrc)
	arg := callArgOf(g, "Ns.Items.addTags", 0)
	if arg == "" {
		t.Fatal("the namespace member call never lowered")
	}
	p := paramOf(g, "addTags", "tags")
	if p == "" {
		t.Fatal("a member assignment on a namespace object did not become a function definition, so the dotted call has no callee body")
	}
	if !reaches(t, g, arg, p) {
		t.Fatal("the argument of a dotted namespace call did not reach the assigned body's parameter")
	}
}

// Inside the $.each callback `this` is the iterated element, so the element must reach every
// read of it in the body — including when the callback names no parameter at all.
func TestEachCallbackBindsTheIteratedElementToThis(t *testing.T) {
	g := lowerJSFile(t, namespaceEachThisSrc)
	arg := callArgOf(g, "Ns.Items.addTags", 0)
	if arg == "" {
		t.Fatal("the namespace member call never lowered")
	}
	trim := callArgOf(g, "$.trim", 0)
	if trim == "" {
		t.Fatal("the $.trim call never lowered")
	}
	if !reaches(t, g, arg, trim) {
		t.Fatal("the iterated element did not reach the callback body's read of this")
	}
}

// The whole chain the CVE rides: form value -> addTags -> split -> each(this) ->
// addTagElement's parameter -> the markup the sink consumes.
func TestNamespaceEachChainReachesTheElementConsumer(t *testing.T) {
	g := lowerJSFile(t, namespaceEachThisSrc)
	arg := callArgOf(g, "Ns.Items.addTags", 0)
	consumer := paramOf(g, "addTagElement", "tag")
	prepend := callArgOf(g, "tagLi.prepend", 0)
	if consumer == "" {
		t.Fatal("addTagElement's parameter never lowered")
	}
	if prepend == "" {
		t.Fatal("the prepend call never lowered")
	}
	if !reaches(t, g, arg, consumer) {
		t.Fatal("the form value's taint stopped before the element consumer")
	}
	if !reaches(t, g, arg, prepend) {
		t.Fatal("the form value's taint stopped before the markup argument")
	}
}

// The receiver spelling of the same iteration: `values.forEach(function () { … })` invokes
// the callback with the element as `this` too, so the collection reaches the read.
func TestForEachCallbackBindsTheElementToThis(t *testing.T) {
	g := lowerJSFile(t, `
var Ns = {};
Ns.consume = function (values) {
    values.forEach(function () {
        sink($.trim(this));
    });
};
`)
	coll := paramOf(g, "consume", "values")
	trim := callArgOf(g, "$.trim", 0)
	if coll == "" || trim == "" {
		t.Fatal("the collection parameter or the this-reading call never lowered")
	}
	if !reaches(t, g, coll, trim) {
		t.Fatal("the forEach receiver's elements did not reach the callback body's read of this")
	}
}

// An arrow callback keeps the LEXICAL `this` — the language guarantees the iteration helper
// cannot re-bind it — so the element must not be routed into an arrow's `this` read.
func TestEachCallbackDoesNotBindAnArrowsLexicalThis(t *testing.T) {
	g := lowerJSFile(t, `
var Ns = {};
Ns.consume = function (values) {
    $.each(values, () => {
        sink(this);
    });
};
`)
	coll := paramOf(g, "consume", "values")
	sinkArg := callArgOf(g, "sink", 0)
	if coll == "" || sinkArg == "" {
		t.Fatal("the collection parameter or the sink argument never lowered")
	}
	if reaches(t, g, coll, sinkArg) {
		t.Fatal("the iterated element was routed into an arrow's lexical this")
	}
}

// A function expression nested inside the callback binds a `this` of its own at every call,
// so the element the iteration bound to the callback's `this` must not stand in for the
// nested body's `this` reads: a plugin's `.each(function (index) { … $(this) … })` reads
// the ELEMENT through `this`, not the collection the outer callback received.
func TestNonIterationCallbackThisStaysPerOccurrence(t *testing.T) {
	g := lowerJSFile(t, `
var Ns = {};
Ns.run = function (coll) {
    $.each(coll, function () {
        mark($.trim(this));
        work(function (index) {
            sink(this);
        });
    });
};
`)
	coll := paramOf(g, "run", "coll")
	trim := callArgOf(g, "$.trim", 0)
	sinkArg := callArgOf(g, "sink", 0)
	if coll == "" || trim == "" || sinkArg == "" {
		t.Fatal("the collection parameter or a this-reading call never lowered")
	}
	if !reaches(t, g, coll, trim) {
		t.Fatal("the iterated element no longer reaches the callback body's read of this")
	}
	if reaches(t, g, coll, sinkArg) {
		t.Fatal("the iterated element reached a nested function expression's own this; a function expression binds a this of its own at every call, and nothing invokes it with the element")
	}
}

// An each callback nested inside another one binds ITS OWN element: the inner callback's
// `this` is the inner collection's element, not the outer one's — even though the outer
// callback binds (and reads) an element of its own through `this`.
func TestNestedEachCallbackBindsItsOwnElement(t *testing.T) {
	g := lowerJSFile(t, `
var Ns = {};
Ns.run = function (outer, inner) {
    $.each(outer, function () {
        mark($.trim(this));
        $.each(inner, function () {
            sink(this);
        });
    });
};
`)
	outerP := paramOf(g, "run", "outer")
	innerP := paramOf(g, "run", "inner")
	trim := callArgOf(g, "$.trim", 0)
	sinkArg := callArgOf(g, "sink", 0)
	if outerP == "" || innerP == "" || trim == "" || sinkArg == "" {
		t.Fatal("a collection parameter or a this-reading call never lowered")
	}
	if !reaches(t, g, outerP, trim) {
		t.Fatal("the outer collection's element did not reach the outer callback's read of this")
	}
	if !reaches(t, g, innerP, sinkArg) {
		t.Fatal("the inner collection's element did not reach the inner callback's read of this")
	}
	if reaches(t, g, outerP, sinkArg) {
		t.Fatal("the outer collection's element reached the inner callback's this; the inner callback iterates the inner collection")
	}
}

// Only a root the module itself built into a namespace (`var Ns = {}`, `Ns = Ns || {}`,
// `Ns.Sub = {}`) has its member-assigned functions registered. A root holding anything
// else — a call result here — keeps the plain member-store lowering, so no function
// definition is minted for its members.
func TestNonNamespaceMemberAssignmentStaysAStore(t *testing.T) {
	g := lowerJSFile(t, `
var store = loadStore();
store.run = function (v) {
    sink(v);
};
`)
	if _, ok := funcDefNames(g)["run"]; ok {
		t.Fatal("a member assignment on a non-namespace root became a function definition; it stores a value, it does not attach the module's surface")
	}
}

// Only load-time statements build the namespace: a member assignment inside a function body
// writes some runtime object (whatever the namespace holds by the time that function runs),
// so it keeps the plain member-store lowering. Registering it would give every dotted call
// that spells the same property a callee body — the noise half of this change, unpinned by
// the sources above, whose member assignments all sit at module level.
func TestNamespaceMemberAssignmentInsideAFunctionStaysAStore(t *testing.T) {
	g := lowerJSFile(t, `
var Ns = {};
Ns.late = function (x) {
    Ns.runtime = function (v) {
        sink(x);
        sink(v);
    };
};
`)
	if _, ok := funcDefNames(g)["runtime"]; ok {
		t.Fatal("a member assignment inside a function body became a function definition; it writes a runtime object, it does not attach the module's namespace surface")
	}
	if _, ok := funcDefNames(g)["late"]; !ok {
		t.Fatal("the load-time member assignment on the same namespace stopped registering")
	}
}

// The guarded initialiser is a namespace too: `var Ns = Ns || {}` says the object's members
// all arrive later by member assignment exactly as the bare literal does, so the helper a
// member assignment attaches is registered and a dotted call into it carries its argument.
// The main source above builds the namespace through the typeof guard instead; this pins the
// `||` arm of namespaceObjectInit on its own.
func TestGuardedNamespaceInitialiserRegistersMemberFunctions(t *testing.T) {
	g := lowerJSFile(t, `
var Ns = Ns || {};
Ns.consume = function (v) {
    sink(v);
};
Ns.wire = function () {
    Ns.consume(source());
};
`)
	p := paramOf(g, "consume", "v")
	arg := callArgOf(g, "Ns.consume", 0)
	if p == "" {
		t.Fatal("a member assignment on a guard-initialised namespace did not become a function definition, so the dotted call has no callee body")
	}
	if arg == "" {
		t.Fatal("the namespace member call never lowered")
	}
	if !reaches(t, g, arg, p) {
		t.Fatal("the argument of a dotted call into a guard-initialised namespace did not reach the assigned body's parameter")
	}
}

// A class method's `this` is a binding the body inherits (the class's one stable self node),
// not a slot an iteration callback may rebind: a field the constructor writes through `this`
// still reaches a `this` read in another method with an each callback sitting in between, and
// the iterated element is not merged into that binding — inside the callback `this` keeps
// resolving the way it always did rather than to a node the iteration flows into.
func TestClassMethodThisSurvivesAnEachCallbackInTheMethod(t *testing.T) {
	g := lowerJSFile(t, `
class Widget {
    constructor(list) {
        this.list = list;
    }
    run() {
        $.each(this.list, function () {
            sink(this);
        });
    }
    emit() {
        use(this.list);
    }
}
`)
	src := paramOf(g, "constructor", "list")
	useArg := callArgOf(g, "use", 0)
	sinkArg := callArgOf(g, "sink", 0)
	if src == "" || useArg == "" || sinkArg == "" {
		t.Fatal("the constructor parameter or a this-reading call never lowered")
	}
	if !reaches(t, g, src, useArg) {
		t.Fatal("a field written through this in the constructor stopped reaching a this read in another method; the class's self binding did not survive the each callback")
	}
	if reaches(t, g, src, sinkArg) {
		t.Fatal("the iterated collection was merged into a class method's this; the method's this is a binding the body inherits, not a slot the iteration rebinds")
	}
}

// A POPULATED object literal is a complete record, not a namespace being built for later
// member assignment: `X.fn = X.prototype = { method: … }` already places its members, so a
// member assignment layered onto it afterwards (`X.fn.load = function …`, the way a library
// extends a prototype) stays a plain store — registering it would resolve every application
// `.load()` into the library's internals.
func TestPopulatedObjectLiteralIsNotANamespace(t *testing.T) {
	g := lowerJSFile(t, `
X.fn = X.prototype = {
    init: function (selector) {
        return sink(selector);
    }
};
X.fn.load = function (url) {
    run(url);
};
`)
	if _, ok := funcDefNames(g)["load"]; ok {
		t.Fatal("a member assignment on a record built from a populated literal became a function definition; the record's members are already in place, the assignment rewrites one")
	}
}
