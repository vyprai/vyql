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
