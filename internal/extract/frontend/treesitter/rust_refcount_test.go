package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/usg"
)

// rustAnalysisNodes lowers one Rust source and returns the analysis calls with
// the given callee path.
func rustAnalysisNodes(t *testing.T, src string, path string) []usg.Node {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "lib.rs")
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := ExtractRust([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	var out []usg.Node
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == path {
			out = append(out, n)
		}
	}
	return out
}

const rustRefcountDropImpl = `
/// Dropping a Py instance decrements the reference count on the object by 1.
impl<T> Drop for Py<T> {
    fn drop(&mut self) {
        unsafe {
            gil::register_decref(self.0);
        }
    }
}
`

// TestRustManualRefcountDropIsLabelled covers the first half of the gap: a Drop
// impl that hands a manually kept reference back has to be nameable before
// anything can reason about how many times the release runs.
func TestRustManualRefcountDropIsLabelled(t *testing.T) {
	nodes := rustAnalysisNodes(t, rustRefcountDropImpl, "analysis.rust.manual_refcount_drop")
	if len(nodes) != 1 {
		t.Fatalf("want one manual_refcount_drop observation, got %d", len(nodes))
	}
	tokens := nodes[0].Prop("str_args")
	for _, want := range []string{"type:Py", "release:gil.register_decref", "kind:drop_impl"} {
		if !strings.Contains(tokens, want) {
			t.Fatalf("manual_refcount_drop tokens %q missing %q", tokens, want)
		}
	}
}

// TestRustDropWithoutReferenceReleaseIsNotLabelled keeps the fact to reference
// counts: a Drop that frees a buffer or closes a handle releases nothing that
// can be released twice by copying a field out.
func TestRustDropWithoutReferenceReleaseIsNotLabelled(t *testing.T) {
	src := `
impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr, self.len) }
    }
}

impl Mapping {
    fn into_raw(self) -> *mut u8 {
        let raw = self.ptr;
        raw
    }
}
`
	if nodes := rustAnalysisNodes(t, src, "analysis.rust.manual_refcount_drop"); len(nodes) != 0 {
		t.Fatalf("munmap Drop should not be a manual reference release; got %d", len(nodes))
	}
	if nodes := rustAnalysisNodes(t, src, "analysis.rust.refcounted_conversion_missing_forget"); len(nodes) != 0 {
		t.Fatalf("conversion of a non-refcounted type should not be reported; got %d", len(nodes))
	}
}

// TestRustRefcountedConversionSeparatesVulnerableFromFixed pins the two forms
// of the same From impl in pyo3 CVE-2020-35917 apart. The vulnerable form
// destructures the owned Py for its Copy pointer and lets the value drop,
// releasing a reference the returned pointer still stands for; the fixed form
// moves the value through a helper that forgets it.
func TestRustRefcountedConversionSeparatesVulnerableFromFixed(t *testing.T) {
	vulnerable := rustRefcountDropImpl + `
impl<T> std::convert::From<Py<T>> for PyObject
where
    T: AsRef<PyAny>,
{
    fn from(other: Py<T>) -> Self {
        let Py(ptr, _) = other;
        Py(ptr, PhantomData)
    }
}
`
	fixed := rustRefcountDropImpl + `
impl<T> Py<T> {
    fn into_non_null(self) -> NonNull<ffi::PyObject> {
        let pointer = self.0;
        mem::forget(self);
        pointer
    }
}

impl<T> std::convert::From<Py<T>> for PyObject
where
    T: AsRef<PyAny>,
{
    #[inline]
    fn from(other: Py<T>) -> Self {
        unsafe { Self::from_non_null(other.into_non_null()) }
    }
}
`
	nodes := rustAnalysisNodes(t, vulnerable, "analysis.rust.refcounted_conversion_missing_forget")
	if len(nodes) != 1 {
		t.Fatalf("want one refcounted_conversion_missing_forget on the vulnerable form, got %d", len(nodes))
	}
	tokens := nodes[0].Prop("str_args")
	for _, want := range []string{"type:Py", "value:other", "field:ptr", "release:gil.register_decref"} {
		if !strings.Contains(tokens, want) {
			t.Fatalf("conversion tokens %q missing %q", tokens, want)
		}
	}
	if nodes := rustAnalysisNodes(t, fixed, "analysis.rust.refcounted_conversion_missing_forget"); len(nodes) != 0 {
		t.Fatalf("fixed form should not be reported; got %d: %#v", len(nodes), nodes)
	}
}

// TestRustRefcountedConversionSuppressedForms covers the shapes that must not
// fire: a borrowed receiver drops nothing, a mem::forget or ManuallyDrop
// rebinding stops the drop, and a copy that never leaves the body releases
// nothing.
func TestRustRefcountedConversionSuppressedForms(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"borrowed receiver", `
impl<T> Py<T> {
    fn as_ptr(&self) -> *mut ffi::PyObject {
        self.0.as_ptr()
    }
}`},
		{"forgotten receiver", `
impl<T> Py<T> {
    fn into_non_null(self) -> NonNull<ffi::PyObject> {
        let pointer = self.0;
        mem::forget(self);
        pointer
    }
}`},
		{"manually dropped receiver", `
impl<T> Py<T> {
    fn into_ptr(self) -> *mut ffi::PyObject {
        let me = ManuallyDrop::new(self);
        me.0.as_ptr()
    }
}`},
		{"copy does not escape", `
impl<T> Py<T> {
    fn log(self) {
        let Py(ptr, _) = self;
        record(ptr);
    }
}`},
		{"value is moved, not copied", `
impl<T> Py<T> {
    fn into_ptr(self) -> *mut ffi::PyObject {
        self.into_non_null().as_ptr()
    }
}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes := rustAnalysisNodes(t, rustRefcountDropImpl+tc.body, "analysis.rust.refcounted_conversion_missing_forget")
			if len(nodes) != 0 {
				t.Fatalf("%s should not be reported; got %d: %#v", tc.name, len(nodes), nodes)
			}
		})
	}
}

// TestRustRefcountedConversionReportedForms covers the spellings of the same
// bug other than the one CVE-2020-35917 uses: a field read instead of a
// destructuring, an explicit return instead of a tail expression, and a self
// receiver instead of a named parameter.
func TestRustRefcountedConversionReportedForms(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"self receiver, field read, tail", `
impl<T> Py<T> {
    fn into_ptr(self) -> *mut ffi::PyObject {
        self.0.as_ptr()
    }
}`},
		{"explicit return of a carried copy", `
impl<T> Py<T> {
    fn into_ptr(self) -> *mut ffi::PyObject {
        let raw = self.0;
        return raw.as_ptr();
    }
}`},
		{"struct destructuring inside an unsafe tail", `
impl<T> Py<T> {
    fn take(self) -> *mut ffi::PyObject {
        let Py { ptr, .. } = self;
        unsafe { ptr }
    }
}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes := rustAnalysisNodes(t, rustRefcountDropImpl+tc.body, "analysis.rust.refcounted_conversion_missing_forget")
			if len(nodes) != 1 {
				t.Fatalf("%s should be reported once; got %d", tc.name, len(nodes))
			}
		})
	}
}

// TestRustRefcountedConversionAcrossItemPositions covers the item positions a
// Drop impl can be written in other than the top level of the file, and the
// order it can be written in relative to the conversion that mishandles the
// type: inside a module, and inside a function body.
func TestRustRefcountedConversionAcrossItemPositions(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"drop impl inside a module, below the conversion", `
mod inner {
    impl<T> Py<T> {
        fn into_ptr(self) -> *mut u8 {
            let Py(ptr, _) = self;
            ptr
        }
    }

    impl<T> Drop for Py<T> {
        fn drop(&mut self) {
            unsafe { gil::register_decref(self.0); }
        }
    }
}`},
		{"drop impl inside a function body", `
fn install() {
    impl<T> Drop for Py<T> {
        fn drop(&mut self) {
            unsafe { gil::register_decref(self.0); }
        }
    }
}

impl<T> Py<T> {
    fn into_ptr(self) -> *mut u8 {
        let Py(ptr, _) = self;
        ptr
    }
}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if nodes := rustAnalysisNodes(t, tc.src, "analysis.rust.manual_refcount_drop"); len(nodes) != 1 {
				t.Fatalf("want one manual_refcount_drop observation, got %d", len(nodes))
			}
			if nodes := rustAnalysisNodes(t, tc.src, "analysis.rust.refcounted_conversion_missing_forget"); len(nodes) != 1 {
				t.Fatalf("want one refcounted_conversion_missing_forget observation, got %d", len(nodes))
			}
		})
	}
}
