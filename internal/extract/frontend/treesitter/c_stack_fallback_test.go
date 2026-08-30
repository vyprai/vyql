package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccStackFallbackObs runs the stack-fallback observation over one C source
// and returns the emitted facts as "allocation=..;buffer=..;stride=.." text.
func ccStackFallbackObs(t *testing.T, src string) []string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "qmfb.c")
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, st := range prog.Modules[0].Body {
		fn, ok := st.(nir.FuncDef)
		if !ok {
			continue
		}
		for _, s := range fn.Body {
			es, ok := s.(nir.ExprStmt)
			if !ok {
				continue
			}
			call, ok := es.Value.(nir.Call)
			if !ok || call.Path != "analysis.alloc.stack_fallback_stride_underalloc" {
				continue
			}
			var parts []string
			for _, a := range call.Args {
				if konst, ok := a.(nir.Const); ok {
					parts = append(parts, konst.Value)
				}
			}
			out = append(out, strings.Join(parts, ";"))
		}
	}
	return out
}

func TestCStackFallbackStrideUnderallocObservations(t *testing.T) {
	// The dual-path idiom with the fallback sized by the count alone: the
	// write loop advances the buffer by the width the allocation omits.
	got := ccStackFallbackObs(t, `
#define SPLITBUFSIZE 4096
#define COLGRPSIZE 8
void split_colgrp(int *a, int numrows, int stride, int parity) {
	int bufsize = (numrows + 1) / 2;
	int splitbuf[SPLITBUFSIZE * COLGRPSIZE];
	int *buf = splitbuf;
	int *dstptr;
	int n, i;
	if (bufsize > SPLITBUFSIZE) {
		if (!(buf = my_alloc2(bufsize, sizeof(int)))) {
			abort();
		}
	}
	n = numrows;
	dstptr = buf;
	while (n-- > 0) {
		for (i = 0; i < COLGRPSIZE; ++i) {
			*dstptr = a[i];
			++dstptr;
		}
		dstptr += COLGRPSIZE;
	}
	if (buf != splitbuf) {
		free(buf);
	}
}
`)
	want := "allocation=my_alloc2;buffer=splitbuf;count=bufsize;stride=COLGRPSIZE;guard=count_bound_only"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("expected one observation %q, got %v", want, got)
	}

	// Naming the stride in the fallback's size clears it.
	if got := ccStackFallbackObs(t, `
#define SPLITBUFSIZE 4096
#define COLGRPSIZE 8
void split_colgrp(int *a, int numrows, int stride, int parity) {
	int bufsize = (numrows + 1) / 2;
	int splitbuf[SPLITBUFSIZE * COLGRPSIZE];
	int *buf = splitbuf;
	int *dstptr;
	int n, i;
	if (bufsize > SPLITBUFSIZE) {
		if (!(buf = my_alloc3(bufsize, COLGRPSIZE, sizeof(int)))) {
			abort();
		}
	}
	n = numrows;
	dstptr = buf;
	while (n-- > 0) {
		for (i = 0; i < COLGRPSIZE; ++i) {
			*dstptr = a[i];
			++dstptr;
		}
		dstptr += COLGRPSIZE;
	}
	if (buf != splitbuf) {
		free(buf);
	}
}
`); len(got) != 0 {
		t.Fatalf("stride named in the fallback should clear, got %v", got)
	}

	// A buffer pointer the loop reassigns to another expression stops
	// contributing its stride.
	if got := ccStackFallbackObs(t, `
#define SPLITBUFSIZE 4096
#define COLGRPSIZE 8
void split_colgrp(int *a, int numrows, int stride, int parity) {
	int bufsize = (numrows + 1) / 2;
	int splitbuf[SPLITBUFSIZE * COLGRPSIZE];
	int *buf = splitbuf;
	int *dstptr;
	int n, i;
	if (bufsize > SPLITBUFSIZE) {
		if (!(buf = my_alloc2(bufsize, sizeof(int)))) {
			abort();
		}
	}
	dstptr = &a[parity * stride];
	while (n-- > 0) {
		for (i = 0; i < COLGRPSIZE; ++i) {
			*dstptr = a[i];
			++dstptr;
		}
		dstptr += stride;
	}
	if (buf != splitbuf) {
		free(buf);
	}
}
`); len(got) != 0 {
		t.Fatalf("stride on a pointer that no longer names the buffer should clear, got %v", got)
	}

	// A plain fixed-size array without a product keeps whatever bound its
	// own declaration carries and is not this idiom.
	if got := ccStackFallbackObs(t, `
#define SPLITBUFSIZE 4096
void split_col(int *a, int numrows, int stride, int parity) {
	int bufsize = (numrows + 1) / 2;
	int splitbuf[SPLITBUFSIZE];
	int *buf = splitbuf;
	int *dstptr;
	int n;
	if (bufsize > SPLITBUFSIZE) {
		if (!(buf = my_alloc2(bufsize, sizeof(int)))) {
			abort();
		}
	}
	dstptr = buf;
	while (n-- > 0) {
		*dstptr = *a;
		++dstptr;
	}
	if (buf != splitbuf) {
		free(buf);
	}
}
`); len(got) != 0 {
		t.Fatalf("single-factor array should not report, got %v", got)
	}
}
