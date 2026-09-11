package extract_test

import (
	"testing"
)

// A C reader (fgets/fread/read/...) fills its destination argument from the file
// or socket it reads, so whatever a binding labels on the call has to reach the
// variable that argument names. The frontend lowers that write as an assignment
// of the call to the destination -- but only in exprStmt, which runs for a bare
// call whose result nobody reads. Every other spelling of the same read dropped
// the destination, so the label sat on the call and died there.

// The control: the result discarded, the destination write reaches the read.
func TestCReaderFillsItsDestinationWhenTheResultIsDiscarded(t *testing.T) {
	g := lowerC(t, "discard.c", `
extern int fread(void *, int, int, void *);
extern void sink(unsigned int);

static void run(void *fp)
{
    unsigned int num;

    fread(&num, 1, 4, fp);
    sink(num);
}
`)
	if !reachesNodeAt(t, g, callAt(t, g, "discard.c:9"), "code.Call", "discard.c:10") {
		t.Error("a read whose result is discarded left its destination clean")
	}
}

// A declaration consumes the result and still drops the destination.
func TestCReaderFillsItsDestinationUnderADeclaration(t *testing.T) {
	g := lowerC(t, "declare.c", `
extern int fread(void *, int, int, void *);
extern void sink(unsigned int);

static void run(void *fp)
{
    unsigned int num;
    int r;

    r = fread(&num, 1, 4, fp);
    sink(num);
}
`)
	if !reachesNodeAt(t, g, callAt(t, g, "declare.c:10"), "code.Call", "declare.c:11") {
		t.Error("a read consumed by a declaration left its destination clean")
	}
}

// The compound assignment is the shape rank 2620's mp4reader reads every count
// through: `len += fread(&num, 1, 4, mp4->mediafp)`.
func TestCReaderFillsItsDestinationUnderACompoundAssignment(t *testing.T) {
	g := lowerC(t, "compound.c", `
extern int fread(void *, int, int, void *);
extern void sink(unsigned int);

static void run(void *fp)
{
    unsigned int num;
    size_t len;

    len += fread(&num, 1, 4, fp);
    sink(num);
}
`)
	if !reachesNodeAt(t, g, callAt(t, g, "compound.c:10"), "code.Call", "compound.c:11") {
		t.Error("a read consumed by a compound assignment left its destination clean")
	}
}

// A condition consumes the result too: the idiom `if (fread(...) != 4) return`.
func TestCReaderFillsItsDestinationUnderACondition(t *testing.T) {
	g := lowerC(t, "condition.c", `
extern int fread(void *, int, int, void *);
extern void sink(unsigned int);

static void run(void *fp)
{
    unsigned int num;

    if (fread(&num, 1, 4, fp) != 4)
        return;
    sink(num);
}
`)
	if !reachesNodeAt(t, g, callAt(t, g, "condition.c:9"), "code.Call", "condition.c:11") {
		t.Error("a read consumed by a condition left its destination clean")
	}
}
