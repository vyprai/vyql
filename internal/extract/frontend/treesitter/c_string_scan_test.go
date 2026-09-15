package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccStringScanObs runs the string-scan length-bound observation over one C
// source and returns the emitted facts as
// "scan=..;cursor=..;buffer=..;length=..;termination=.." text.
func ccStringScanObs(t *testing.T, src string) []string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "scan.c")
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
			if !ok || call.Path != "analysis.string_scan.missing_length_bound" {
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

// The CVE-2017-5209 shape, reduced: base64decode walks a size-bounded buffer
// with strspn/strcspn, whose only stop condition is a delimiter byte or the
// terminating NUL, and checks the cursor against buf+len only after each scan
// has already run. The pairing -- a cursor derived from buf compared against
// buf+len -- is what makes len the buffer's real bound, and nothing
// establishes a NUL within it.
func TestCStringScanMissingLengthBoundObservations(t *testing.T) {
	got := ccStringScanObs(t, `
#include <stdlib.h>
#include <string.h>
unsigned char *base64decode(const char *buf, size_t *size)
{
	size_t len = (*size > 0) ? *size : strlen(buf);
	unsigned char *outbuf = (unsigned char*)malloc((len/4)*3+3);
	const char *ptr = buf;
	int p = 0;
	size_t l = 0;

	do {
		ptr += strspn(ptr, "\r\n\t ");
		if (*ptr == '\0' || ptr >= buf+len) {
			break;
		}
		l = strcspn(ptr, "\r\n\t ");
		if (l > 3 && ptr+l <= buf+len) {
			p += base64decode_block(outbuf+p, ptr, l);
			ptr += l;
		} else {
			break;
		}
	} while (1);

	outbuf[p] = 0;
	*size = p;
	return outbuf;
}
`)
	want := []string{
		"scan=strspn;cursor=ptr;buffer=buf;length=len;termination=not_established_within_length",
		"scan=strcspn;cursor=ptr;buffer=buf;length=len;termination=not_established_within_length",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("base64decode idiom: got %q want %q", got, want)
	}

	// The fix's shape: the walk is a hand-rolled loop whose own condition is
	// the bound, and no libc scan remains, so nothing reports.
	got = ccStringScanObs(t, `
#include <stdlib.h>
#include <string.h>
unsigned char *base64decode(const char *buf, size_t *size)
{
	size_t len = (*size > 0) ? *size : strlen(buf);
	unsigned char *outbuf = (unsigned char*)malloc((len/4)*3+3);
	const char *ptr = buf;
	int p = 0;

	do {
		while (ptr < buf+len && (*ptr == ' ' || *ptr == '\t' || *ptr == '\n' || *ptr == '\r')) {
			ptr++;
		}
		if (*ptr == '\0' || ptr >= buf+len) {
			break;
		}
		if ((wv = base64_table[(int)(unsigned char)*ptr++]) == -1) {
			continue;
		}
	} while (1);

	outbuf[p] = 0;
	*size = p;
	return outbuf;
}
`)
	if len(got) != 0 {
		t.Fatalf("bounded walk: got %q want none", got)
	}

	// The ordinary safe idiom: a scan on a string whose contract is its
	// terminator, with no separate length anywhere in the function.
	got = ccStringScanObs(t, `
#include <string.h>
void trim(char *line) {
	line[strcspn(line, "\n")] = 0;
}
`)
	if len(got) != 0 {
		t.Fatalf("terminator-contract scan: got %q want none", got)
	}

	// The fgets idiom: a length is passed to the reader, the reader writes
	// the terminator, and the scan trims through it. No comparison ever
	// states the buffer's end as line+n, so no pairing exists.
	got = ccStringScanObs(t, `
#include <stdio.h>
#include <string.h>
void handle(size_t n) {
	char line[512];
	if (!fgets(line, n, stdin)) return;
	line[strcspn(line, "\n")] = 0;
	use(line);
}
`)
	if len(got) != 0 {
		t.Fatalf("fgets trim: got %q want none", got)
	}

	// A NUL written at the bound before the scan establishes the terminator
	// the scan stops on, so the length-bounded buffer is safe to scan.
	got = ccStringScanObs(t, `
#include <string.h>
size_t parse(char *buf, size_t len) {
	char *p;
	size_t k;
	for (p = buf; p < buf + len; p++) {
		count(*p);
	}
	buf[len] = '\0';
	k = strcspn(buf, ",");
	return k;
}
`)
	if len(got) != 0 {
		t.Fatalf("nul written at bound: got %q want none", got)
	}

	// The dereferenced-sum spelling of the same establishment.
	got = ccStringScanObs(t, `
#include <string.h>
size_t parse(char *buf, size_t len) {
	char *p;
	size_t k;
	for (p = buf; p < buf + len; p++) {
		count(*p);
	}
	*(buf + len) = 0;
	k = strcspn(buf, ",");
	return k;
}
`)
	if len(got) != 0 {
		t.Fatalf("nul written at dereferenced sum: got %q want none", got)
	}

	// A memchr asked to find the terminator within the length establishes
	// it for the scan that follows.
	got = ccStringScanObs(t, `
#include <string.h>
size_t parse(char *buf, size_t len) {
	char *p;
	size_t k;
	for (p = buf; p < buf + len; p++) {
		count(*p);
	}
	if (!memchr(buf, 0, len)) {
		return 0;
	}
	k = strcspn(buf, ",");
	return k;
}
`)
	if len(got) != 0 {
		t.Fatalf("memchr establishment: got %q want none", got)
	}

	// A memchr for a delimiter byte establishes nothing about where the
	// terminating NUL is: finding a ',' within the length does not stop a
	// scan whose set is "\r\n\t ", so the scan still runs past the bound
	// and the fact stands.
	got = ccStringScanObs(t, `
#include <string.h>
size_t parse(char *buf, size_t len) {
	char *p;
	size_t k;
	for (p = buf; p < buf + len; p++) {
		count(*p);
	}
	if (!memchr(buf, ',', len)) {
		return 0;
	}
	k = strcspn(buf, "\r\n\t ");
	return k;
}
`)
	wantDelim := []string{"scan=strcspn;cursor=buf;buffer=buf;length=len;termination=not_established_within_length"}
	if strings.Join(got, "|") != strings.Join(wantDelim, "|") {
		t.Fatalf("memchr for a delimiter byte: got %q want %q", got, wantDelim)
	}

	// A memchr whose byte is a variable is not a stated NUL either: the
	// tree does not say what delim holds, so nothing is established.
	got = ccStringScanObs(t, `
#include <string.h>
size_t parse(char *buf, size_t len, int delim) {
	char *p;
	size_t k;
	for (p = buf; p < buf + len; p++) {
		count(*p);
	}
	if (!memchr(buf, delim, len)) {
		return 0;
	}
	k = strcspn(buf, ",");
	return k;
}
`)
	if strings.Join(got, "|") != strings.Join(wantDelim, "|") {
		t.Fatalf("memchr for a variable byte: got %q want %q", got, wantDelim)
	}

	// The scan's own result cannot bound the buffer it measured: the guard
	// comparing the scanned endpoint against the end reports the real
	// length only, never the measurement.
	got = ccStringScanObs(t, `
#include <string.h>
size_t parse(char *buf, size_t len) {
	size_t k = strcspn(buf, ",");
	if (buf + k > buf + len) {
		return 0;
	}
	return k;
}
`)
	want2 := []string{"scan=strcspn;cursor=buf;buffer=buf;length=len;termination=not_established_within_length"}
	if strings.Join(got, "|") != strings.Join(want2, "|") {
		t.Fatalf("scan-result guard: got %q want %q", got, want2)
	}

	// A scan of a different string than the bounded one stays unreported:
	// the cursor's origins do not include the bounded buffer.
	got = ccStringScanObs(t, `
#include <string.h>
void parse(char *buf, size_t len, char *name) {
	char *p;
	for (p = buf; p < buf + len; p++) {
		count(*p);
	}
	if (strcspn(name, "/") == 0) {
		return;
	}
	use(name);
}
`)
	if len(got) != 0 {
		t.Fatalf("unbounded sibling scan: got %q want none", got)
	}

	// The mirrored sum: the length may stand on either side of the pointer,
	// and a cursor reassigned from the buffer mid-function still pairs.
	got = ccStringScanObs(t, `
#include <string.h>
void parse(char *buf, size_t len) {
	char *p = buf;
	while (p < len + buf) {
		p += strspn(p, " ");
		if (p >= len + buf) {
			break;
		}
		p += strcspn(p, " ");
	}
}
`)
	want3 := []string{
		"scan=strspn;cursor=p;buffer=buf;length=len;termination=not_established_within_length",
		"scan=strcspn;cursor=p;buffer=buf;length=len;termination=not_established_within_length",
	}
	if strings.Join(got, "|") != strings.Join(want3, "|") {
		t.Fatalf("mirrored sum: got %q want %q", got, want3)
	}

	// A bound named by a constant macro rather than a parameter or local
	// variable is not this fact's separate length.
	got = ccStringScanObs(t, `
#include <string.h>
#define CAP 512
void parse(char *buf) {
	char *p;
	for (p = buf; p < buf + CAP; p++) {
		count(*p);
	}
	p += strspn(p, " ");
	use(p);
}
`)
	if len(got) != 0 {
		t.Fatalf("macro bound: got %q want none", got)
	}
}
