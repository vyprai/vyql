package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccFormatCapacityObs runs the format-capacity observation over one C source
// and returns the emitted facts as
// "format=..;dest=..;capacity=..;capacity_kind=..;conversions=.." text.
func ccFormatCapacityObs(t *testing.T, src string) []string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "send.c")
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
			if !ok || call.Path != "analysis.format_capacity.integer_conversions" {
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

func TestCFormatIntegerCapacityObservations(t *testing.T) {
	// The libc sibling: the declared array states the whole capacity, and the
	// conversion widths (%02d's floor of two, %4d's floor of four) pair with
	// that number rather than bounding anything themselves.
	got := ccFormatCapacityObs(t, `
#include <stdio.h>
#include <stddef.h>
void last_modified_header(char *buf, size_t cap, long long mtime) {
	char date[30];
	struct tm gmt;
	sprintf(date, "%s, %02d %s %4d %02d:%02d:%02d GMT",
	        "Mon", gmt.tm_mday, "Sep", gmt.tm_year,
	        gmt.tm_hour, gmt.tm_min, gmt.tm_sec);
	snprintf(buf, cap, "Last-Modified: %s\r\n", date);
}
`)
	want := []string{"format=sprintf;dest=date;capacity=30;capacity_kind=declared_array;conversions=%02d,%4d"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("libc array: got %q want %q", got, want)
	}

	// The bounded libc spelling keeps its own size argument beside the
	// pairing, so a rule can tell the call caps the write itself.
	got = ccFormatCapacityObs(t, `
#include <stdio.h>
void log_pair(int n, const char *v) {
	char buf[64];
	snprintf(buf, sizeof(buf), "n=%d v=%s", n, v);
}
`)
	want = []string{"format=snprintf;dest=buf;capacity=64;capacity_kind=declared_array;conversions=%d;size_arg=sizeof(buf)"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("bounded libc spelling: got %q want %q", got, want)
	}

	// The pool-buffer idiom: the allocation's size argument is a local whose
	// store sums a sizeof of the four-digit date literal, and the destination
	// is the member the returned cursor writes through. nginx's own
	// ngx_sprintf is the writer, which no libc name would reach.
	got = ccFormatCapacityObs(t, `
#include <stddef.h>
typedef unsigned char u_char;
typedef struct { u_char *last; u_char *pos; } ngx_buf_t;
extern ngx_buf_t *ngx_create_temp_buf(void *pool, size_t size);
extern u_char *ngx_sprintf(u_char *buf, const char *fmt, ...);
static char *months[] = { "Jan", "Feb" };
void entry(void *pool, int mday, int mon, int year, int hour, int min) {
	ngx_buf_t *b;
	size_t len;
	len = sizeof(" 28-Sep-1970 12:00 ") - 1 + 20 + 2;
	b = ngx_create_temp_buf(pool, len);
	if (b == NULL) {
		return;
	}
	b->last = ngx_sprintf(b->last, "%02d-%s-%d %02d:%02d ",
	                      mday, months[mon - 1], year, hour, min);
}
`)
	want = []string{"format=ngx_sprintf;dest=b->last;capacity=sizeof(\"28-Sep-197012:00\")-1+20+2;capacity_kind=allocation;conversions=%02d,%d"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("pool allocation: got %q want %q", got, want)
	}

	// The accumulating spelling of the same budget: the per-entry `len +=`
	// sums into what the allocation receives.
	got = ccFormatCapacityObs(t, `
#include <stddef.h>
typedef unsigned char u_char;
typedef struct { u_char *last; } ngx_buf_t;
extern ngx_buf_t *ngx_create_temp_buf(void *pool, size_t size);
extern u_char *ngx_sprintf(u_char *buf, const char *fmt, ...);
static char title[] = "Index of /";
void entry(void *pool, int mday, int year) {
	ngx_buf_t *b;
	size_t len;
	len = sizeof(title) - 1;
	len += sizeof(" 28-Sep-1970 12:00 ") - 1 + 20 + 2;
	b = ngx_create_temp_buf(pool, len);
	if (b == NULL) {
		return;
	}
	b->last = ngx_sprintf(b->last, "%02d-%d ", mday, year);
}
`)
	want = []string{"format=ngx_sprintf;dest=b->last;capacity=sizeof(title)-1+sizeof(\"28-Sep-197012:00\")-1+20+2;capacity_kind=allocation;conversions=%02d,%d"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("accumulated budget: got %q want %q", got, want)
	}

	// The sizeof-declared array, reached through a pointer the function sets
	// into it: the row's dimension is the capacity, whatever the first
	// dimension counts.
	got = ccFormatCapacityObs(t, `
#include <stddef.h>
typedef unsigned char u_char;
typedef long long time_t;
typedef struct { int ngx_tm_year; } ngx_tm_t;
extern u_char *ngx_sprintf(u_char *buf, const char *fmt, ...);
extern void ngx_gmtime(time_t t, ngx_tm_t *tp);
static u_char cached_http_time[16][sizeof("Mon, 28 Sep 1970 06:00:00 GMT")];
void update(time_t t) {
	ngx_tm_t tm;
	u_char *p0;
	ngx_gmtime(t, &tm);
	p0 = &cached_http_time[0][0];
	(void) ngx_sprintf(p0, "%s, %02d %s %4d %02d:%02d:%02d GMT",
	                   "Mon", 28, "Sep", tm.ngx_tm_year, 6, 0, 0);
}
`)
	want = []string{"format=ngx_sprintf;dest=p0;capacity=sizeof(\"Mon,28Sep197006:00:00GMT\");capacity_kind=declared_array;conversions=%02d,%4d"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("sizeof-declared array: got %q want %q", got, want)
	}

	// A format that is not a literal -- the conditional spelling nginx's
	// cookie time uses -- states no conversions to pair.
	got = ccFormatCapacityObs(t, `
#include <stddef.h>
typedef unsigned char u_char;
extern u_char *ngx_sprintf(u_char *buf, const char *fmt, ...);
u_char *cookie(u_char *buf, int year, int big) {
	return ngx_sprintf(buf, big ? "%02d" : "%d", year);
}
`)
	if len(got) != 0 {
		t.Fatalf("non-literal format: got %q want none", got)
	}

	// A format with no integer conversion pairs nothing here: %s is bounded
	// by an argument the call receives, not by a width the format states,
	// and %% is a literal percent rather than a conversion.
	for name, fmt := range map[string]string{
		"string_only":     `"%s"`,
		"literal_percent": `"100%%d done"`,
	} {
		got = ccFormatCapacityObs(t, `
#include <stdio.h>
void note(const char *s) {
	char line[8];
	sprintf(line, `+fmt+`, s);
}
`)
		if len(got) != 0 {
			t.Fatalf("%s format: got %q want none", name, got)
		}
	}

	// A destination whose capacity this function does not state -- a pointer
	// parameter, the caller's buffer -- pairs nothing.
	got = ccFormatCapacityObs(t, `
#include <stdio.h>
void emit(char *buf, int year) {
	sprintf(buf, "%4d", year);
}
`)
	if len(got) != 0 {
		t.Fatalf("caller-owned destination: got %q want none", got)
	}

	// An allocation whose size argument is a plain expression states that
	// expression as the capacity, without inventing a sum.
	got = ccFormatCapacityObs(t, `
#include <stdio.h>
#include <stdlib.h>
void emit(int year) {
	char *p;
	p = malloc(32);
	sprintf(p, "%4d", year);
}
`)
	want = []string{"format=sprintf;dest=p;capacity=32;capacity_kind=allocation;conversions=%4d"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("expression-sized allocation: got %q want %q", got, want)
	}
}
