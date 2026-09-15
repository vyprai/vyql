package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccProducerRangeObs runs the producer field range-bound observation over one
// C source and returns the emitted facts as
// "via=..;field=..;value=..;guard=..[;bound=..;bound_var=..]" text.
func ccProducerRangeObs(t *testing.T, src string) []string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "ngx_times.c")
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
			if !ok || (call.Path != "analysis.range.producer_field_bounded" &&
				call.Path != "analysis.range.producer_field_unbounded") {
				continue
			}
			var parts []string
			for _, a := range call.Args {
				if konst, ok := a.(nir.Const); ok {
					parts = append(parts, konst.Value)
				}
			}
			out = append(out, strings.TrimPrefix(call.Path, "analysis.range.")+" "+
				strings.Join(parts, ";"))
		}
	}
	return out
}

func hasLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// The vulnerable producer of CVE-2017-20005: ngx_gmtime at the fix's parent
// computes the year from days with no ceiling anywhere, so the field every
// consumer formats is paired with nothing.
const ccVulnGmtime = `
#include <stddef.h>
typedef size_t ngx_uint_t;
typedef long ngx_int_t;
typedef long long time_t;
typedef struct {
	int ngx_tm_sec, ngx_tm_min, ngx_tm_hour;
	int ngx_tm_mday, ngx_tm_mon, ngx_tm_year, ngx_tm_wday;
} ngx_tm_t;
void ngx_gmtime(time_t t, ngx_tm_t *tp) {
	ngx_int_t yday;
	ngx_uint_t sec, min, hour, mday, mon, year, wday, days, leap;
	if (t < 0) {
		t = 0;
	}
	days = t / 86400;
	sec = t % 86400;
	wday = (4 + days) % 7;
	hour = sec / 3600;
	sec %= 3600;
	min = sec / 60;
	sec %= 60;
	days = days - (31 + 28) + 719527;
	year = (days + 2) * 400 / (365 * 400 + 100 - 4 + 1);
	yday = days - (365 * year + year / 4 - year / 100 + year / 400);
	if (yday < 0) {
		leap = (year % 4 == 0) && (year % 100 || (year % 400 == 0));
		yday = 365 + leap + yday;
		year--;
	}
	mon = (yday + 31) * 10 / 306;
	mday = yday - (367 * mon / 12 - 30) + 1;
	if (yday >= 306) {
		year++;
		mon -= 10;
	} else {
		mon += 2;
	}
	tp->ngx_tm_sec = (int) sec;
	tp->ngx_tm_min = (int) min;
	tp->ngx_tm_hour = (int) hour;
	tp->ngx_tm_mday = (int) mday;
	tp->ngx_tm_mon = (int) mon;
	tp->ngx_tm_year = (int) year;
	tp->ngx_tm_wday = (int) wday;
}
`

// The fixed producer: the same function with b900cc28's ten added lines, a
// clamp on days that every derived field inherits.
const ccFixedGmtime = `
#include <stddef.h>
typedef size_t ngx_uint_t;
typedef long ngx_int_t;
typedef long long time_t;
typedef struct {
	int ngx_tm_sec, ngx_tm_min, ngx_tm_hour;
	int ngx_tm_mday, ngx_tm_mon, ngx_tm_year, ngx_tm_wday;
} ngx_tm_t;
void ngx_gmtime(time_t t, ngx_tm_t *tp) {
	ngx_int_t yday;
	ngx_uint_t sec, min, hour, mday, mon, year, wday, days, leap;
	if (t < 0) {
		t = 0;
	}
	days = t / 86400;
	sec = t % 86400;
	if (days > 2932896) {
		days = 2932896;
		sec = 86399;
	}
	wday = (4 + days) % 7;
	hour = sec / 3600;
	sec %= 3600;
	min = sec / 60;
	sec %= 60;
	days = days - (31 + 28) + 719527;
	year = (days + 2) * 400 / (365 * 400 + 100 - 4 + 1);
	yday = days - (365 * year + year / 4 - year / 100 + year / 400);
	if (yday < 0) {
		leap = (year % 4 == 0) && (year % 100 || (year % 400 == 0));
		yday = 365 + leap + yday;
		year--;
	}
	mon = (yday + 31) * 10 / 306;
	mday = yday - (367 * mon / 12 - 30) + 1;
	if (yday >= 306) {
		year++;
		mon -= 10;
	} else {
		mon += 2;
	}
	tp->ngx_tm_sec = (int) sec;
	tp->ngx_tm_min = (int) min;
	tp->ngx_tm_hour = (int) hour;
	tp->ngx_tm_mday = (int) mday;
	tp->ngx_tm_mon = (int) mon;
	tp->ngx_tm_year = (int) year;
	tp->ngx_tm_wday = (int) wday;
}
`

func TestCProducerFieldRangeBoundObservations(t *testing.T) {
	// The vulnerable producer: the year field is stored from a local whose
	// whole derivation carries no bound, which is the fact the CVE's
	// consumers had no way to ask about.
	got := ccProducerRangeObs(t, ccVulnGmtime)
	want := "producer_field_unbounded via=tp;field=ngx_tm_year;value=year;guard=missing_upper_bound"
	if !hasLine(got, want) {
		t.Fatalf("vulnerable ngx_tm_year: got %q want %q among them", got, want)
	}

	// The fields the arithmetic reduces with a modulo are bounded by that
	// modulus in both revisions; the missing polarity is not a claim that
	// every field is unbounded, only the ones nothing bounds.
	for _, src := range []string{ccVulnGmtime, ccFixedGmtime} {
		got := ccProducerRangeObs(t, src)
		want := "producer_field_bounded via=tp;field=ngx_tm_sec;value=sec;guard=modulo;bound=60;bound_var=sec"
		if !hasLine(got, want) {
			t.Fatalf("ngx_tm_sec modulo bound: got %q want %q among them", got, want)
		}
		want = "producer_field_bounded via=tp;field=ngx_tm_wday;value=wday;guard=modulo;bound=7;bound_var=wday"
		if !hasLine(got, want) {
			t.Fatalf("ngx_tm_wday modulo bound: got %q want %q among them", got, want)
		}
	}

	// The fixed producer: the clamp on days is credited to the year field,
	// through the local the stored value derives from and under the fixing
	// commit's own names only as data -- nothing here keys on them.
	got = ccProducerRangeObs(t, ccFixedGmtime)
	want = "producer_field_bounded via=tp;field=ngx_tm_year;value=year;guard=clamp;bound=2932896;bound_var=days"
	if !hasLine(got, want) {
		t.Fatalf("fixed ngx_tm_year clamp: got %q want %q among them", got, want)
	}
	unwanted := "producer_field_unbounded via=tp;field=ngx_tm_year;value=year;guard=missing_upper_bound"
	if hasLine(got, unwanted) {
		t.Fatalf("fixed ngx_tm_year still reported unbounded: %q", got)
	}

	// A proceed comparison against a real bound credits the same way, and a
	// sign test does not: `year < 10000` bounds, `t < 0` does not.
	got = ccProducerRangeObs(t, `
void clamp_year(long t, struct out *o) {
	int year = t / 86400;
	if (year < 10000) {
		o->year = year;
	}
}
`)
	want = "producer_field_bounded via=o;field=year;value=year;guard=clamp;bound=10000;bound_var=year"
	if !hasLine(got, want) {
		t.Fatalf("proceed bound: got %q want %q among them", got, want)
	}

	// A stored parameter is an input this function bounds nothing about, and
	// says so.
	got = ccProducerRangeObs(t, `
void copy_in(int raw, struct out *o) {
	o->raw = raw;
}
`)
	want = "producer_field_unbounded via=o;field=raw;value=raw;guard=missing_upper_bound"
	if !hasLine(got, want) {
		t.Fatalf("stored parameter: got %q want %q among them", got, want)
	}

	// A local computed from a constant cannot grow and pairs nothing, and a
	// member-selection right-hand side is someone else's storage.
	got = ccProducerRangeObs(t, `
struct out { int code, other; };
void fill(struct out *o) {
	int code = 5;
	o->code = code;
	o->other = o->code;
}
`)
	if len(got) != 0 {
		t.Fatalf("constant and member stores: got %q want none", got)
	}

	// A field of an object this function owns is not an output: only a
	// parameter's field escapes to a caller.
	got = ccProducerRangeObs(t, `
struct out { int year; };
int local_only(long t) {
	struct out mine;
	int year = t / 86400;
	mine.year = year;
	return mine.year;
}
`)
	if len(got) != 0 {
		t.Fatalf("local object field: got %q want none", got)
	}
}
