package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccPopulationObs runs the counted-population observation over one translation
// unit and returns the emitted facts as
// "<path>|counter=..|container=..|element=..|sync=..|write=..|counted=.." text.
// The file name picks the grammar, so a .cpp case reads the C++ spellings.
func ccPopulationObs(t *testing.T, file, src string) []string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, file)
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	extract := ExtractC
	if strings.HasSuffix(file, ".cpp") {
		extract = ExtractCPP
	}
	prog, err := extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	var walk func([]nir.Stmt)
	walk = func(body []nir.Stmt) {
		for _, st := range body {
			switch s := st.(type) {
			case nir.ClassDef:
				walk(s.Body)
			case nir.FuncDef:
				walk(s.Body)
			case nir.ExprStmt:
				call, ok := s.Value.(nir.Call)
				if !ok || !strings.HasPrefix(call.Path, "analysis.element_count.") {
					continue
				}
				parts := []string{call.Path}
				for _, a := range call.Args {
					if konst, ok := a.(nir.Const); ok {
						parts = append(parts, konst.Value)
					}
				}
				out = append(out, strings.Join(parts, "|"))
			}
		}
	}
	walk(prog.Modules[0].Body)
	return out
}

// ccPopulationStale returns only the facts reporting a counter the population
// left behind.
func ccPopulationStale(facts []string) []string {
	var out []string
	for _, f := range facts {
		if strings.HasPrefix(f, "analysis.element_count.uncounted_population|") {
			out = append(out, f)
		}
	}
	return out
}

// wrapLinesSmart is libass's smart line wrap (ass_render.c, CVE-2016-7969)
// reduced to the shape the defect turns on. Pass one marks a line break and
// counts the line it opens; pass two rebalances a break by moving the mark,
// and @@REBALANCE@@ is what it does there -- the parent's bare mark, or the
// fix's mark behind the count it now charges.
const wrapLinesSmart = `#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct { long x, y; } FT_Vector;
typedef struct { long xMin, xMax, yMin, yMax; } FT_BBox;

typedef struct glyph_info GlyphInfo;
struct glyph_info {
    FT_BBox bbox;
    FT_Vector pos;
    unsigned symbol;
    char linebreak;             /* the first (leading) glyph of some line ? */
    int asc, desc;
    int skip;
    struct glyph_info *next;
};

typedef struct {
    double asc, desc;
    int offset, len;
} LineInfo;

typedef struct {
    GlyphInfo *glyphs;
    int length;
    LineInfo *lines;
    int n_lines;
    double height;
    int max_glyphs;
    int max_lines;
} TextInfo;

typedef struct { int wrap_style; } render_state;
typedef struct { double line_spacing; } render_settings;

typedef struct {
    TextInfo text_info;
    render_state state;
    render_settings settings;
    void *library;
} ASS_Renderer;

#define MSGL_DBG2 6
#define DIFF(x, y) (((x) < (y)) ? (y - x) : (x - y))

static inline double d6_to_double(int x) { return x / 64.; }
static inline int double_to_d6(double x) { return (int) (x * 64); }
void ass_msg(void *priv, int lvl, const char *fmt, ...);
static void measure_text(ASS_Renderer *render_priv);
static void trim_whitespace(ASS_Renderer *render_priv);

static void
wrap_lines_smart(ASS_Renderer *render_priv, double max_text_width)
{
    int i;
    GlyphInfo *cur, *s1, *e1, *s2, *s3;
    int last_space;
    int break_type;
    int exit;
    double pen_shift_x;
    double pen_shift_y;
    int cur_line;
    int run_offset;
    TextInfo *text_info = &render_priv->text_info;

    last_space = -1;
    text_info->n_lines = 1;
    break_type = 0;
    s1 = text_info->glyphs;     // current line start
    for (i = 0; i < text_info->length; ++i) {
        int break_at = -1;
        double s_offset, len;
        cur = text_info->glyphs + i;
        s_offset = d6_to_double(s1->bbox.xMin + s1->pos.x);
        len = d6_to_double(cur->bbox.xMax + cur->pos.x) - s_offset;

        if (cur->symbol == '\n') {
            break_type = 2;
            break_at = i;
            ass_msg(render_priv->library, MSGL_DBG2,
                    "forced line break at %d", break_at);
        } else if (cur->symbol == ' ') {
            last_space = i;
        } else if (len >= max_text_width
                   && (render_priv->state.wrap_style != 2)) {
            break_type = 1;
            break_at = last_space;
            if (break_at >= 0)
                ass_msg(render_priv->library, MSGL_DBG2, "line break at %d",
                        break_at);
        }

        if (break_at != -1) {
            // need to use one more line
            // marking break_at+1 as start of a new line
            int lead = break_at + 1;    // the first symbol of the new line
            if (text_info->n_lines >= text_info->max_lines) {
                // Raise maximum number of lines
                text_info->max_lines *= 2;
                text_info->lines = realloc(text_info->lines,
                                           sizeof(LineInfo) *
                                           text_info->max_lines);
            }
            if (lead < text_info->length) {
                text_info->glyphs[lead].linebreak = break_type;
                last_space = -1;
                s1 = text_info->glyphs + lead;
                text_info->n_lines++;
            }
        }
    }

    exit = 0;
    while (!exit && render_priv->state.wrap_style != 1) {
        exit = 1;
        s3 = text_info->glyphs;
        s1 = s2 = 0;
        for (i = 0; i <= text_info->length; ++i) {
            cur = text_info->glyphs + i;
            if ((i == text_info->length) || cur->linebreak) {
                s1 = s2;
                s2 = s3;
                s3 = cur;
                if (s1 && (s2->linebreak == 1)) {   // have at least 2 lines
                    double l1, l2, l1_new, l2_new;
                    GlyphInfo *w = s2;

                    do {
                        --w;
                    } while ((w > s1) && (w->symbol == ' '));
                    while ((w > s1) && (w->symbol != ' ')) {
                        --w;
                    }
                    e1 = w;
                    while ((e1 > s1) && (e1->symbol == ' ')) {
                        --e1;
                    }
                    if (w->symbol == ' ')
                        ++w;

                    l1 = d6_to_double(((s2 - 1)->bbox.xMax + (s2 - 1)->pos.x) -
                        (s1->bbox.xMin + s1->pos.x));
                    l2 = d6_to_double(((s3 - 1)->bbox.xMax + (s3 - 1)->pos.x) -
                        (s2->bbox.xMin + s2->pos.x));
                    l1_new = d6_to_double(
                        (e1->bbox.xMax + e1->pos.x) -
                        (s1->bbox.xMin + s1->pos.x));
                    l2_new = d6_to_double(
                        ((s3 - 1)->bbox.xMax + (s3 - 1)->pos.x) -
                        (w->bbox.xMin + w->pos.x));

                    if (DIFF(l1_new, l2_new) < DIFF(l1, l2)) {
                        @@REBALANCE@@
                        s2->linebreak = 0;
                        exit = 0;
                    }
                }
            }
            if (i == text_info->length)
                break;
        }
    }
    assert(text_info->n_lines >= 1);

    measure_text(render_priv);
    trim_whitespace(render_priv);

    cur_line = 1;
    run_offset = 0;

    i = 0;
    cur = text_info->glyphs + i;
    while (i < text_info->length && cur->skip)
        cur = text_info->glyphs + ++i;
    pen_shift_x = d6_to_double(-cur->pos.x);
    pen_shift_y = 0.;

    for (i = 0; i < text_info->length; ++i) {
        cur = text_info->glyphs + i;
        if (cur->linebreak) {
            while (i < text_info->length && cur->skip && cur->symbol != '\n')
                cur = text_info->glyphs + ++i;
            double height =
                text_info->lines[cur_line - 1].desc +
                text_info->lines[cur_line].asc;
            text_info->lines[cur_line - 1].len = i -
                text_info->lines[cur_line - 1].offset;
            text_info->lines[cur_line].offset = i;
            cur_line++;
            run_offset++;
            pen_shift_x = d6_to_double(-cur->pos.x);
            pen_shift_y += height + render_priv->settings.line_spacing;
        }
        cur->pos.x += double_to_d6(pen_shift_x);
        cur->pos.y += double_to_d6(pen_shift_y);
    }
    text_info->lines[cur_line - 1].len =
        text_info->length - text_info->lines[cur_line - 1].offset;
}
`

// The counter is the invariant pass one states: a branch that marks an element
// of text_info->glyphs charges text_info->n_lines in the same branch. Pass two
// moves a mark and charges nothing, so n_lines keeps claiming a line whose
// LineInfo nothing wrote, and everything that later indexes lines[] by it
// reads an entry this routine never populated.
func TestCountedPopulationStaleCounter(t *testing.T) {
	src := strings.Replace(wrapLinesSmart, "@@REBALANCE@@", "w->linebreak = 1;", 1)
	for _, file := range []string{"ass_render.c", "ass_render.cpp"} {
		facts := ccPopulationObs(t, file, src)
		stale := ccPopulationStale(facts)
		want := "analysis.element_count.uncounted_population|counter=text_info->n_lines|container=text_info->glyphs|" +
			"element=linebreak|sync=stale|write=w->linebreak=1|counted=text_info->glyphs[lead].linebreak=break_type"
		if len(stale) != 1 || stale[0] != want {
			t.Fatalf("%s: stale facts: got %q want exactly [%s]", file, stale, want)
		}
		// The population pass one performs is reported as the counted form, so
		// the pairing is readable on a routine that keeps the count in step as
		// well.
		counted := "analysis.element_count.counted_population|counter=text_info->n_lines|container=text_info->glyphs|" +
			"element=linebreak|sync=in_step|write=text_info->glyphs[lead].linebreak=break_type|" +
			"counted=text_info->glyphs[lead].linebreak=break_type"
		if len(facts) != 2 || facts[0] != counted {
			t.Fatalf("%s: facts: got %q want the counted pass-one population first", file, facts)
		}
	}
}

// The fix charges the count in the same branch as the mark it moves -- in a
// sibling arm of it, which is why the branch a population is judged against is
// the outermost conditional and not the innermost. The same write is then the
// counted form, and nothing is reported stale.
func TestCountedPopulationCounterKeptInStep(t *testing.T) {
	fix := `if (w->linebreak || w == text_info->glyphs)
                            text_info->n_lines--;
                        if (w != text_info->glyphs)
                            w->linebreak = 1;`
	src := strings.Replace(wrapLinesSmart, "@@REBALANCE@@", fix, 1)
	facts := ccPopulationObs(t, "ass_render.c", src)
	if stale := ccPopulationStale(facts); len(stale) != 0 {
		t.Fatalf("stale facts: got %q want none once the count is charged", stale)
	}
	want := "analysis.element_count.counted_population|counter=text_info->n_lines|container=text_info->glyphs|" +
		"element=linebreak|sync=in_step|write=w->linebreak=1|counted=text_info->glyphs[lead].linebreak=break_type"
	found := false
	for _, f := range facts {
		if f == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("facts: got %q want the rebalance reported in step", facts)
	}
}

// bagFill is the same shape reduced to its parts: a walked pointer, the branch
// that populates an element by subscript and charges the count, and a second
// branch that writes the same member. Each placeholder is what one narrowing
// turns on.
const bagFill = `typedef struct { int mark; int other; } Item;
typedef struct { Item *items; Item *spare; Item head; int n; int cap; } Bag;

static Bag stats;
int recount(Bag *bag);

void fill(Bag *bag, int lead, int cond)
{
    Item *w = @@WALK@@;
    if (lead < bag->cap) {
        @@ANCHOR@@
        @@COUNT@@
    }
    if (cond) {
        @@SECOND@@
    }
    @@TAIL@@
}
`

func TestCountedPopulationNarrowing(t *testing.T) {
	base := map[string]string{
		"@@WALK@@":   "bag->items + lead",
		"@@ANCHOR@@": "bag->items[lead].mark = 1;",
		"@@COUNT@@":  "bag->n++;",
		"@@SECOND@@": "w->mark = 1;",
		"@@TAIL@@":   "",
	}
	cases := []struct {
		name  string
		with  map[string]string
		stale int
	}{
		{name: "the second branch writes the marked member and charges nothing", stale: 1},
		{
			name:  "the second branch charges the count too",
			with:  map[string]string{"@@SECOND@@": "w->mark = 1; bag->n--;"},
			stale: 0,
		},
		{
			name:  "the pointer walks a different container",
			with:  map[string]string{"@@WALK@@": "bag->spare + lead"},
			stale: 0,
		},
		{
			name:  "the counter belongs to another object",
			with:  map[string]string{"@@COUNT@@": "stats.n++;"},
			stale: 0,
		},
		{
			name:  "the counter is replaced rather than counted",
			with:  map[string]string{"@@COUNT@@": "bag->n = recount(bag);"},
			stale: 0,
		},
		{
			name:  "no population names the container by subscript",
			with:  map[string]string{"@@ANCHOR@@": "bag->head.mark = 1;"},
			stale: 0,
		},
		{
			name:  "the second branch writes another member",
			with:  map[string]string{"@@SECOND@@": "w->other = 1;"},
			stale: 0,
		},
		{
			name:  "the second write is not in a branch",
			with:  map[string]string{"@@SECOND@@": "cond = 0;", "@@TAIL@@": "w->mark = 1;"},
			stale: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := bagFill
			for key, val := range base {
				if override, ok := tc.with[key]; ok {
					val = override
				}
				src = strings.ReplaceAll(src, key, val)
			}
			stale := ccPopulationStale(ccPopulationObs(t, "bag.c", src))
			if len(stale) != tc.stale {
				t.Fatalf("stale facts: got %q want %d", stale, tc.stale)
			}
		})
	}
}
