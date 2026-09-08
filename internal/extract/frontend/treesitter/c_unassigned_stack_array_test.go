package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccStackArrayFacts runs one C source through the frontend and returns the
// stack-array observations it emits, keyed by function name, as
// "origin=..;array=..;size=.." text. Both members of the family are
// collected so the disjointness of the two facts can be asserted.
func ccStackArrayFacts(t *testing.T, src, path string) map[string][]string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "vla.c")
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
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
			if !ok || call.Path != path {
				continue
			}
			var parts []string
			for _, a := range call.Args {
				if konst, ok := a.(nir.Const); ok {
					parts = append(parts, konst.Value)
				}
			}
			out[fn.Name] = append(out[fn.Name], strings.Join(parts, ";"))
		}
	}
	return out
}

const ccUnassignedStackArraySrc = `
#include <stdlib.h>
#include <string.h>

#define SQUASHFS_METADATA_SIZE 8192
#define TRACE(...) do { } while(0)

enum { header_bytes = 16 };

const int preamble_len = 32;

unsigned int block_size;
int swap;
void *comp;

int read_fs_bytes(int fd, long long start, long long count, void *buf);
int compressor_uncompress(void *comp, void *dest, void *src, int size,
	int outsize, int *error);
unsigned int image_block_count(int fd);
int read_count(int fd, unsigned int *count);
int use(void *p);

/* rank 2445, unsquash-2.c: the size is the caller's, and the body never
   computes or compares it. */
void read_block_list_2(unsigned int *block_list, char *block_ptr, int blocks)
{
	if (swap) {
		unsigned int sblock_list[blocks];
		memcpy(sblock_list, block_ptr, blocks * sizeof(unsigned int));
		use(sblock_list);
	} else
		memcpy(block_list, block_ptr, blocks * sizeof(unsigned int));
}

/* rank 2445's fix: the swap happens in place and no array is declared. */
void read_block_list_2_fixed(unsigned int *block_list, char *block_ptr, int blocks)
{
	if (swap)
		use(block_ptr);
	else
		memcpy(block_list, block_ptr, blocks * sizeof(unsigned int));
}

/* rank 2445, unsquashfs.c: the size is a global the superblock wrote. */
void *inflator(void *arg)
{
	char tmp[block_size];

	compressor_uncompress(comp, tmp, arg, block_size, block_size, 0);
	return 0;
}

/* rank 2445's fix: the same buffer on the heap. */
void *inflator_fixed(void *arg)
{
	char *tmp = malloc(block_size);

	compressor_uncompress(comp, tmp, arg, block_size, block_size, 0);
	return 0;
}

/* the third origin: a local another call filled through its address. */
void read_blocks(int fd)
{
	unsigned int blocks;

	read_count(fd, &blocks);
	{
		unsigned char sblock_list[blocks];
		use(sblock_list);
	}
}

/* the bound the allocation needs, on the parameter. */
void read_block_list_2_bounded(char *block_ptr, int blocks)
{
	if (blocks > 1024)
		return;
	{
		unsigned int sblock_list[blocks];
		use(sblock_list);
	}
}

/* the same bound on the global, in the function that allocates. */
void *inflator_bounded(void *arg)
{
	if (block_size > SQUASHFS_METADATA_SIZE)
		return 0;
	{
		char tmp[block_size];
		use(tmp);
	}
	return 0;
}

/* an equality check is not a bound: it cannot be told from a sentinel test. */
void read_block_list_2_equality(char *block_ptr, int blocks)
{
	if (blocks == 0)
		return;
	{
		unsigned int sblock_list[blocks];
		use(sblock_list);
	}
}

/* a comparison of an unrelated value leaves the fact standing. */
void read_block_list_2_other(char *block_ptr, int blocks, int fd)
{
	if (fd > 3)
		return;
	{
		unsigned int sblock_list[blocks];
		use(sblock_list);
	}
}

/* the sibling fact's territory: the function computes the size itself. */
void read_block_list_assigned(int fd)
{
	unsigned int blocks = image_block_count(fd);
	unsigned char sblock_list[blocks];

	use(sblock_list);
}

/* also the sibling's: assigned from something that is not a call. */
void read_block_list_field(struct { unsigned int n; } *hdr)
{
	unsigned int blocks;

	blocks = hdr->n;
	{
		unsigned char sblock_list[blocks];
		use(sblock_list);
	}
}

/* constants the declaration states, in all three spellings. */
void fixed_sizes(void)
{
	char literal[64];
	char macro[SQUASHFS_METADATA_SIZE];
	char enumerated[header_bytes];
	char file_const[preamble_len];

	use(literal);
	use(macro);
	use(enumerated);
	use(file_const);
}

/* a name this file never declares: a header's global and a header's macro
   constant are the same text here, so neither earns a fact. */
void header_sized(void)
{
	char data[mm_max];

	use(data);
}

/* netxduo's shape, reduced from
   common/src/nx_ip_interface_address_get.c: a bare macro followed by a
   macro invocation reads as a declaration, and the subscript inside it as
   an array declarator sized by a parameter that declares nothing. */
UINT _nx_ip_interface_address_get(NX_IP *ip_ptr, UINT interface_index, ULONG *ip_address)
{

#ifndef NX_DISABLE_IPV4
TX_INTERRUPT_SAVE_AREA

    NX_TRACE_IN_LINE_INSERT(NX_TRACE_IP_ADDRESS_GET, ip_ptr, ip_ptr -> nx_ip_interface[interface_index].nx_interface_ip_address, 0);

    *ip_address = ip_ptr -> nx_ip_interface[interface_index].nx_interface_ip_address;
    return(NX_SUCCESS);
#else
    return(NX_NOT_SUPPORTED);
#endif
}

/* declared and never written: indeterminate, not unbounded. */
void indeterminate(void)
{
	int n;
	char buf[n];

	use(buf);
}
`

func TestCUnassignedSizedStackArrayObservations(t *testing.T) {
	const path = "analysis.alloc.unbounded_stack_array"
	got := ccStackArrayFacts(t, ccUnassignedStackArraySrc, path)

	want := map[string][]string{
		"read_block_list_2": {
			"origin=parameter;array=sblock_list;size=blocks;guard=missing_size_bound_check",
		},
		"inflator": {
			"origin=global;array=tmp;size=block_size;guard=missing_size_bound_check",
		},
		"read_blocks": {
			"origin=out_param;array=sblock_list;size=blocks;callee=read_count;guard=missing_size_bound_check",
		},
		"read_block_list_2_equality": {
			"origin=parameter;array=sblock_list;size=blocks;guard=missing_size_bound_check",
		},
		"read_block_list_2_other": {
			"origin=parameter;array=sblock_list;size=blocks;guard=missing_size_bound_check",
		},
	}
	for fn, wantFacts := range want {
		if len(got[fn]) != len(wantFacts) {
			t.Fatalf("%s: got %v, want %v", fn, got[fn], wantFacts)
		}
		for i, w := range wantFacts {
			if got[fn][i] != w {
				t.Errorf("%s: got %q, want %q", fn, got[fn][i], w)
			}
		}
	}
	quiet := []string{
		"read_block_list_2_fixed",      // no array at all
		"inflator_fixed",               // the heap, not the frame
		"read_block_list_2_bounded",    // the parameter is compared
		"inflator_bounded",             // the global is compared
		"read_block_list_assigned",     // the sibling fact's shape
		"read_block_list_field",        // also the sibling's
		"fixed_sizes",                  // the declaration states the capacity
		"indeterminate",                // declared and never written
		"header_sized",                 // the file does not state what the name is
		"_nx_ip_interface_address_get", // a macro invocation the grammar reads as a declaration
	}
	for _, fn := range quiet {
		if len(got[fn]) != 0 {
			t.Errorf("%s: expected no fact, got %v", fn, got[fn])
		}
	}
}

// TestCStackArrayFactsAreDisjoint holds the boundary between the new fact
// and the call-sized one it sits beside: an assigned size stays the
// sibling's, and an unassigned one is never reported by the sibling, so no
// site earns both.
func TestCStackArrayFactsAreDisjoint(t *testing.T) {
	sibling := ccStackArrayFacts(t, ccUnassignedStackArraySrc,
		"analysis.alloc.unbounded_call_sized_stack_array")
	if len(sibling["read_block_list_assigned"]) != 1 {
		t.Fatalf("read_block_list_assigned: sibling fact missing: %v", sibling)
	}
	if got := sibling["read_block_list_assigned"][0]; !strings.Contains(got, "callee=image_block_count") {
		t.Errorf("read_block_list_assigned: got %q", got)
	}
	for _, fn := range []string{"read_block_list_2", "inflator", "read_blocks"} {
		if len(sibling[fn]) != 0 {
			t.Errorf("%s: sibling fact should not fire: %v", fn, sibling[fn])
		}
	}
	mine := ccStackArrayFacts(t, ccUnassignedStackArraySrc,
		"analysis.alloc.unbounded_stack_array")
	for fn := range sibling {
		if len(mine[fn]) != 0 {
			t.Errorf("%s: both facts fired: %v / %v", fn, sibling[fn], mine[fn])
		}
	}
}
