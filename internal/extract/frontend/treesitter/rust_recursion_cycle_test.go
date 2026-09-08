package treesitter_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
)

// rust-protobuf's CodedInputStream skipped an unknown group by walking it and answering a
// nested START_GROUP by skipping that group too. The recursion is MUTUAL -- skip_group calls
// skip_field and skip_field's StartGroup arm calls skip_group back -- so a message of a few
// thousand bytes exhausts the stack of whoever decodes it (CVE-2025-53605, CWE-674). The
// budget already existed on the struct: incr_recursion compares recursion_level against
// recursion_limit, and merge_message already spent it. The fix spends it on the group path
// too, and touches nothing else.
//
// Both halves of that have to be readable: the cycle, which no single function's body states,
// and the budget, which lives behind a call to a helper four hundred lines above.
const rustSkipGroupUnbounded = `
impl<'a> CodedInputStream<'a> {
    #[inline]
    pub(crate) fn incr_recursion(&mut self) -> crate::Result<()> {
        if self.recursion_level >= self.recursion_limit {
            return Err(ProtobufError::WireError(WireError::OverRecursionLimit));
        }
        self.recursion_level += 1;
        Ok(())
    }

    #[inline]
    pub(crate) fn decr_recursion(&mut self) {
        self.recursion_level -= 1;
    }

    fn skip_group(&mut self) -> crate::Result<()> {
        while !self.eof()? {
            let wire_type = self.read_tag_unpack()?.1;
            if wire_type == WireType::EndGroup {
                break;
            }
            self.skip_field(wire_type)?;
        }
        Ok(())
    }

    pub fn skip_field(&mut self, wire_type: WireType) -> crate::Result<()> {
        match wire_type {
            WireType::Varint => self.read_raw_varint64().map(|_| ()),
            WireType::StartGroup => self.skip_group(),
            _ => Ok(()),
        }
    }

    pub fn merge_message<M: Message>(&mut self, message: &mut M) -> crate::Result<()> {
        self.incr_recursion()?;
        let ret = self.merge_message_no_depth_check(message);
        self.decr_recursion();
        ret
    }

    fn eof(&mut self) -> crate::Result<bool> {
        Ok(self.source.pos >= self.source.buf.len())
    }

    fn read_tag_unpack(&mut self) -> crate::Result<(u32, WireType)> {
        let v = self.read_raw_varint64()?;
        Ok(((v >> 3) as u32, WireType::Varint))
    }
}
`

// The fix (f06992f4, released 3.7.2): skip_group spends the budget, and the walk it did
// inline moves into skip_group_no_depth_check. skip_field is byte-identical.
const rustSkipGroupBounded = `
impl<'a> CodedInputStream<'a> {
    #[inline]
    pub(crate) fn incr_recursion(&mut self) -> crate::Result<()> {
        if self.recursion_level >= self.recursion_limit {
            return Err(ProtobufError::WireError(WireError::OverRecursionLimit));
        }
        self.recursion_level += 1;
        Ok(())
    }

    #[inline]
    pub(crate) fn decr_recursion(&mut self) {
        self.recursion_level -= 1;
    }

    fn skip_group(&mut self) -> crate::Result<()> {
        self.incr_recursion()?;
        let ret = self.skip_group_no_depth_check();
        self.decr_recursion();
        ret
    }

    fn skip_group_no_depth_check(&mut self) -> crate::Result<()> {
        while !self.eof()? {
            let wire_type = self.read_tag_unpack()?.1;
            if wire_type == WireType::EndGroup {
                break;
            }
            self.skip_field(wire_type)?;
        }
        Ok(())
    }

    pub fn skip_field(&mut self, wire_type: WireType) -> crate::Result<()> {
        match wire_type {
            WireType::Varint => self.read_raw_varint64().map(|_| ()),
            WireType::StartGroup => self.skip_group(),
            _ => Ok(()),
        }
    }

    fn eof(&mut self) -> crate::Result<bool> {
        Ok(self.source.pos >= self.source.buf.len())
    }

    fn read_tag_unpack(&mut self) -> crate::Result<(u32, WireType)> {
        let v = self.read_raw_varint64()?;
        Ok(((v >> 3) as u32, WireType::Varint))
    }
}
`

// rustRecursionCycles lowers one Rust source and returns the tokens of every
// analysis.recursion.cycle event it produced, one string per event.
func rustRecursionCycles(t *testing.T, src string) []string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "mod.rs")
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractRust([]string{file}, dir)
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
	var out []string
	for _, n := range nodes {
		if n.Prop("callee_path") == "analysis.recursion.cycle" {
			out = append(out, strings.ReplaceAll(n.Prop("str_args"), "\x00", " "))
		}
	}
	sort.Strings(out)
	return out
}

func TestRustMutualRecursionWithoutADepthBudget(t *testing.T) {
	events := rustRecursionCycles(t, rustSkipGroupUnbounded)
	if len(events) != 2 {
		t.Fatalf("expected the two edges of the skip_group/skip_field cycle, got %q", events)
	}
	for _, ev := range events {
		if !strings.Contains(ev, "cycle=mutual") || !strings.Contains(ev, "cycle_length=2") {
			t.Fatalf("cycle not recorded as the mutual pair it is: %q", ev)
		}
		// merge_message spends the budget, but merge_message is not on this cycle. A guard
		// declared in the file is not a guard the recursion runs.
		if !strings.Contains(ev, "depth_budget=absent") {
			t.Fatalf("a budget the cycle never spends was credited to it: %q", ev)
		}
	}
	if !strings.Contains(events[0]+events[1], "function=skip_group") ||
		!strings.Contains(events[0]+events[1], "function=skip_field") {
		t.Fatalf("both call sites of the cycle should be named: %q", events)
	}
}

func TestRustMutualRecursionBoundedByADelegatedDepthBudget(t *testing.T) {
	events := rustRecursionCycles(t, rustSkipGroupBounded)
	if len(events) != 3 {
		t.Fatalf("expected the three edges of the fixed cycle, got %q", events)
	}
	for _, ev := range events {
		if !strings.Contains(ev, "depth_budget=present") || !strings.Contains(ev, "budget=self.recursion_level") {
			t.Fatalf("the budget skip_group now spends was not credited: %q", ev)
		}
	}
}
