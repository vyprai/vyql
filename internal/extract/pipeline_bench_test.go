package extract_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
)

// The pipeline's cost is dominated by allocation rather than by algorithmic work — a scan
// of a few thousand Java files churns gigabytes and spends much of its CPU in the garbage
// collector. These benchmarks exist so that a claimed improvement is a number: run them
// with -benchmem and compare B/op and allocs/op, which move long before ns/op does.
//
//	go test -run '^$' -bench . -benchmem ./internal/extract/
//
// The corpus is generated rather than vendored so the benchmark runs anywhere, including
// CI, with no external checkout. It is deliberately shaped like the code that drives the
// hot paths — packages and imports, nested classes and methods, call chains, string
// concatenation, try/catch/finally, and annotations — rather than being minimal.

// benchCorpus writes n synthetic Java files and returns their paths and the root.
// Deterministic: the same n always produces byte-identical files, so two runs of the
// benchmark differ only by the code under test.
func benchCorpus(tb testing.TB, n int) (files []string, root string) {
	tb.Helper()
	root = tb.TempDir()
	for i := range n {
		var b strings.Builder
		fmt.Fprintf(&b, "package com.example.mod%d;\n\n", i%16)
		b.WriteString("import java.util.List;\nimport java.util.Map;\nimport java.sql.Connection;\n\n")
		fmt.Fprintf(&b, "@Service\npublic class Handler%d {\n", i)
		b.WriteString("    private final Connection conn;\n    private final Map<String, List<String>> cache;\n\n")
		for m := range 8 {
			fmt.Fprintf(&b, "    public String handle%d(String input, int limit) {\n", m)
			b.WriteString("        String query = \"SELECT * FROM t WHERE c = '\" + input + \"'\";\n")
			b.WriteString("        StringBuilder sb = new StringBuilder();\n")
			b.WriteString("        for (String row : cache.get(input)) {\n")
			b.WriteString("            sb.append(row.trim()).append(\",\").append(limit);\n")
			b.WriteString("        }\n")
			b.WriteString("        lock.lock();\n")
			b.WriteString("        try {\n")
			b.WriteString("            conn.createStatement().executeQuery(query);\n")
			b.WriteString("        } catch (Exception e) {\n")
			b.WriteString("            log.error(\"failed: \" + e.getMessage());\n")
			b.WriteString("        } finally {\n")
			b.WriteString("            lock.unlock();\n")
			b.WriteString("        }\n")
			b.WriteString("        return sb.toString();\n    }\n\n")
		}
		b.WriteString("}\n")
		p := filepath.Join(root, fmt.Sprintf("Handler%d.java", i))
		if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
			tb.Fatal(err)
		}
		files = append(files, p)
	}
	return files, root
}

// BenchmarkJavaExtract measures the frontend alone: tree-sitter parse plus CST→NIR
// conversion. This is where the cgo boundary and the per-node allocations live.
func BenchmarkJavaExtract(b *testing.B) {
	files, root := benchCorpus(b, 48)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		prog, err := treesitter.ExtractJava(files, root)
		if err != nil {
			b.Fatal(err)
		}
		if len(prog.Modules) != len(files) {
			b.Fatalf("extracted %d modules, want %d", len(prog.Modules), len(files))
		}
	}
}

// BenchmarkJavaLower measures lowering alone — NIR to the graph, including dataflow and
// the CFG metadata — against a corpus extracted once outside the timed loop.
func BenchmarkJavaLower(b *testing.B) {
	files, root := benchCorpus(b, 48)
	prog, err := treesitter.ExtractJava(files, root)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := lowering.Lower(prog, true); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkJavaExtractAndLower measures both together, which is what a scan actually
// pays. Kept separate from the two above so a change that moves cost across the boundary
// rather than removing it is visible.
func BenchmarkJavaExtractAndLower(b *testing.B) {
	files, root := benchCorpus(b, 48)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		prog, err := treesitter.ExtractJava(files, root)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := lowering.Lower(prog, true); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLowerScaling reports cost per file at two corpus sizes. Allocation that grows
// faster than the corpus is the signature of the blow-up that makes a mid-sized
// repository exhaust memory, and a per-file number makes it visible on a corpus small
// enough to run safely.
func BenchmarkLowerScaling(b *testing.B) {
	for _, n := range []int{16, 64} {
		b.Run(fmt.Sprintf("files=%d", n), func(b *testing.B) {
			files, root := benchCorpus(b, n)
			prog, err := treesitter.ExtractJava(files, root)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := lowering.Lower(prog, true); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n), "ns/file")
		})
	}
}
