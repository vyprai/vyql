package parser

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestAdaptersAvoidLegacyStructuredTokenHasSyntax(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	adapterRoot := filepath.Join(root, "vyql", "adapters")
	legacy := regexp.MustCompile(`\b(?:has|lacks)\s+"(?:call_path|literal|selector|identifier|function_name|class_name|class_base|class_bases|attr_path|decorator_path|decorator_method|param_name|param_type|param_index|var_name|return):`)

	var hits []string
	err := filepath.WalkDir(adapterRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".vyql" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for i, line := range strings.Split(string(data), "\n") {
			if legacy.MatchString(line) {
				hits = append(hits, rel+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) > 0 {
		t.Fatalf("use structured flag predicates such as `call path`, `literal`, `selector`, `function`, or `token <name>` instead of legacy structured-token has/lacks:\n%s", strings.Join(hits, "\n"))
	}
}

func TestSecretComparisonReviewUsesStructuredFlagPredicates(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	adapterRoot := filepath.Join(root, "vyql", "adapters")

	var hits []string
	err := filepath.WalkDir(adapterRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".vyql" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		decls, err := Parse(string(data))
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, decl := range decls {
			ad, ok := decl.(*AdapterDecl)
			if !ok {
				continue
			}
			for _, mapping := range ad.Mappings {
				if mapping.Concept != "code.SecretComparisonReview" || mapping.Flag == nil {
					continue
				}
				for _, pred := range mapping.Flag.Predicates {
					if pred.Property != "tokens" {
						continue
					}
					for _, value := range pred.Values {
						if isStructuredFlagToken(value) {
							continue
						}
						hits = append(hits, rel+": unstructured SecretComparisonReview token "+strconv.Quote(value))
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) > 0 {
		t.Fatalf("SecretComparisonReview must use AST/structured predicates, not raw has/lacks text:\n%s", strings.Join(hits, "\n"))
	}
}

func TestMultipleDropdownScalarFallbackUsesAstPredicates(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	adapterRoot := filepath.Join(root, "vyql", "adapters")

	var hits []string
	err := filepath.WalkDir(adapterRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".vyql" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		decls, err := Parse(string(data))
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, decl := range decls {
			ad, ok := decl.(*AdapterDecl)
			if !ok {
				continue
			}
			for _, mapping := range ad.Mappings {
				if mapping.Concept != "code.MultipleDropdownScalarFallbackMissing" || mapping.Flag == nil {
					continue
				}
				for _, pred := range mapping.Flag.Predicates {
					if pred.Property != "tokens" {
						continue
					}
					for _, value := range pred.Values {
						if !isStructuredFlagToken(value) || strings.HasPrefix(value, "assign:") {
							hits = append(hits, rel+": non-AST MultipleDropdownScalarFallbackMissing predicate "+strconv.Quote(value))
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) > 0 {
		t.Fatalf("MultipleDropdownScalarFallbackMissing must use AST-backed predicates such as `literal`, `token subscript`, `token identifier`, or `call arg`, not raw has/lacks or compact assign text:\n%s", strings.Join(hits, "\n"))
	}
}

func isStructuredFlagToken(value string) bool {
	return strings.Contains(value, ":") || strings.Contains(value, "=")
}
