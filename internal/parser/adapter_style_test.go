package parser

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/datadir"
)

// testRepoRoot walks up from this file until it finds the directory holding the
// runtime data tree. Counting "../.." instead would pin the depth of this package
// below the repository root, which differs between this repository (parser/ sits
// under go/) and the published one (parser/ sits at the root).
func testRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "vyql", "bindings")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("locate repo root from %s: no ancestor contains vyql/bindings", file)
		}
		dir = parent
	}
}

func TestAdaptersAvoidLegacyStructuredTokenHasSyntax(t *testing.T) {
	root := testRepoRoot(t)
	bindingRoot := filepath.Join(root, "vyql", "bindings")
	legacy := regexp.MustCompile(`\b(?:has|lacks)\s+"(?:call_path|literal|selector|identifier|function_name|class_name|class_base|class_bases|attr_path|decorator_path|decorator_method|param_name|param_type|param_index|var_name|return):`)

	var hits []string
	err := filepath.WalkDir(bindingRoot, func(path string, d os.DirEntry, err error) error {
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
	root := testRepoRoot(t)
	bindingRoot := filepath.Join(root, "vyql", "bindings")

	var hits []string
	err := filepath.WalkDir(bindingRoot, func(path string, d os.DirEntry, err error) error {
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
		decls, err := parseV2DefinitionsForTest(string(data))
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, decl := range decls {
			ad, ok := decl.(*BindingSet)
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
	root := testRepoRoot(t)
	bindingRoot := filepath.Join(root, "vyql", "bindings")

	var hits []string
	err := filepath.WalkDir(bindingRoot, func(path string, d os.DirEntry, err error) error {
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
		decls, err := parseV2DefinitionsForTest(string(data))
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, decl := range decls {
			ad, ok := decl.(*BindingSet)
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

func TestJavaScriptContextFlowFlagsUseAstPredicates(t *testing.T) {
	sources, err := datadir.ReadVYQLDir("bindings/javascript")
	if err != nil {
		t.Fatal(err)
	}
	var decls []Decl
	for _, source := range sources {
		parsed, err := parseV2DefinitionsForTest(string(source.Data))
		if err != nil {
			t.Fatalf("parse %s: %v", source.Name, err)
		}
		decls = append(decls, parsed...)
	}
	structuralConcepts := map[string]bool{
		"code.StoredHtmlWrite":                          true,
		"code.UnescapedHtmlOptionRenderer":              true,
		"code.HighlightedSearchResultHtmlEscapeMissing": true,
		"code.UnescapedTableExportHtml":                 true,
		"code.UnescapedHtmlPresenter":                   true,
		"code.UninitializedBufferExposure":              true,
		"code.UnescapedChartTooltipHtml":                true,
		"code.UnescapedChartTooltipDataName":            true,
		"code.DropdownEntryLabelInnerHtmlXss":           true,
		"code.PrivilegedContainer":                      true,
		"code.DefaultPermissiveCorsConfig":              true,
		"code.WebSocketUpgradeMissingOriginCheck":       true,
		"code.JobOutputEventUpdateAuthorizationBypass":  true,
		"code.MethodGatedRedirectValidationBypass":      true,
		"code.CinnyServiceWorkerMediaAuthLeak":          true,
		"code.McpToolCommandTemplateExecution":          true,
		"code.CommandStringWrapperExecution":            true,
		"code.DefaultExternalRelaySecretExposure":       true,
		"code.ExternalSettingTokenSyncUrlExposure":      true,
		"code.BrowserPostExportMissingOriginGuard":      true,
		"code.UrlPathParameterCaseNormalizationBypass":  true,
		"code.GitPackSignatureSearchParsingBypass":      true,
	}

	var hits []string
	for _, decl := range decls {
		ad, ok := decl.(*BindingSet)
		if !ok {
			continue
		}
		for _, mapping := range ad.Mappings {
			if !structuralConcepts[mapping.Concept] || mapping.Flag == nil {
				continue
			}
			for _, pred := range mapping.Flag.Predicates {
				if pred.Property != "tokens" {
					continue
				}
				for _, value := range pred.Values {
					if !isStructuredFlagToken(value) {
						hits = append(hits, mapping.Concept+": raw token predicate "+strconv.Quote(value))
					}
				}
			}
		}
	}
	if len(hits) > 0 {
		t.Fatalf("JavaScript context-flow flags must use AST-backed predicates, not raw has/lacks text:\n%s", strings.Join(hits, "\n"))
	}
}

func TestFlowAwareFlagsUseAstPredicates(t *testing.T) {
	root := testRepoRoot(t)
	bindingRoot := filepath.Join(root, "vyql", "bindings")

	var hits []string
	err := filepath.WalkDir(bindingRoot, func(path string, d os.DirEntry, err error) error {
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
		decls, err := parseV2DefinitionsForTest(string(data))
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, decl := range decls {
			ad, ok := decl.(*BindingSet)
			if !ok {
				continue
			}
			for _, mapping := range ad.Mappings {
				if mapping.Flag == nil || !flagHasFlowPredicate(mapping.Flag) {
					continue
				}
				for _, pred := range mapping.Flag.Predicates {
					if pred.Property != "tokens" {
						continue
					}
					for _, value := range pred.Values {
						if !isStructuredFlagToken(value) {
							hits = append(hits, rel+": flow-aware flag "+mapping.Concept+" uses raw token predicate "+strconv.Quote(value))
						}
					}
				}
				for _, operand := range mapping.Flag.Operands {
					for _, pred := range operand.Predicates {
						if pred.Property != "tokens" {
							continue
						}
						for _, value := range pred.Values {
							if !isStructuredFlagToken(value) {
								hits = append(hits, rel+": flow-aware flag "+mapping.Concept+" uses raw operand token predicate "+strconv.Quote(value))
							}
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
		t.Fatalf("flow-aware flags must use AST/structured predicates around `flows to`, not raw has/lacks text:\n%s", strings.Join(hits, "\n"))
	}
}

func TestConvertedContextFlagsUseStructuredPredicates(t *testing.T) {
	root := testRepoRoot(t)
	bindingRoot := filepath.Join(root, "vyql", "bindings")
	structuralConcepts := map[string]bool{
		"code.EnvFileVariableInjection":                       true,
		"code.ForOwnRecursiveDefaultsPrototypePollution":      true,
		"code.PgEscapeStringSqlFilterInjection":               true,
		"code.RecursiveObjectParentResolveWithoutCycleGuard":  true,
		"code.ShellTruePackageManagerProbe":                   true,
		"code.TemplateDirectoryHiddenGlobCopy":                true,
		"code.CallerControlledFilenameComponentPathTraversal": true,
		"code.UnfilteredAgentCommandTag":                      true,
		"code.UnsanitizedSvgUpload":                           true,
		"code.UnvalidatedSqlIdentifierInterpolation":          true,
		"code.LeagueCommonMarkUnsafeHtmlMode":                 true,
		"code.IsolateLevelIncrementWithoutCap":                true,
		"code.UnboundedRouteFilenameCacheAccess":              true,
	}

	var hits []string
	err := filepath.WalkDir(bindingRoot, func(path string, d os.DirEntry, err error) error {
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
		decls, err := parseV2DefinitionsForTest(string(data))
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, decl := range decls {
			ad, ok := decl.(*BindingSet)
			if !ok {
				continue
			}
			for _, mapping := range ad.Mappings {
				if !structuralConcepts[mapping.Concept] || mapping.Flag == nil {
					continue
				}
				for _, pred := range mapping.Flag.Predicates {
					if pred.Property != "tokens" {
						continue
					}
					for _, value := range pred.Values {
						if !isStructuredFlagToken(value) {
							hits = append(hits, rel+": "+mapping.Concept+" raw token predicate "+strconv.Quote(value))
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
		t.Fatalf("converted context flags must use AST/structured predicates, not raw has/lacks text:\n%s", strings.Join(hits, "\n"))
	}
}

func flagHasFlowPredicate(flag *BindingPresence) bool {
	for _, pred := range flag.Predicates {
		if pred.Subject == "flow_to" {
			return true
		}
	}
	return false
}

func isStructuredFlagToken(value string) bool {
	for _, prefix := range structuredFlagTokenPrefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

var structuredFlagTokenPrefixes = []string{
	"annotation:",
	"assign:",
	"attr_path:",
	"binary:",
	"bound:",
	"call:",
	"call_arg:",
	"call_order:",
	"call_path:",
	"catch_type:",
	"class_base:",
	"class_bases=",
	"class_name:",
	"decorator_path:",
	"decorator_method:",
	"expr:",
	"field:",
	"function_name:",
	"identifier:",
	"index:",
	"lang=",
	"literal:",
	"name=",
	"param_index:",
	"param_name:",
	"param_type:",
	"prop:",
	"python_review:",
	"regex:",
	"selector:",
	"shell=",
	"slice:",
	"subscript:",
	"trait:",
	"var_name:",
}
