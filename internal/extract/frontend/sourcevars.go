package frontend

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/vyprai/vyql/internal/bindings"
	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/parser"
)

// Loading the source-variable profiles lives here, not in the frontend that consumes them.
//
// A frontend must not know about concepts, and this data is binding-layer content: it decides
// that `$HTTP_USER_AGENT` in a shell script is a request-borne source. Reading it also means
// reading the VyQL corpus, which pulled `datadir` and `parser` into the tree-sitter package --
// the only two imports there that crossed a layer. The extractor now receives a lookup and knows
// nothing about where it came from.
//
// It installs itself, because the profiles are consulted DURING extraction while BindingsFor runs
// after it. The load is still lazy: registration only hands over a closure, and the corpus is read
// on the first shell or PowerShell variable that asks.

func init() { treesitter.SetSourceVarLookup(lookupSourceVar) }

type sourceVarProfile struct {
	Event       string
	Case        string
	StripPrefix []string
	Exact       []string
	Prefix      []string
}

var (
	sourceVarOnce     sync.Once
	sourceVarProfiles map[string]sourceVarProfile
)

func lookupSourceVar(tech, name string) (string, bool) {
	sourceVarOnce.Do(loadSourceVarProfiles)
	profile, ok := sourceVarProfiles[tech]
	if !ok || profile.Event == "" {
		return "", false
	}
	n := profile.normalize(name)
	for _, exact := range profile.Exact {
		if n == profile.normalize(exact) {
			return profile.Event, true
		}
	}
	for _, prefix := range profile.Prefix {
		if strings.HasPrefix(n, profile.normalize(prefix)) {
			return profile.Event, true
		}
	}
	return "", false
}

func (p sourceVarProfile) normalize(s string) string {
	if p.Case == "upper" {
		s = strings.ToUpper(s)
	}
	for _, prefix := range p.StripPrefix {
		if strings.HasPrefix(s, p.normalizeNoStrip(prefix)) {
			s = strings.TrimPrefix(s, p.normalizeNoStrip(prefix))
		}
	}
	return s
}

func (p sourceVarProfile) normalizeNoStrip(s string) string {
	if p.Case == "upper" {
		return strings.ToUpper(s)
	}
	return s
}

// loadSourceVarProfiles reads the source-var metadata out of the binding corpus.
//
// A failure here degrades to "no source variables" and says so on stderr. It used to panic:
// malformed rule-layer DATA would abort the PARSER, which is the wrong blast radius entirely --
// one bad binding file took down every scan of every language rather than costing the shell
// frontend one class of source.
func loadSourceVarProfiles() {
	sourceVarProfiles = map[string]sourceVarProfile{}
	files, err := datadir.ReadVYQLDirExcept("bindings", "packages")
	if err != nil {
		fmt.Fprintf(os.Stderr, "vyql: source-var profiles unavailable (read bindings: %v)\n", err)
		return
	}
	selected := map[string]bool{}
	for _, file := range files {
		selected[file.Name] = true
	}
	parsed, keep, err := parser.ParseV2Sources(v2DefinitionSourcesForProfile(files), func(src parser.V2DefinitionSource) bool {
		return selected[src.Name]
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "vyql: source-var profiles unavailable (parse binding corpus: %v)\n", err)
		return
	}
	sets, err := bindings.CompileSources(parsed, keep)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vyql: source-var profiles unavailable (compile binding corpus: %v)\n", err)
		return
	}
	for _, ad := range sets {
		profile := sourceVarProfile{
			Event:       sourceVarMetaString(ad.Meta, "source_var_event"),
			Case:        sourceVarMetaString(ad.Meta, "source_var_case"),
			StripPrefix: sourceVarMetaList(ad.Meta, "source_var_strip_prefix"),
			Exact:       sourceVarMetaList(ad.Meta, "source_var_exact"),
			Prefix:      sourceVarMetaList(ad.Meta, "source_var_prefix"),
		}
		if profile.Event != "" && (len(profile.Exact) > 0 || len(profile.Prefix) > 0) {
			sourceVarProfiles[ad.Name] = profile
		}
	}
}

// v2DefinitionSourcesForProfile prepends the ontology and policies the parser needs to resolve the
// binding files; only the binding metadata is read back out.
func v2DefinitionSourcesForProfile(files []datadir.Source) []parser.V2DefinitionSource {
	out := make([]parser.V2DefinitionSource, 0, len(files)+32)
	for _, dir := range []string{"ontology/concepts", "ontology/threatkinds", "policies"} {
		core, err := datadir.ReadVYQLDir(dir)
		if err != nil {
			continue
		}
		for _, file := range core {
			out = append(out, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
		}
	}
	for _, file := range files {
		out = append(out, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
	}
	return out
}

func sourceVarMetaString(meta map[string]any, key string) string {
	if s, ok := meta[key].(string); ok {
		return s
	}
	return ""
}

func sourceVarMetaList(meta map[string]any, key string) []string {
	switch v := meta[key].(type) {
	case []string:
		return v
	case string:
		if v != "" {
			return []string{v}
		}
	}
	return nil
}
