// Package textpattern runs a data-defined text-pattern profile over files that do not need
// a language parser. The scanner mechanics are generic; the adapter metadata declares the
// patterns, file extensions, emitted event path, and the concept label for that event.
package textpattern

import (
	"bytes"
	"encoding/gob"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/extract/nir"
	"github.com/vyprai/vyql/extract/parsecache"
	"github.com/vyprai/vyql/parser"
)

type textPatternProfile struct {
	Event              string
	CacheKey           string
	Extensions         map[string]bool
	Direct             []*regexp.Regexp
	Assignment         *regexp.Regexp
	ExcludedValues     map[string]bool
	ExcludedPrefixes   []string
	ExcludedSubstrings []string
	MinValueClasses    int
}

var (
	profileOnce sync.Once
	profile     textPatternProfile
)

// Extensions returns the file suffixes this data-defined text profile applies to.
func Extensions() map[string]bool {
	out := map[string]bool{}
	for ext := range loadProfile().Extensions {
		out[ext] = true
	}
	return out
}

// textPatternHits is the cached per-file result: the 1-based line numbers carrying a
// profile match. nil/empty means a clean file and is cached as well.
type textPatternHits struct{ Lines []int }

func Extract(files []string, root string) (nir.Program, error) {
	cfg := loadProfile()
	var prog nir.Program
	prog.SelfName = "self"
	// Stat fast-path: the result depends only on file content plus the profile key, so an
	// unchanged file's hits are replayed instead of re-reading and re-scanning it.
	cache := parsecache.Shared()
	var auxKeys map[string]string
	var cached map[string][]byte
	if cache != nil {
		auxKeys = cache.AuxStatKeys(root, files, cfg.CacheKey)
		keyList := make([]string, 0, len(auxKeys))
		for _, k := range auxKeys {
			keyList = append(keyList, k)
		}
		cached = cache.GetManyRaw(keyList)
	}
	writes := map[string][]byte{}
	for _, f := range files {
		rel := relPath(root, f)
		var lines []int
		if k, ok := auxKeys[f]; ok {
			if raw, hit := cached[k]; hit {
				if h, ok := decodeHits(raw); ok {
					lines = h.Lines
					addEvents(&prog, cfg.Event, rel, lines)
					continue
				}
			}
		}
		data, err := os.ReadFile(f)
		if err != nil || isBinary(data) {
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			if cfg.matchLine(line) {
				lines = append(lines, i+1)
			}
		}
		if k, ok := auxKeys[f]; ok {
			writes[k] = encodeHits(textPatternHits{Lines: lines})
		}
		addEvents(&prog, cfg.Event, rel, lines)
	}
	if cache != nil && len(writes) > 0 {
		cache.PutManyRaw(writes)
	}
	return prog, nil
}

// addEvents appends a module for rel if the profile matched any lines.
func addEvents(prog *nir.Program, event, rel string, lines []int) {
	if len(lines) == 0 {
		return
	}
	var body []nir.Stmt
	for _, ln := range lines {
		loc := rel + ":" + itoa(ln)
		body = append(body, nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: event, Loc: loc},
			Path:   event, Method: lastSeg(event), Loc: loc}})
	}
	fn := nir.FuncDef{Name: "__text_patterns__", Body: body, Loc: rel + ":1"}
	prog.Modules = append(prog.Modules, nir.Module{Key: rel, File: rel, Body: []nir.Stmt{fn}})
}

func encodeHits(h textPatternHits) []byte {
	var buf bytes.Buffer
	_ = gob.NewEncoder(&buf).Encode(h)
	return buf.Bytes()
}

func decodeHits(raw []byte) (textPatternHits, bool) {
	var h textPatternHits
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&h); err != nil {
		return textPatternHits{}, false
	}
	return h, true
}

func (cfg textPatternProfile) matchLine(line string) bool {
	for _, re := range cfg.Direct {
		if re.MatchString(line) {
			return true
		}
	}
	if cfg.Assignment != nil {
		m := cfg.Assignment.FindStringSubmatch(line)
		if m == nil {
			return false
		}
		raw := m[2]
		val := strings.ToLower(raw)
		if cfg.ExcludedValues[val] {
			return false
		}
		for _, p := range cfg.ExcludedPrefixes {
			if strings.HasPrefix(val, strings.ToLower(p)) {
				return false
			}
		}
		for _, sub := range cfg.ExcludedSubstrings {
			if strings.Contains(val, strings.ToLower(sub)) {
				return false
			}
		}
		if charClasses(raw) < cfg.MinValueClasses {
			return false
		}
		return true
	}
	return false
}

// charClasses counts how many of {lowercase, uppercase, digit, symbol} appear in s.
func charClasses(s string) int {
	var lower, upper, digit, symbol bool
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			symbol = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, symbol} {
		if b {
			n++
		}
	}
	return n
}

func loadProfile() textPatternProfile {
	profileOnce.Do(func() {
		raw := string(datadir.MustRead("adapters/textpattern.vyql"))
		decls, err := parser.Parse(raw)
		if err != nil {
			panic("textpattern: parse adapters/textpattern.vyql: " + err.Error())
		}
		var meta map[string]any
		for _, d := range decls {
			if ad, ok := d.(*parser.AdapterDecl); ok && ad.Name == "textpattern" {
				meta = ad.Meta
				break
			}
		}
		if meta == nil {
			panic("textpattern: missing adapter metadata")
		}
		profile = textPatternProfile{
			Event:              metaString(meta, "text_pattern_event"),
			CacheKey:           metaString(meta, "text_pattern_cache_key"),
			Extensions:         stringSet(metaList(meta, "text_pattern_extensions")),
			ExcludedValues:     stringSetLower(metaList(meta, "text_pattern_excluded_values")),
			ExcludedPrefixes:   metaList(meta, "text_pattern_excluded_prefixes"),
			ExcludedSubstrings: metaList(meta, "text_pattern_excluded_substrings"),
			MinValueClasses:    metaInt(meta, "text_pattern_min_value_classes"),
		}
		if profile.Event == "" || profile.CacheKey == "" {
			panic("textpattern: text_pattern_event and text_pattern_cache_key are required")
		}
		if profile.MinValueClasses == 0 {
			profile.MinValueClasses = 1
		}
		for _, pattern := range metaList(meta, "text_pattern_direct") {
			profile.Direct = append(profile.Direct, regexp.MustCompile(pattern))
		}
		if names := metaList(meta, "text_pattern_assignment_names"); len(names) > 0 {
			minLen := metaInt(meta, "text_pattern_assignment_value_min")
			if minLen == 0 {
				minLen = 1
			}
			profile.Assignment = regexp.MustCompile(`(?i)(["']?(?:` + strings.Join(names, "|") + `)["']?)\s*[:=]\s*["'` + "`" + `]([^"'` + "`" + `\s]{` + strconv.Itoa(minLen) + `,})["'` + "`" + `]`)
		}
	})
	return profile
}

func metaString(meta map[string]any, key string) string {
	if s, ok := meta[key].(string); ok {
		return s
	}
	return ""
}

func metaList(meta map[string]any, key string) []string {
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

func metaInt(meta map[string]any, key string) int {
	n, _ := strconv.Atoi(metaString(meta, key))
	return n
}

func stringSet(vals []string) map[string]bool {
	out := map[string]bool{}
	for _, v := range vals {
		if v != "" {
			out[v] = true
		}
	}
	return out
}

func stringSetLower(vals []string) map[string]bool {
	out := map[string]bool{}
	for _, v := range vals {
		if v != "" {
			out[strings.ToLower(v)] = true
		}
	}
	return out
}

func isBinary(data []byte) bool {
	n := len(data)
	if n > 4096 {
		n = 4096
	}
	for i := 0; i < n; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

func relPath(root, f string) string {
	if rel, err := filepath.Rel(root, f); err == nil {
		return rel
	}
	return filepath.Base(f)
}

func lastSeg(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return path
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
