package treesitter

import (
	"strings"
	"sync"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/parser"
)

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

func sourceVarEvent(tech, name string) (string, bool) {
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

func sourceVarEventInText(tech, text string) (string, bool) {
	for i := 0; i < len(text); i++ {
		if text[i] != '$' {
			continue
		}
		j := i + 1
		if j < len(text) && text[j] == '{' {
			j++
		}
		start := j
		for j < len(text) && sourceVarNameByte(text[j]) {
			j++
		}
		if start == j {
			continue
		}
		if event, ok := sourceVarEvent(tech, text[start:j]); ok {
			return event, true
		}
	}
	return "", false
}

func sourceVarNameByte(b byte) bool {
	return b == '_' || b == ':' || b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
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

func loadSourceVarProfiles() {
	sourceVarProfiles = map[string]sourceVarProfile{}
	files, err := datadir.ReadVYQLDirExcept("adapters", "packages")
	if err != nil {
		panic("treesitter: read adapters: " + err.Error())
	}
	selected := map[string]bool{}
	for _, file := range files {
		selected[file.Name] = true
	}
	decls, err := parser.ParseV2RuntimeSourcesSelected(v2RuntimeSourcesForProfile(files), func(src parser.V2RuntimeSource) bool {
		return selected[src.Name]
	})
	if err != nil {
		panic("treesitter: parse adapter source-var corpus: " + err.Error())
	}
	for _, d := range decls {
		ad, ok := d.(*parser.AdapterDecl)
		if !ok {
			continue
		}
		profile := sourceVarProfile{
			Event:       metaString(ad.Meta, "source_var_event"),
			Case:        metaString(ad.Meta, "source_var_case"),
			StripPrefix: metaList(ad.Meta, "source_var_strip_prefix"),
			Exact:       metaList(ad.Meta, "source_var_exact"),
			Prefix:      metaList(ad.Meta, "source_var_prefix"),
		}
		if profile.Event != "" && (len(profile.Exact) > 0 || len(profile.Prefix) > 0) {
			sourceVarProfiles[ad.Name] = profile
		}
	}
}

func v2RuntimeSourcesForProfile(files []datadir.Source) []parser.V2RuntimeSource {
	out := make([]parser.V2RuntimeSource, 0, len(files)+32)
	if core, err := datadir.ReadVYQL("ontology/concepts.vyql"); err == nil {
		for _, file := range core {
			out = append(out, parser.V2RuntimeSource{Name: file.Name, Source: string(file.Data)})
		}
	}
	if threats, err := datadir.ReadVYQLDir("ontology/threatkinds"); err == nil {
		for _, file := range threats {
			out = append(out, parser.V2RuntimeSource{Name: file.Name, Source: string(file.Data)})
		}
	}
	if mechanics, err := datadir.ReadVYQLDir("mechanics"); err == nil {
		for _, file := range mechanics {
			out = append(out, parser.V2RuntimeSource{Name: file.Name, Source: string(file.Data)})
		}
	}
	for _, file := range files {
		out = append(out, parser.V2RuntimeSource{Name: file.Name, Source: string(file.Data)})
	}
	return out
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
