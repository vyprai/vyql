package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/extract/nir"
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
	callFlowOnce      sync.Once
	callFlowProfiles  map[string][]callFlowSpec
)

type callFlowSpec struct {
	Pattern string
	Method  bool
	Effect  nir.CallEffect
}

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
	files, err := filepath.Glob(filepath.Join(datadir.Root(), "adapters", "*.vyql"))
	if err != nil {
		panic("treesitter: glob adapters/*.vyql: " + err.Error())
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			panic("treesitter: read " + file + ": " + err.Error())
		}
		decls, err := parser.Parse(string(raw))
		if err != nil {
			panic("treesitter: parse " + file + ": " + err.Error())
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
}

func callEffectsFor(tech, path, method string) []nir.CallEffect {
	callFlowOnce.Do(loadCallFlowProfiles)
	var out []nir.CallEffect
	for _, spec := range callFlowProfiles[tech] {
		if spec.Method {
			if method == spec.Pattern {
				out = append(out, spec.Effect)
			}
			continue
		}
		if path == spec.Pattern || strings.HasSuffix(path, "."+spec.Pattern) {
			out = append(out, spec.Effect)
		}
	}
	return out
}

func loadCallFlowProfiles() {
	callFlowProfiles = map[string][]callFlowSpec{}
	files, err := filepath.Glob(filepath.Join(datadir.Root(), "adapters", "*.vyql"))
	if err != nil {
		panic("treesitter: glob adapters/*.vyql: " + err.Error())
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			panic("treesitter: read " + file + ": " + err.Error())
		}
		decls, err := parser.Parse(string(raw))
		if err != nil {
			panic("treesitter: parse " + file + ": " + err.Error())
		}
		for _, d := range decls {
			ad, ok := d.(*parser.AdapterDecl)
			if !ok {
				continue
			}
			for _, mp := range ad.Mappings {
				if mp.Kind != "flow_path" && mp.Kind != "flow_method" {
					continue
				}
				callFlowProfiles[ad.Name] = append(callFlowProfiles[ad.Name], callFlowSpec{
					Pattern: mp.Pattern,
					Method:  mp.Kind == "flow_method",
					Effect: nir.CallEffect{
						DestArg:      mp.FlowDestArg,
						SourceArg:    mp.FlowSourceArg,
						SourceResult: mp.FlowSourceResult,
					},
				})
			}
		}
	}
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
