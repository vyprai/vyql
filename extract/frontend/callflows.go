package frontend

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/extract/nir"
	"github.com/vyprai/vyql/parser"
)

type callFlowSpec struct {
	Pattern string
	Method  bool
	Prefix  bool
	Effect  nir.CallEffect
}

var (
	callFlowOnce     sync.Once
	callFlowProfiles map[string][]callFlowSpec
)

func CallEffectsFor(tech, path, method string) []nir.CallEffect {
	callFlowOnce.Do(loadCallFlowProfiles)
	var out []nir.CallEffect
	for _, spec := range callFlowProfiles[tech] {
		if spec.Prefix {
			name := method
			if name == "" {
				name = lastSeg(path)
			}
			if strings.HasPrefix(strings.ToLower(name), strings.ToLower(spec.Pattern)) {
				out = append(out, spec.Effect)
			}
			continue
		}
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
		panic("frontend: glob adapters/*.vyql: " + err.Error())
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			panic("frontend: read " + file + ": " + err.Error())
		}
		decls, err := parser.Parse(string(raw))
		if err != nil {
			panic("frontend: parse " + file + ": " + err.Error())
		}
		for _, d := range decls {
			ad, ok := d.(*parser.AdapterDecl)
			if !ok {
				continue
			}
			for _, mp := range ad.Mappings {
				if mp.Kind != "flow_path" && mp.Kind != "flow_method" && mp.Kind != "flow_prefix" {
					continue
				}
				callFlowProfiles[ad.Name] = append(callFlowProfiles[ad.Name], callFlowSpec{
					Pattern: mp.Pattern,
					Method:  mp.Kind == "flow_method",
					Prefix:  mp.Kind == "flow_prefix",
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

func lastSeg(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return path
}
