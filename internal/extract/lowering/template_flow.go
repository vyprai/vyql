package lowering

import (
	"regexp"

	"github.com/vyprai/vyql/internal/extract/nir"
)

var staticTemplateVarRE = regexp.MustCompile(`{{-?\s*([A-Za-z_][A-Za-z0-9_]*)`)

type templateInfo struct {
	vars   map[string]bool
	static bool
}

func staticTemplateVars(text string) map[string]bool {
	out := map[string]bool{}
	for _, match := range staticTemplateVarRE.FindAllStringSubmatch(text, -1) {
		out[match[1]] = true
	}
	return out
}

func (l *lowerer) rememberTemplate(call nir.Call, result string, sc *scope) {
	if call.Method != "from_string" || len(call.Args) == 0 {
		return
	}
	if text, ok := l.constStrVal(call.Args[0], sc); ok {
		l.templates[result] = templateInfo{vars: staticTemplateVars(text), static: true}
		return
	}
	l.templates[result] = templateInfo{}
}

func (l *lowerer) flowTemplateRender(call nir.Call, argVals []string, recv, result string) []bool {
	handled := make([]bool, len(argVals))
	info, tracked := l.templates[recv]
	if call.Method != "render" || recv == "" || !tracked {
		return handled
	}
	if len(argVals) > 0 {
		if info.static {
			handled[0] = true
			if ci := l.containers[argVals[0]]; ci != nil && !ci.dirty {
				for key := range info.vars {
					if elem := ci.elems[key]; elem != "" {
						l.flow(elem, result)
					}
				}
			} else {
				handled[0] = false
			}
		}
	}
	for i := 1; i < len(handled); i++ {
		handled[i] = true
	}
	return handled
}
