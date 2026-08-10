package treesitter

// Source-variable lookup for the shell and PowerShell frontends.
//
// Which variable names carry request-borne data is binding-layer content, so this package holds
// only the scanning: the lookup is injected. Loading it here meant importing datadir and parser --
// the only two layer-crossing imports this package had -- and a malformed binding file panicked
// the parser rather than costing one frontend one class of source.

var sourceVarLookup func(tech, name string) (string, bool)

// SetSourceVarLookup installs the resolver. Called by the binding layer at init; unset, the
// frontends simply find no source variables, which is the correct degradation for a frontend
// asked to run without a knowledge base.
func SetSourceVarLookup(fn func(tech, name string) (string, bool)) { sourceVarLookup = fn }

func sourceVarEvent(tech, name string) (string, bool) {
	if sourceVarLookup == nil {
		return "", false
	}
	return sourceVarLookup(tech, name)
}

// sourceVarEventInText finds a `$NAME` or `${NAME}` reference anywhere in raw text and reports the
// source event it names, for the shell constructs the grammar hands over unparsed.
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
