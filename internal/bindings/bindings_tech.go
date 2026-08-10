// Technology attribution: which binding set may label a node, derived from its file.

package bindings

import (
	"strings"

	"github.com/vyprai/vyql/internal/usg"
)

var extTech = map[string]string{
	".go": "go", ".py": "python",
	".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript", ".vue": "javascript",
	".rb": "ruby", ".java": "java", ".php": "php", ".phtml": "php", ".inc": "php", ".cs": "csharp",
	".c": "c", ".h": "c", ".xs": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
	".rs": "rust", ".sh": "bash", ".bash": "bash", ".scala": "scala", ".sc": "scala", ".lua": "lua", ".kt": "kotlin", ".kts": "kotlin", ".ps1": "powershell", ".psm1": "powershell", ".swift": "swift", ".pl": "perl", ".pm": "perl", ".cgi": "perl", ".sol": "solidity", ".m": "objc",
	".xml": "config", ".plist": "config", ".jelly": "config", ".jsp": "config", ".tag": "config", ".html": "config", ".pest": "config", ".sch": "config",
	".ex": "elixir", ".exs": "elixir",
	".dart":   "dart",
	".groovy": "groovy", ".gradle": "groovy",
}

// nodeTech returns the language technology of a node from its loc ("file.ext:line").

func nodeTech(loc string) string {
	if i := strings.LastIndexByte(loc, ':'); i >= 0 {
		loc = loc[:i]
	}
	if i := strings.LastIndexByte(loc, '.'); i >= 0 {
		return extTech[loc[i:]]
	}
	return ""
}

func nodeTechFromNode(n usg.Node) string {
	if t := contextNodeTech(n); t != "" {
		return t
	}
	return nodeTech(n.Prop("loc"))
}

func nodeTechFromNodeWithFileContext(n usg.Node, fileTech map[string]string) string {
	if t := contextNodeTech(n); t != "" {
		return t
	}
	if fileTech != nil {
		if t := fileTech[locFile(n.Prop("loc"))]; t != "" {
			return t
		}
	}
	return nodeTech(n.Prop("loc"))
}

func fileContextTechs(s usg.Store) map[string]string {
	out := map[string]string{}
	ids, _ := s.NodesOfType("code.Call")
	for _, id := range ids {
		n, ok, err := s.GetNode(id)
		if err != nil || !ok {
			continue
		}
		t := contextNodeTech(n)
		if t == "" {
			continue
		}
		if file := locFile(n.Prop("loc")); file != "" {
			out[file] = t
		}
	}
	return out
}

func contextNodeTech(n usg.Node) string {
	if n.Type != "code.Call" || !strings.HasPrefix(n.Prop("callee_path"), "analysis.") {
		return ""
	}
	text := n.Prop("str_args")
	for start := 0; start <= len(text); {
		end := strings.IndexByte(text[start:], '\x00')
		var tok string
		if end < 0 {
			tok = text[start:]
			start = len(text) + 1
		} else {
			tok = text[start : start+end]
			start += end + 1
		}
		if strings.HasPrefix(tok, "lang=") {
			return tok[len("lang="):]
		}
	}
	return ""
}

// rangeNodes streams every node to fn via the store's RangeNodes fast path (no full []Node copy)
// when available, else falls back to AllNodes. Binding passes iterate every node once; the slice
// copy was a multi-GB transient on large graphs.
