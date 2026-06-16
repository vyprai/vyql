// Package secretscan is a non-tree-sitter frontend (like extract/frontend/config) that
// scans any text file for HARDCODED secrets — provider-specific tokens and high-confidence
// secret-assignment literals — and emits a markable NIR node per hit. The secretscan
// adapter labels each `hardcoded_secret` node code.HardcodedSecret; a presence rule flags
// it. Provider patterns are near-zero-FP; the generic assignment pattern excludes env
// reads and obvious placeholders.
package secretscan

import (
	"bytes"
	"encoding/gob"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vyprai/vyql/extract/nir"
	"github.com/vyprai/vyql/extract/parsecache"
)

// providerPatterns are high-precision, near-zero-FP secret tokens (CWE-798).
var providerPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                       // AWS access key id
	regexp.MustCompile(`ASIA[0-9A-Z]{16}`),                       // AWS temp access key
	regexp.MustCompile(`sk_live_[0-9A-Za-z]{20,}`),               // Stripe live secret
	regexp.MustCompile(`rk_live_[0-9A-Za-z]{20,}`),               // Stripe restricted
	regexp.MustCompile(`ghp_[0-9A-Za-z]{36,}`),                   // GitHub PAT
	regexp.MustCompile(`gho_[0-9A-Za-z]{36,}`),                   // GitHub OAuth
	regexp.MustCompile(`github_pat_[0-9A-Za-z_]{40,}`),           // GitHub fine-grained PAT
	regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),                 // Google API key
	regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`),           // Slack token
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),     // PEM private key
	regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`), // JWT
	regexp.MustCompile(`glpat-[0-9A-Za-z_\-]{20,}`),              // GitLab PAT
	regexp.MustCompile(`SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}`), // SendGrid
}

// genericAssign matches `secret-ish-name = "literal"` with a non-trivial value.
var genericAssign = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*["'` + "`" + `]([^"'` + "`" + `\s]{8,})["'` + "`" + `]`)

// placeholders are values that are not real secrets (examples/templates/defaults).
var placeholders = map[string]bool{
	"password": true, "changeme": true, "change_me": true, "example": true, "test": true,
	"xxxxxxxx": true, "placeholder": true, "your_password": true, "your_secret": true,
	"none": true, "null": true, "undefined": true, "redacted": true, "secret": true,
	"yourpassword": true, "yoursecret": true, "yourapikey": true, "todo": true,
}

// Extract scans the given files for hardcoded secrets.
// secretHits is the cached per-file result: the 1-based line numbers carrying a secret. nil/
// empty means a clean file — still cached, so an unchanged file is never re-read.
type secretHits struct{ Lines []int }

func Extract(files []string, root string) (nir.Program, error) {
	var prog nir.Program
	prog.SelfName = "self"
	// Stat fast-path: the result depends only on file content, so an unchanged file's hits are
	// replayed from cache instead of re-reading and re-scanning it — secret scanning otherwise
	// reads every source file on every scan.
	cache := parsecache.Shared()
	var auxKeys map[string]string
	var cached map[string][]byte
	if cache != nil {
		auxKeys = cache.AuxStatKeys(root, files, "secret")
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
					addSecrets(&prog, rel, lines)
					continue
				}
			}
		}
		data, err := os.ReadFile(f)
		if err != nil || isBinary(data) {
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			if scanLine(line) {
				lines = append(lines, i+1)
			}
		}
		if k, ok := auxKeys[f]; ok {
			writes[k] = encodeHits(secretHits{Lines: lines})
		}
		addSecrets(&prog, rel, lines)
	}
	if cache != nil && len(writes) > 0 {
		cache.PutManyRaw(writes)
	}
	return prog, nil
}

// addSecrets appends a secret-bearing module for rel if lines is non-empty.
func addSecrets(prog *nir.Program, rel string, lines []int) {
	if len(lines) == 0 {
		return
	}
	var body []nir.Stmt
	for _, ln := range lines {
		loc := rel + ":" + itoa(ln)
		body = append(body, nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: "hardcoded_secret", Loc: loc},
			Path:   "hardcoded_secret", Method: "hardcoded_secret", Loc: loc}})
	}
	fn := nir.FuncDef{Name: "__secrets__", Body: body, Loc: rel + ":1"}
	prog.Modules = append(prog.Modules, nir.Module{Key: rel, File: rel, Body: []nir.Stmt{fn}})
}

func encodeHits(h secretHits) []byte {
	var buf bytes.Buffer
	_ = gob.NewEncoder(&buf).Encode(h)
	return buf.Bytes()
}

func decodeHits(raw []byte) (secretHits, bool) {
	var h secretHits
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&h); err != nil {
		return secretHits{}, false
	}
	return h, true
}

func scanLine(line string) bool {
	for _, re := range providerPatterns {
		if re.MatchString(line) {
			return true
		}
	}
	if m := genericAssign.FindStringSubmatch(line); m != nil {
		raw := m[2]
		val := strings.ToLower(raw)
		// skip env-var indirection captured as a literal value, and placeholders.
		if placeholders[val] || strings.HasPrefix(val, "${") || strings.HasPrefix(val, "<") ||
			strings.Contains(val, "env") || strings.Contains(val, "process.") {
			return false
		}
		// Real credentials mix character classes; descriptive placeholders like
		// "MYSUPERSECRETKEY" or "changeme" are single-case dictionary words. Require
		// >=2 of {lower,upper,digit,symbol} so the generic branch stays near-zero-FP.
		if charClasses(raw) < 2 {
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
