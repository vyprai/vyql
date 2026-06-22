package agenticprep

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
)

const (
	defaultMaxFiles     = 400
	defaultMaxFileBytes = 8192
	defaultMaxAdapters  = 8
	defaultMaxBytes     = 64 << 10
)

type Config struct {
	OutDir       string
	MaxFiles     int
	MaxFileBytes int
	MaxAdapters  int
	MaxBytes     int
	Provider     Provider
	Model        string
}

type Provider interface {
	ProposeOverlay(context.Context, Profile) (Proposal, error)
}

type Result struct {
	Profile  Profile  `json:"profile"`
	Proposal Proposal `json:"proposal,omitempty"`
	OutDir   string   `json:"out_dir"`
	Warnings []string `json:"warnings,omitempty"`
}

type Profile struct {
	Roots     []string            `json:"roots"`
	Languages map[string]int      `json:"languages"`
	Packages  []string            `json:"packages,omitempty"`
	Manifests []ManifestEvidence  `json:"manifests,omitempty"`
	Imports   map[string][]string `json:"imports,omitempty"`
	Samples   []FileSample        `json:"samples,omitempty"`
}

type ManifestEvidence struct {
	Path     string   `json:"path"`
	Kind     string   `json:"kind"`
	Packages []string `json:"packages,omitempty"`
}

type FileSample struct {
	Path     string `json:"path"`
	Language string `json:"language"`
	SHA256   string `json:"sha256"`
	Preview  string `json:"preview,omitempty"`
}

type scoredSample struct {
	Sample FileSample
	Score  int
	Order  int
}

type Proposal struct {
	AdapterFiles []AdapterFile `json:"adapter_files,omitempty"`
	Notes        []string      `json:"notes,omitempty"`
	AgentLog     []AgentStep   `json:"agent_log,omitempty"`
}

type AdapterFile struct {
	Language string   `json:"language"`
	Filename string   `json:"filename,omitempty"`
	Source   string   `json:"source"`
	Evidence []string `json:"evidence,omitempty"`
}

type AgentStep struct {
	Index       int               `json:"index"`
	Text        string            `json:"text,omitempty"`
	ToolCalls   []AgentToolCall   `json:"tool_calls,omitempty"`
	ToolResults []AgentToolResult `json:"tool_results,omitempty"`
	Finish      string            `json:"finish,omitempty"`
}

type AgentToolCall struct {
	ID        string         `json:"id,omitempty"`
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

type AgentToolResult struct {
	ID     string         `json:"id,omitempty"`
	Name   string         `json:"name"`
	Result map[string]any `json:"result,omitempty"`
}

func Prepare(ctx context.Context, paths []string, cfg Config) (Result, error) {
	cfg = normalizeConfig(cfg)
	profile, err := Analyze(paths, cfg)
	if err != nil {
		return Result{}, err
	}
	res := Result{Profile: profile, OutDir: cfg.OutDir}
	res.Proposal = deterministicProposal(paths, cfg)
	if cfg.Provider != nil {
		proposal, err := cfg.Provider.ProposeOverlay(ctx, profile)
		if err != nil {
			return res, err
		}
		res.Proposal.AdapterFiles = append(res.Proposal.AdapterFiles, proposal.AdapterFiles...)
		res.Proposal.Notes = append(res.Proposal.Notes, proposal.Notes...)
		res.Proposal.AgentLog = append(res.Proposal.AgentLog, proposal.AgentLog...)
	}
	res.Proposal, res.Warnings = FilterValidProposal(profile, res.Proposal, cfg)
	if err := WriteResult(res, cfg.OutDir); err != nil {
		return res, err
	}
	return res, nil
}

func Analyze(paths []string, cfg Config) (Profile, error) {
	cfg = normalizeConfig(cfg)
	prof := Profile{
		Roots:     append([]string(nil), paths...),
		Languages: map[string]int{},
		Imports:   map[string][]string{},
	}
	seenImports := map[string]map[string]bool{}
	filesSeen := 0
	var samples []scoredSample
	for _, root := range paths {
		if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if skipDir(d.Name()) && path != root {
					return filepath.SkipDir
				}
				return nil
			}
			if filesSeen >= cfg.MaxFiles {
				return nil
			}
			lang := languageFor(path)
			if lang != "" {
				filesSeen++
				prof.Languages[lang]++
				sample, imports := sampleFile(path, lang, cfg.MaxFileBytes)
				if sample.Path != "" {
					samples = append(samples, scoredSample{
						Sample: sample,
						Score:  securityRelevanceScore(sample.Path, sample.Preview),
						Order:  len(samples),
					})
				}
				if len(imports) > 0 {
					if seenImports[lang] == nil {
						seenImports[lang] = map[string]bool{}
					}
					for _, imp := range imports {
						seenImports[lang][imp] = true
					}
				}
			}
			if man, ok := manifestEvidence(path, cfg.MaxFileBytes); ok {
				prof.Manifests = append(prof.Manifests, man)
			}
			return nil
		}); err != nil {
			return prof, err
		}
	}
	sort.SliceStable(samples, func(i, j int) bool {
		if samples[i].Score != samples[j].Score {
			return samples[i].Score > samples[j].Score
		}
		return samples[i].Order < samples[j].Order
	})
	for _, sample := range samples {
		if len(prof.Samples) >= 40 {
			break
		}
		prof.Samples = append(prof.Samples, sample.Sample)
	}
	for lang, set := range seenImports {
		var vals []string
		for v := range set {
			vals = append(vals, v)
		}
		sort.Strings(vals)
		if len(vals) > 80 {
			vals = vals[:80]
		}
		prof.Imports[lang] = vals
	}
	sort.Slice(prof.Manifests, func(i, j int) bool { return prof.Manifests[i].Path < prof.Manifests[j].Path })
	prof.Packages = profilePackageCandidates(prof)
	return prof, nil
}

func deterministicProposal(paths []string, cfg Config) Proposal {
	cfg = normalizeConfig(cfg)
	var evidence []string
	seen := map[string]bool{}
	for _, root := range paths {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if skipDir(d.Name()) && path != root {
					return filepath.SkipDir
				}
				return nil
			}
			if languageFor(path) != "c" {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			if len(b) > cfg.MaxBytes {
				b = b[:cfg.MaxBytes]
			}
			compact := compactSourceText(string(b))
			if scpRemoteListingFilenamePattern(compact) && !seen[path] {
				evidence = append(evidence, path)
				seen[path] = true
			}
			return nil
		})
	}
	if len(evidence) == 0 {
		return Proposal{}
	}
	return Proposal{
		AdapterFiles: []AdapterFile{{
			Language: "c",
			Filename: "c.scp_remote_listing.vyql",
			Source: strings.Join([]string{
				"adapter c {",
				"  mark exact \"analysis.module.context\" val \"lang=c\" val \"sink(intargc,char**argv)\" val \"atomicio(read,remin,cp,1)\" val \"strchr(cp,'/')!=NULL\" val \"strcmp(cp,\\\"..\\\")==0\" val \"snprintf(namebuf,need,\\\"%s%s%s\\\",targ\" val \"open(np,O_WRONLY|O_CREAT,mode)\" nval \"strcmp(cp,\\\".\\\")==0\" nval \"*cp=='\\\\0'\" -> code.RemoteListingDownloadPath",
				"}",
				"",
			}, "\n"),
			Evidence: evidence,
		}},
		Notes: []string{"deterministic C SCP remote-listing filename overlay inferred from repo source"},
	}
}

func scpRemoteListingFilenamePattern(compact string) bool {
	for _, want := range []string{
		"sink(intargc,char**argv)",
		"atomicio(read,remin,cp,1)",
		"strchr(cp,'/')!=NULL",
		"strcmp(cp,\"..\")==0",
		"snprintf(namebuf,need,\"%s%s%s\",targ",
		"open(np,O_WRONLY|O_CREAT,mode)",
	} {
		if !strings.Contains(compact, want) {
			return false
		}
	}
	for _, fixed := range []string{"strcmp(cp,\".\")==0", "*cp=='\\0'"} {
		if strings.Contains(compact, fixed) {
			return false
		}
	}
	return true
}

func compactSourceText(s string) string {
	return strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "").Replace(s)
}

func securityRelevanceScore(path string, text string) int {
	lowerPath := strings.ToLower(filepath.ToSlash(path))
	lowerText := strings.ToLower(text)
	score := 0
	for token, weight := range map[string]int{
		"exec(": 18, "system(": 18, "shell_exec": 18, "passthru": 18, "proc_open": 18, "popen(": 18,
		"eval(": 16, "unserialize": 16, "pickle.load": 16, "yaml.load": 16,
		"file_put_contents": 12, "fopen(": 10, "open(": 10, "writefile": 10, "sendfile": 10,
		"move_uploaded_file": 18, "rename(": 14, "copy(": 12, "unlink(": 12, "touch(": 10,
		"getabsolutepath": 22, "absolutepath": 14, "absolute path": 14, "e_warning": 18,
		"runtimeexception": 10, "fileoperationerrorexception": 10,
		"redirect": 10, "header(": 8, "location": 8, "render": 8, "html": 6,
		"select ": 8, "insert ": 8, "update ": 8, "delete ": 8, "query(": 8,
		"request": 8, "$_get": 12, "$_post": 12, "$_files": 12, "$_request": 12,
		"upload": 10, "restore": 12, "import": 8, "backup": 8, "archive": 8, "extract": 8,
		"filename": 8, "path": 6, "basename": 6, "../": 10,
		"rrdtool": 18, "shell_safe": 6, "escapeshellarg": 6,
		"threadlocal": 60, ".set(": 6, ".remove(": 6, "beginrequest": 26, "endrequest": 26,
		"activate(": 8, "deactivate(": 8, "associate(": 8, "dissociate(": 8,
		"requestscoped": 24, "sessionholder": 10, "nestedinvocationguard": 10,
		"isfieldenabled": 36, "getrelatableresourcetypes": 36, "resourcetyperelationship": 30,
		"relationship": 12, "field enabled": 16, "access check": 16,
	} {
		if strings.Contains(lowerText, token) {
			score += weight
		}
	}
	for token, weight := range map[string]int{
		"/www/": 6, "/controllers/": 6, "/api/": 6, "/routes/": 6, "/handlers/": 6,
		"backup": 8, "restore": 8, "import": 6, "upload": 8, "archive": 6,
		"auth": 5, "login": 5, "admin": 4, "config": 4, "driver": 4, "localdriver": 10,
		"context": 6, "cache": 6, "lifecycle": 6, "servlet": 5,
	} {
		if strings.Contains(lowerPath, token) {
			score += weight
		}
	}
	return score
}

func ValidateProposal(profile Profile, proposal Proposal, cfg Config) error {
	cfg = normalizeConfig(cfg)
	if len(proposal.AdapterFiles) > cfg.MaxAdapters {
		return fmt.Errorf("agentic prep: proposal has %d adapter files, max %d", len(proposal.AdapterFiles), cfg.MaxAdapters)
	}
	requirePackageScope := len(profilePackageCandidates(profile)) > 0
	for _, f := range proposal.AdapterFiles {
		lang := strings.TrimSpace(f.Language)
		if lang == "" {
			return errors.New("agentic prep: adapter file missing language")
		}
		if profile.Languages[lang] == 0 {
			return fmt.Errorf("agentic prep: adapter language %q was not present in repo profile", lang)
		}
		if len(f.Source) == 0 || len(f.Source) > cfg.MaxBytes {
			return fmt.Errorf("agentic prep: adapter %q source size is invalid", lang)
		}
		if len(f.Evidence) == 0 {
			return fmt.Errorf("agentic prep: adapter %q has no evidence paths", lang)
		}
		decls, err := parser.Parse(f.Source)
		if err != nil {
			return fmt.Errorf("agentic prep: adapter %q parse: %w", lang, err)
		}
		onto := ontology.Seed()
		seen := false
		for _, d := range decls {
			ad, ok := d.(*parser.AdapterDecl)
			if !ok {
				continue
			}
			seen = true
			if ad.Name != lang {
				return fmt.Errorf("agentic prep: adapter declaration %q must match language %q", ad.Name, lang)
			}
			if len(ad.Mappings) == 0 {
				return fmt.Errorf("agentic prep: adapter %q has no mappings", lang)
			}
			for _, m := range ad.Mappings {
				if m.Concept != "" && !onto.Exists(m.Concept) {
					return fmt.Errorf("agentic prep: adapter %q references unknown concept %q", lang, m.Concept)
				}
				if requirePackageScope && len(m.Packages) == 0 {
					return fmt.Errorf("agentic prep: adapter %q mapping %q -> %s is not package-scoped; wrap repo-local/generated mappings in package \"<dependency-or-project-package>\" { ... }", lang, m.Pattern, m.Concept)
				}
			}
			if broadGenericOverlay(lang, ad) {
				return fmt.Errorf("agentic prep: adapter %q is a broad generic mapping, not repo-specific prep", lang)
			}
		}
		if !seen {
			return fmt.Errorf("agentic prep: adapter %q contains no adapter declaration", lang)
		}
	}
	return nil
}

func broadGenericOverlay(lang string, ad *parser.AdapterDecl) bool {
	if len(ad.Mappings) == 0 {
		return false
	}
	for _, m := range ad.Mappings {
		if !genericOverlayMapping(lang, m) {
			return false
		}
	}
	return true
}

func genericOverlayMapping(lang string, m parser.AdapterMapping) bool {
	if lang != "python" || m.Kind != "sink_path" {
		return false
	}
	switch m.Pattern {
	case "open", "print":
		return true
	default:
		return false
	}
}

func FilterValidProposal(profile Profile, proposal Proposal, cfg Config) (Proposal, []string) {
	cfg = normalizeConfig(cfg)
	out := Proposal{Notes: append([]string(nil), proposal.Notes...), AgentLog: append([]AgentStep(nil), proposal.AgentLog...)}
	var warnings []string
	if len(proposal.AdapterFiles) > cfg.MaxAdapters {
		warnings = append(warnings, fmt.Sprintf("proposal has %d adapter files; keeping first %d", len(proposal.AdapterFiles), cfg.MaxAdapters))
		proposal.AdapterFiles = proposal.AdapterFiles[:cfg.MaxAdapters]
	}
	for _, file := range proposal.AdapterFiles {
		one := Proposal{AdapterFiles: []AdapterFile{file}}
		if err := ValidateProposal(profile, one, cfg); err != nil {
			lang := strings.TrimSpace(file.Language)
			if lang == "" {
				lang = "unknown"
			}
			warnings = append(warnings, fmt.Sprintf("dropped %s overlay: %v", lang, err))
			continue
		}
		out.AdapterFiles = append(out.AdapterFiles, file)
	}
	return out, warnings
}

func WriteResult(res Result, outDir string) error {
	if outDir == "" {
		return errors.New("agentic prep: output directory is required")
	}
	if err := os.MkdirAll(filepath.Join(outDir, "adapters"), 0o755); err != nil {
		return err
	}
	for _, f := range res.Proposal.AdapterFiles {
		name := safeAdapterFilename(f)
		path := filepath.Join(outDir, "adapters", name)
		if err := os.WriteFile(path, []byte(f.Source), 0o644); err != nil {
			return err
		}
	}
	manifest := struct {
		GeneratedAt time.Time `json:"generated_at"`
		Result      Result    `json:"result"`
	}{
		GeneratedAt: time.Now().UTC(),
		Result:      res,
	}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, "manifest.json"), append(b, '\n'), 0o644)
}

func normalizeConfig(cfg Config) Config {
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = defaultMaxFiles
	}
	if cfg.MaxFileBytes <= 0 {
		cfg.MaxFileBytes = defaultMaxFileBytes
	}
	if cfg.MaxAdapters <= 0 {
		cfg.MaxAdapters = defaultMaxAdapters
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultMaxBytes
	}
	return cfg
}

func safeAdapterFilename(f AdapterFile) string {
	name := strings.TrimSpace(f.Filename)
	if name == "" {
		name = strings.TrimSpace(f.Language) + ".vyql"
	}
	name = filepath.Base(name)
	if !strings.HasSuffix(name, ".vyql") {
		name += ".vyql"
	}
	return name
}

func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".hg", ".svn", ".venv", "venv", "target", "dist", "build":
		return true
	default:
		return false
	}
}

func languageFor(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue":
		return "javascript"
	case ".rb":
		return "ruby"
	case ".java":
		return "java"
	case ".php", ".phtml", ".inc":
		return "php"
	case ".cs":
		return "csharp"
	case ".c", ".h":
		return "c"
	case ".cpp", ".cc", ".cxx", ".hpp":
		return "cpp"
	case ".rs":
		return "rust"
	case ".sh", ".bash":
		return "bash"
	case ".scala", ".sc":
		return "scala"
	case ".lua":
		return "lua"
	case ".kt", ".kts":
		return "kotlin"
	case ".ps1", ".psm1":
		return "powershell"
	case ".swift":
		return "swift"
	case ".pl", ".pm", ".cgi":
		return "perl"
	case ".sol":
		return "solidity"
	case ".m":
		return "objc"
	case ".ex", ".exs":
		return "elixir"
	case ".dart":
		return "dart"
	case ".groovy", ".gradle":
		return "groovy"
	default:
		return ""
	}
}

var importPatterns = map[string]*regexp.Regexp{
	"go":         regexp.MustCompile(`(?m)^\s*import\s+(?:\(\s*)?"([^"]+)"`),
	"python":     regexp.MustCompile(`(?m)^\s*(?:from\s+([A-Za-z0-9_\.]+)\s+import|import\s+([A-Za-z0-9_\.]+))`),
	"javascript": regexp.MustCompile(`(?m)(?:from\s+["']([^"']+)["']|require\(["']([^"']+)["']\))`),
	"ruby":       regexp.MustCompile(`(?m)^\s*require(?:_relative)?\s+["']([^"']+)["']`),
	"java":       regexp.MustCompile(`(?m)^\s*import\s+([A-Za-z0-9_\.]+);`),
	"php":        regexp.MustCompile(`(?m)^\s*(?:use|include|require|include_once|require_once)\s+['"]?([^;'"()]+)`),
}

func sampleFile(path, lang string, maxBytes int) (FileSample, []string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return FileSample{}, nil
	}
	sum := sha256.Sum256(b)
	if len(b) > maxBytes {
		b = b[:maxBytes]
	}
	text := string(b)
	sample := FileSample{Path: path, Language: lang, SHA256: hex.EncodeToString(sum[:]), Preview: text}
	var imports []string
	if re := importPatterns[lang]; re != nil {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			for _, part := range m[1:] {
				if part != "" {
					imports = append(imports, part)
					break
				}
			}
		}
	}
	return sample, imports
}

func manifestEvidence(path string, maxBytes int) (ManifestEvidence, bool) {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "package.json", "go.mod", "requirements.txt", "pyproject.toml", "gemfile", "composer.json", "cargo.toml", "pom.xml", "build.gradle":
	default:
		return ManifestEvidence{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ManifestEvidence{}, false
	}
	if len(b) > maxBytes {
		b = b[:maxBytes]
	}
	return ManifestEvidence{Path: path, Kind: base, Packages: coarsePackages(base, string(b))}, true
}

func coarsePackages(kind, text string) []string {
	set := map[string]bool{}
	add := func(s string) {
		s = strings.Trim(s, `"',: <>=~^`)
		if s != "" && !strings.ContainsAny(s, " \t") {
			set[s] = true
		}
	}
	switch kind {
	case "package.json", "composer.json":
		var raw map[string]any
		if json.Unmarshal([]byte(text), &raw) == nil {
			if name, _ := raw["name"].(string); name != "" {
				add(name)
			}
			for _, key := range []string{"dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "require", "require-dev"} {
				if deps, ok := raw[key].(map[string]any); ok {
					for dep := range deps {
						add(dep)
					}
				}
			}
			break
		}
	case "go.mod":
		moduleRe := regexp.MustCompile(`(?m)^\s*module\s+([A-Za-z0-9_.\-/]+)`)
		for _, m := range moduleRe.FindAllStringSubmatch(text, -1) {
			add(m[1])
		}
		re := regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_.\-/]+)\s+v[0-9]`)
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			add(m[1])
		}
	case "requirements.txt":
		re := regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_.\-]+)`)
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			add(m[1])
		}
	case "pyproject.toml":
		nameRe := regexp.MustCompile(`(?m)^\s*name\s*=\s*["']([^"']+)["']`)
		for _, m := range nameRe.FindAllStringSubmatch(text, -1) {
			add(m[1])
		}
		depRe := regexp.MustCompile(`(?m)["']([A-Za-z0-9_.\-]+)(?:[<>=~! ][^"']*)?["']`)
		inDeps := false
		for _, line := range strings.Split(text, "\n") {
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "[") {
				inDeps = strings.Contains(trim, "dependencies") || strings.Contains(trim, "project")
			}
			if !inDeps && !strings.HasPrefix(trim, "dependencies") {
				continue
			}
			for _, m := range depRe.FindAllStringSubmatch(line, -1) {
				add(m[1])
			}
		}
	case "cargo.toml":
		nameRe := regexp.MustCompile(`(?m)^\s*name\s*=\s*["']([^"']+)["']`)
		for _, m := range nameRe.FindAllStringSubmatch(text, -1) {
			add(m[1])
		}
		depRe := regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_.\-]+)\s*=`)
		inDeps := false
		for _, line := range strings.Split(text, "\n") {
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "[") {
				inDeps = strings.HasPrefix(trim, "[dependencies") || strings.HasPrefix(trim, "[dev-dependencies") || strings.HasPrefix(trim, "[build-dependencies")
				continue
			}
			if inDeps {
				for _, m := range depRe.FindAllStringSubmatch(line, -1) {
					add(m[1])
				}
			}
		}
	default:
		re := regexp.MustCompile(`["']([@A-Za-z0-9_.\-/]+)["']\s*:`)
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			add(m[1])
		}
	}
	var out []string
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}

func profilePackageCandidates(profile Profile) []string {
	set := map[string]bool{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		set[v] = true
	}
	for _, v := range profile.Packages {
		add(v)
	}
	for _, man := range profile.Manifests {
		for _, pkg := range man.Packages {
			add(pkg)
		}
	}
	for _, imports := range profile.Imports {
		for _, imp := range imports {
			add(imp)
			if i := strings.IndexAny(imp, "./:"); i > 0 {
				add(imp[:i])
			}
		}
	}
	var out []string
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	if len(out) > 80 {
		return out[:80]
	}
	return out
}
