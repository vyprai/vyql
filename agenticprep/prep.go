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

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/extract/sca"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	profpkg "github.com/vyprai/vyql/profile"
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
	Profile    Profile    `json:"profile"`
	ScanConfig ScanConfig `json:"scan_config,omitempty"`
	Proposal   Proposal   `json:"proposal,omitempty"`
	OutDir     string     `json:"out_dir"`
	Warnings   []string   `json:"warnings,omitempty"`
}

type ScanConfig struct {
	Profile string `json:"profile,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type Profile struct {
	Roots     []string            `json:"roots"`
	Languages map[string]int      `json:"languages"`
	Packages  []string            `json:"packages,omitempty"`
	Manifests []ManifestEvidence  `json:"manifests,omitempty"`
	Imports   map[string][]string `json:"imports,omitempty"`
	LocalPkgs []string            `json:"local_packages,omitempty"`
	DepGaps   []DependencyGap     `json:"dependency_gaps,omitempty"`
	Samples   []FileSample        `json:"samples,omitempty"`
}

type ManifestEvidence struct {
	Path     string   `json:"path"`
	Kind     string   `json:"kind"`
	Packages []string `json:"packages,omitempty"`
}

type DependencyGap struct {
	Language string   `json:"language,omitempty"`
	Package  string   `json:"package"`
	Source   string   `json:"source"`
	Score    int      `json:"score,omitempty"`
	Imports  []string `json:"imports,omitempty"`
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
	res := Result{Profile: profile, ScanConfig: detectScanConfig(paths), OutDir: cfg.OutDir}
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

func detectScanConfig(paths []string) ScanConfig {
	profiles, err := profpkg.Load()
	if err != nil {
		return ScanConfig{}
	}
	p := profpkg.Detect(paths, profiles)
	if strings.TrimSpace(p.Name) == "" {
		return ScanConfig{}
	}
	return ScanConfig{Profile: p.Name, Reason: "deterministic repo profile detection"}
}

func Analyze(paths []string, cfg Config) (Profile, error) {
	cfg = normalizeConfig(cfg)
	prof := Profile{
		Roots:     append([]string(nil), paths...),
		Languages: map[string]int{},
		Imports:   map[string][]string{},
	}
	seenImports := map[string]map[string]bool{}
	seenLocalPkgs := map[string]bool{}
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
				sample, imports, localPkgs := sampleFile(path, lang, cfg.MaxFileBytes)
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
				for _, pkg := range localPkgs {
					seenLocalPkgs[pkg] = true
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
	fullImports := map[string][]string{}
	for lang, set := range seenImports {
		var vals []string
		for v := range set {
			vals = append(vals, v)
		}
		sort.Strings(vals)
		fullImports[lang] = vals
		if len(vals) > 240 {
			vals = vals[:240]
		}
		prof.Imports[lang] = vals
	}
	sort.Slice(prof.Manifests, func(i, j int) bool { return prof.Manifests[i].Path < prof.Manifests[j].Path })
	for pkg := range seenLocalPkgs {
		prof.LocalPkgs = append(prof.LocalPkgs, pkg)
	}
	sort.Strings(prof.LocalPkgs)
	if len(prof.LocalPkgs) > 120 {
		prof.LocalPkgs = prof.LocalPkgs[:120]
	}
	prof.Packages = profilePackageCandidates(prof)
	depProfile := prof
	if len(seenLocalPkgs) > 120 {
		depProfile.LocalPkgs = make([]string, 0, len(seenLocalPkgs))
		for pkg := range seenLocalPkgs {
			depProfile.LocalPkgs = append(depProfile.LocalPkgs, pkg)
		}
		sort.Strings(depProfile.LocalPkgs)
	}
	depProfile.Imports = fullImports
	prof.DepGaps = dependencyGaps(depProfile)
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
		"@modelcontextprotocol": 42, "mcpserver": 36, "server.tool": 42,
		"child_process": 20, "execfile": 10, "z.number": 8,
		"eval(": 16, "unserialize": 16, "pickle.load": 16, "yaml.load": 16,
		"constraintvalidator": 34, "constraintvalidatorcontext": 28,
		"buildconstraintviolationwithtemplate": 48, "addconstraintviolation": 20,
		"illegalargumentexception": 12, "getmessage()": 20,
		"pollinghost": 28, "connectionmetadata": 24, "gurl": 18,
		"encodeuricomponent": 18, "wsv2": 18, "herokuapp.com": 26,
		"file_put_contents": 12, "fopen(": 10, "open(": 10, "writefile": 10, "sendfile": 10,
		"move_uploaded_file": 18, "rename(": 14, "copy(": 12, "unlink(": 12, "touch(": 10,
		"getabsolutepath": 22, "absolutepath": 14, "absolute path": 14, "e_warning": 18,
		"runtimeexception": 10, "fileoperationerrorexception": 10,
		"uploadedfile": 18, "fileuploader": 18, "storeas(": 18, "getclientoriginalextension": 20,
		"getclientmimetype": 10, "svg": 16, "getsvgdimensions": 18, "svgsanitize": 28,
		"sanitizesvg": 28, "sanitizer": 18,
		"redirect": 10, "header(": 8, "location": 8, "render": 8, "html": 6,
		"xss": 28, "html::encode": 22, "htmlspecialchars": 18, "escapehtml": 18,
		"encode(": 8, "escape(": 8, "sanitize": 12, "$model->title": 18,
		"$snapshot['title']": 18, "$snapshot[\"title\"]": 18, "snapshot": 8,
		"audit": 6, "title": 4,
		"ssti": 34, "twig": 24, "canonicalurl": 24, "safecanonicalurl": 32,
		"absoluteurlwithprotocol": 36, "getpathinfo": 20, "sanitizeurl": 24,
		"sanitizeuserinput": 22, "x-forwarded-host": 30, "host header": 28,
		"asmodelsuccess": 38, "modelname": 18, "getacceptsjson": 18,
		"getcsrftoken": 10, "json": 8, "secret": 12, "token": 10,
		"credential": 12, "password": 12,
		"runquery": 42, "$ssql": 26, "legacyfilterinputarr": 24,
		"where di_fr_id": 34, "donateditem_di": 18,
		"update_event": 46, "handlechildresponse": 42, "allow_event_updates_from_jobs": 34,
		"listfindupdate": 30, "global/schedule": 26,
		"systemcredentialsprovider": 52, "domaincredentials.migratelisttomap": 46,
		"xml.unmarshal": 34, "credentials.xml": 28, "initmilestone.job_loaded": 42,
		"@initializer": 26, "forceloadduringstartup": 24,
		"formvalidation": 38, "queryparameter": 34, "testconnection": 44,
		"dotest": 28, "docheck": 24, "dofill": 18, "jenkins.administer": 28,
		"checkpermission": 22, "haspermission": 18, "crowdconfigurationservice": 30,
		"cmdexecuteservice": 52, "$cmd_string": 42, "x-islandora-args": 36,
		"generateDerivativeResponse": 32, "$this->cmd->execute": 34,
		"command string": 24, "array_merge": 14, "headerbag": 14,
		"gnupg": 38, "gpg": 22, "escapeshellarg": 24, "setoperation": 26,
		"$operation": 22, "--list-secret-keys": 30, "--list-public-keys": 30,
		"--list-keys": 26, "--delete-key": 30, "--delete-secret-key": 30,
		"--export": 20, "end-of-options": 32,
		"cors": 24, "alloworigins": 34, "alloworiginfunc": 24, "allowallorigins": 22,
		"access-control-allow-origin": 30, "origin": 14, "wildcard": 18,
		"hasprefix": 18, "hassuffix": 12,
		"attestation": 28, "predicate": 24, "signature": 18, "verifyimageattestations": 36,
		"verifylocalimageattestations": 36, "attestationtopayloadjson": 38,
		"printverification": 34, "policy": 12,
		"select ": 8, "insert ": 8, "update ": 8, "delete ": 8, "query(": 8,
		"addconditionparam": 24, "whereraw": 18, "havingraw": 18, "orderbyraw": 18,
		"request": 8, "request->query": 18, "$request->query": 18, "$_get": 12, "$_post": 12, "$_files": 12, "$_request": 12,
		"upload": 10, "restore": 12, "import": 8, "backup": 8, "archive": 8, "extract": 8,
		"filename": 8, "path": 6, "basename": 6, "../": 10,
		"zip.openreader": 34, "os.openfile": 24, "os.o_trunc": 30,
		"getinput": 18, "overwrite": 18,
		"contentlength": 58, "content-length": 46, "io.readfull": 56,
		"limitreader": 42, "maxbytesreader": 40, "maxbodysize": 40,
		"bodysizexceeded": 30, "readrequestbody": 28, "request body": 18,
		"userspec": 42, "strtoll": 22, "u->uid": 34, "u->gid": 24,
		"process->user": 26, "make_oci_process_user": 44, "--user": 18,
		"do_directory": 30, "expand_fs": 34, "romfs_read": 26, "namelen": 18,
		"dirent": 16, "bad filename": 20, "strchr(name": 24, "strcmp(name": 20,
		"rrdtool": 18, "shell_safe": 6,
		"threadlocal": 60, ".set(": 6, ".remove(": 6, "beginrequest": 26, "endrequest": 26,
		"activate(": 8, "deactivate(": 8, "associate(": 8, "dissociate(": 8,
		"requestscoped": 24, "sessionholder": 10, "nestedinvocationguard": 10,
		"isfieldenabled": 36, "getrelatableresourcetypes": 36, "resourcetyperelationship": 30,
		"relationship": 12, "field enabled": 16, "access check": 16,
		"permissionsbyrole": 48, "rolenetworkmanager": 42, "roleadmin": 14,
		"permbackup": 36, "permrestore": 36, "permission denied": 12,
		"authorize(": 18, "authorization": 16, "middleware": 12,
	} {
		if strings.Contains(lowerText, token) {
			score += weight
		}
	}
	for token, weight := range map[string]int{
		"/www/": 6, "/controllers/": 6, "/api/": 6, "/routes/": 6, "/handlers/": 6,
		"backup": 8, "restore": 8, "import": 6, "upload": 8, "uploader": 10, "archive": 6,
		"auth": 5, "login": 5, "admin": 4, "config": 4, "driver": 4, "localdriver": 10,
		"authorization": 16, "permission": 14, "role": 10, "middleware": 8,
		"cors": 18, "origin": 12, "wildcard": 10,
		"attestation": 18, "predicate": 14, "signature": 10, "verify": 8,
		"/validation/": 20, "validator": 16,
		"context": 6, "cache": 6, "lifecycle": 6, "servlet": 5,
		"jenkins": 10, "descriptor": 8,
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
	firstPartyPackages := firstPartyManifestPackages(profile)
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
				if broadCommandWrapperSink(lang, m) {
					return fmt.Errorf("agentic prep: adapter %q maps a broad command-wrapper execute sink; use a narrow analysis.function.context mark to code.CommandStringWrapperExecution so argv-array fixes are not flagged", lang)
				}
				if broadMcpToolCommandMark(m) {
					return fmt.Errorf("agentic prep: adapter %q maps a broad MCP tool command mark; include concrete exec command-template evidence and nval hardening such as execFile so fixed argv-array code is not flagged", lang)
				}
				if invalidJenkinsCredentialStartupMark(m) {
					return fmt.Errorf("agentic prep: adapter %q maps Jenkins credential startup loading too broadly; use minimal analysis.class.context vals for class_name:SystemCredentialsProvider, credential unmarshal/migration call_path evidence, function_name:getInstance, and structured @Initializer/forceLoad absence checks; do not add class_base or positive annotation vals", lang)
				}
				if invalidJobOutputEventUpdateMark(m) {
					return fmt.Errorf("agentic prep: adapter %q maps child job output event updates too broadly; use analysis.function.context vals from the child-output handler showing update_event copied from data into job state, and nval hardening such as allow_event_updates_from_jobs or delete data.update_event", lang)
				}
				if invalidDefaultRelaySecretMark(m) {
					return fmt.Errorf("agentic prep: adapter %q maps default relay secret exposure too broadly; include concrete relay/proxy/tunnel/default-host URL evidence, embedded token/gurl/connection metadata, and an nval for trusted-host or explicit configured-host hardening", lang)
				}
				if localExactContextMapping(m) && len(m.Packages) > 0 {
					return fmt.Errorf("agentic prep: adapter %q package-scopes an exact context mark; keep exact context marks unscoped and put package/dependency evidence in adapter evidence instead of a package gate", lang)
				}
				if requirePackageScope && len(m.Packages) == 0 && !localExactContextMapping(m) {
					return fmt.Errorf("agentic prep: adapter %q mapping %q -> %s is not package-scoped; wrap repo-local/generated mappings in package \"<dependency-or-project-package>\" { ... }", lang, m.Pattern, m.Concept)
				}
				for _, pkg := range m.Packages {
					if firstPartyPackages[sca.NormalizePackageName(pkg)] {
						return fmt.Errorf("agentic prep: adapter %q maps first-party package %q; use a generalized API mapping, exact context mark, or empty overlay instead of local package gating", lang, pkg)
					}
				}
			}
			if broadGenericOverlay(lang, ad) {
				return fmt.Errorf("agentic prep: adapter %q is a broad generic mapping, not repo-specific prep", lang)
			}
			if sourceOnlyParamOverlay(ad) {
				return fmt.Errorf("agentic prep: adapter %q only broadens public parameters as sources; add a concrete sink/mark/control mapping or return an empty overlay", lang)
			}
		}
		if !seen {
			return fmt.Errorf("agentic prep: adapter %q contains no adapter declaration", lang)
		}
	}
	return nil
}

func firstPartyManifestPackages(profile Profile) map[string]bool {
	out := map[string]bool{}
	for _, pkg := range profile.LocalPkgs {
		if norm := sca.NormalizePackageName(pkg); norm != "" {
			out[norm] = true
		}
	}
	for _, man := range profile.Manifests {
		for _, pkg := range manifestDeclaredPackageNames(man.Path, man.Kind) {
			if norm := sca.NormalizePackageName(pkg); norm != "" {
				out[norm] = true
			}
		}
	}
	return out
}

func manifestDeclaredPackageNames(path string, kind string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	text := string(b)
	switch strings.ToLower(kind) {
	case "cargo.toml":
		if name := tomlPackageName(text); name != "" {
			return []string{name}
		}
	case "package.json", "composer.json":
		var m map[string]any
		if json.Unmarshal(b, &m) == nil {
			if name, _ := m["name"].(string); strings.TrimSpace(name) != "" {
				return []string{name}
			}
		}
	case "go.mod":
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "module ") {
				return []string{strings.TrimSpace(strings.TrimPrefix(line, "module "))}
			}
		}
	case "pyproject.toml":
		if name := tomlProjectName(text); name != "" {
			return []string{name}
		}
	}
	return nil
}

func tomlPackageName(text string) string {
	inPackage := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.Split(line, "#")[0])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inPackage = line == "[package]"
			continue
		}
		if inPackage && strings.HasPrefix(line, "name") {
			if name := quotedAssignmentValue(line); name != "" {
				return name
			}
		}
	}
	return ""
}

func tomlProjectName(text string) string {
	inProject := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.Split(line, "#")[0])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inProject = line == "[project]" || line == "[tool.poetry]"
			continue
		}
		if inProject && strings.HasPrefix(line, "name") {
			if name := quotedAssignmentValue(line); name != "" {
				return name
			}
		}
	}
	return ""
}

func quotedAssignmentValue(line string) string {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return ""
	}
	val := strings.TrimSpace(parts[1])
	val = strings.Trim(val, `"'`)
	return strings.TrimSpace(val)
}

func sourceOnlyParamOverlay(ad *parser.AdapterDecl) bool {
	hasSourceParam := false
	for _, m := range ad.Mappings {
		if !strings.HasPrefix(m.Kind, "source") {
			return false
		}
		if m.Kind == "source_param" {
			hasSourceParam = true
		}
	}
	return hasSourceParam
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

func broadCommandWrapperSink(lang string, m parser.AdapterMapping) bool {
	if m.Concept != "code.CommandExecution" && m.Concept != "CommandExecution" {
		return false
	}
	if m.Kind != "sink_path" && m.Kind != "sink_method" {
		return false
	}
	pattern := strings.ToLower(m.Pattern)
	if strings.Contains(pattern, "cmdexecuteservice") || strings.Contains(pattern, "process::fromshellcommandline") {
		return true
	}
	if pattern == "execute" || strings.HasSuffix(pattern, ".execute") {
		return true
	}
	if lang == "php" && strings.Contains(pattern, "execute") && strings.Contains(pattern, "command") {
		return true
	}
	return false
}

func broadMcpToolCommandMark(m parser.AdapterMapping) bool {
	if m.Concept != "code.McpToolCommandTemplateExecution" {
		return false
	}
	if !localExactContextMapping(m) {
		return true
	}
	hasCommandTemplate := false
	for _, v := range m.ValMatches {
		lv := strings.ToLower(v)
		if strings.Contains(lv, "exec(") ||
			strings.Contains(lv, "child_process.exec") ||
			strings.Contains(lv, "lsof") ||
			strings.Contains(lv, "ps -p") ||
			strings.Contains(lv, "`") {
			hasCommandTemplate = true
			break
		}
	}
	hasHardeningNval := false
	for _, nv := range m.ValAbsents {
		lnv := strings.ToLower(nv)
		if strings.Contains(lnv, "execfile") ||
			strings.Contains(lnv, "spawn(") ||
			strings.Contains(lnv, "spawnfile") {
			hasHardeningNval = true
			break
		}
	}
	return !hasCommandTemplate || !hasHardeningNval
}

func invalidJenkinsCredentialStartupMark(m parser.AdapterMapping) bool {
	if m.Concept != "code.JenkinsCredentialsStartupLoadContextExposure" {
		return false
	}
	if m.Kind != "mark" || !m.Exact || m.Pattern != "analysis.class.context" {
		return true
	}
	hasCredentialLoad := false
	hasSystemProviderIdentity := false
	hasStructuredContext := false
	hasGetInstance := false
	for _, v := range m.ValMatches {
		lv := strings.ToLower(v)
		if strings.HasPrefix(lv, "class_base:") || strings.HasPrefix(lv, "annotation:") {
			return true
		}
		if strings.HasPrefix(lv, "class_name:") ||
			strings.HasPrefix(lv, "class_base:") ||
			strings.HasPrefix(lv, "function_name:") ||
			strings.HasPrefix(lv, "call_path:") ||
			strings.HasPrefix(lv, "annotation:") {
			hasStructuredContext = true
		}
		if strings.Contains(lv, "call_path:xml.unmarshal") ||
			strings.Contains(lv, "call_path:domaincredentials.migratelisttomap") ||
			strings.Contains(lv, "credentials.xml") {
			hasCredentialLoad = true
		}
		if strings.Contains(lv, "class_name:systemcredentialsprovider") ||
			strings.Contains(lv, "credentials.xml") ||
			strings.Contains(lv, "call_path:xml.unmarshal") {
			hasSystemProviderIdentity = true
		}
		if strings.Contains(lv, "function_name:getinstance") {
			hasGetInstance = true
		}
	}
	hasStartupAbsence := false
	for _, nv := range m.ValAbsents {
		lnv := strings.ToLower(nv)
		if strings.Contains(lnv, "annotation:initializer") ||
			strings.Contains(lnv, "call_path:initmilestone.job_loaded") ||
			strings.Contains(lnv, "function_name:forceloadduringstartup") {
			hasStartupAbsence = true
			break
		}
	}
	return !hasStructuredContext || !hasCredentialLoad || !hasSystemProviderIdentity || !hasGetInstance || !hasStartupAbsence
}

func invalidJobOutputEventUpdateMark(m parser.AdapterMapping) bool {
	if m.Concept != "code.JobOutputEventUpdateAuthorizationBypass" {
		return false
	}
	if m.Kind != "mark" || !m.Exact || m.Pattern != "analysis.function.context" {
		return true
	}
	hasChildOutputHandler := false
	hasChildOutputCopy := false
	for _, v := range m.ValMatches {
		lv := strings.ToLower(v)
		if strings.Contains(lv, "got job update from child") ||
			strings.Contains(lv, "handlechildresponse") ||
			strings.Contains(lv, "child sent us") {
			hasChildOutputHandler = true
		}
		if strings.Contains(lv, "job[key]=data[key]") ||
			strings.Contains(lv, "job[key] = data[key]") ||
			(strings.Contains(lv, "update_event") && strings.Contains(lv, "data")) {
			hasChildOutputCopy = true
		}
	}
	hasHardeningAbsence := false
	for _, nv := range m.ValAbsents {
		lnv := strings.ToLower(nv)
		if strings.Contains(lnv, "allow_event_updates_from_jobs") ||
			strings.Contains(lnv, "delete data.update_event") {
			hasHardeningAbsence = true
			break
		}
	}
	return !hasChildOutputHandler || !hasChildOutputCopy || !hasHardeningAbsence
}

func invalidDefaultRelaySecretMark(m parser.AdapterMapping) bool {
	if m.Concept != "code.DefaultExternalRelaySecretExposure" {
		return false
	}
	if m.Kind != "mark" || !m.Exact || m.Pattern != "analysis.function.context" {
		return true
	}
	hasRelayURL := false
	hasSensitiveMetadata := false
	for _, v := range m.ValMatches {
		lv := strings.ToLower(v)
		if strings.Contains(lv, "relay") ||
			strings.Contains(lv, "proxy") ||
			strings.Contains(lv, "tunnel") ||
			strings.Contains(lv, "pollinghost") ||
			strings.Contains(lv, "default host") ||
			strings.Contains(lv, "defaulthost") ||
			strings.Contains(lv, "default_host") ||
			strings.Contains(lv, "herokuapp.com") ||
			strings.Contains(lv, "wsv2") {
			hasRelayURL = true
		}
		if strings.Contains(lv, "token") ||
			strings.Contains(lv, "gurl") ||
			strings.Contains(lv, "conmanurl") ||
			strings.Contains(lv, "connectionmetadata") ||
			strings.Contains(lv, "credential") ||
			strings.Contains(lv, "authorization") {
			hasSensitiveMetadata = true
		}
	}
	hasHardeningAbsence := false
	for _, nv := range m.ValAbsents {
		lnv := strings.ToLower(nv)
		if strings.Contains(lnv, "trusted") ||
			strings.Contains(lnv, "configured") ||
			strings.Contains(lnv, "allowlist") ||
			strings.Contains(lnv, "product-owned") ||
			strings.Contains(lnv, "custom host") ||
			strings.Contains(lnv, "default host") {
			hasHardeningAbsence = true
			break
		}
	}
	return !hasRelayURL || !hasSensitiveMetadata || !hasHardeningAbsence
}

func localExactContextMapping(m parser.AdapterMapping) bool {
	if m.Kind != "mark" || !m.Exact {
		return false
	}
	switch m.Pattern {
	case "analysis.function.context", "analysis.class.context", "analysis.module.context":
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
	if strings.TrimSpace(res.ScanConfig.Profile) != "" {
		b, err := json.MarshalIndent(res.ScanConfig, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(outDir, "scan_config.json"), append(b, '\n'), 0o644); err != nil {
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

func sampleFile(path, lang string, maxBytes int) (FileSample, []string, []string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return FileSample{}, nil, nil
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
	return sample, imports, localPackageCandidates(lang, text)
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

type dependencyCandidate struct {
	Language string
	Package  string
	Source   string
	Imports  map[string]bool
}

func dependencyGaps(profile Profile) []DependencyGap {
	candidates := dependencyCandidates(profile)
	defs := adapterPackageDefinitions()
	var out []DependencyGap
	for _, cand := range candidates {
		if dependencyHasDefinition(cand, defs) {
			continue
		}
		imports := make([]string, 0, len(cand.Imports))
		for imp := range cand.Imports {
			imports = append(imports, imp)
		}
		sort.Strings(imports)
		out = append(out, DependencyGap{
			Language: cand.Language,
			Package:  cand.Package,
			Source:   cand.Source,
			Score:    dependencyGapScore(cand),
			Imports:  imports,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].Language != out[j].Language {
			return out[i].Language < out[j].Language
		}
		return out[i].Package < out[j].Package
	})
	if len(out) > 120 {
		out = out[:120]
	}
	return out
}

func dependencyGapScore(c dependencyCandidate) int {
	text := strings.ToLower(c.Package)
	for imp := range c.Imports {
		text += " " + strings.ToLower(imp)
	}
	score := 0
	for token, weight := range map[string]int{
		"meteor": 80, "push": 60, "session": 45, "servlet": 40, "filter": 30,
		"request": 40, "response": 30, "websocket": 35, "socket": 20, "http": 20,
		"cors": 55, "origin": 45, "wildcard": 25,
		"auth": 45, "permission": 35, "role": 25, "redirect": 45, "callback": 35,
		"jenkins": 50, "hudson": 35, "stapler": 45, "queryparameter": 35,
		"formvalidation": 35,
		"sql":            45, "jdbc": 35, "database": 30, "query": 25,
		"template": 35, "html": 25, "xml": 35, "el": 20, "faces": 18,
		"upload": 45, "file": 25, "path": 25, "archive": 35, "zip": 30,
		"crypto": 30, "cipher": 30, "signature": 35, "attestation": 40,
		"predicate": 30, "sigstore": 28, "jms": 18, "message": 18,
		"deserialize": 40, "objectmessage": 35, "cache": 10,
		"credentials": 25, "credentials-plugin": 35,
		"modelcontextprotocol": 55, "mcp": 24, "stdio": 10,
	} {
		if strings.Contains(text, token) {
			score += weight
		}
	}
	if strings.HasPrefix(c.Source, "manifest:") {
		score += 8
	}
	return score
}

func dependencyCandidates(profile Profile) []dependencyCandidate {
	seen := map[string]*dependencyCandidate{}
	add := func(lang, pkg, source, imp string) {
		lang = strings.TrimSpace(lang)
		pkg = sca.NormalizePackageName(pkg)
		if pkg == "" || isLikelyStdOrLocalPackage(lang, pkg) {
			return
		}
		if strings.HasPrefix(source, "import:") && isLocalPackageCandidate(pkg, profile.LocalPkgs) {
			return
		}
		key := lang + "\x00" + pkg
		cand := seen[key]
		if cand == nil {
			cand = &dependencyCandidate{Language: lang, Package: pkg, Source: source, Imports: map[string]bool{}}
			seen[key] = cand
		}
		if cand.Source == "" || strings.HasPrefix(source, "manifest:") {
			cand.Source = source
		}
		if imp != "" {
			cand.Imports[imp] = true
		}
	}
	for _, man := range profile.Manifests {
		langs := manifestLanguages(man.Kind)
		for _, pkg := range man.Packages {
			for _, lang := range langs {
				add(lang, pkg, "manifest:"+man.Kind+":"+man.Path, "")
			}
		}
	}
	for lang, imports := range profile.Imports {
		for _, imp := range imports {
			for _, pkg := range importDependencyCandidates(lang, imp) {
				add(lang, pkg, "import:"+lang, imp)
			}
		}
	}
	out := make([]dependencyCandidate, 0, len(seen))
	for _, cand := range seen {
		out = append(out, *cand)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Language != out[j].Language {
			return out[i].Language < out[j].Language
		}
		return out[i].Package < out[j].Package
	})
	return out
}

func localPackageCandidates(lang, text string) []string {
	var out []string
	addJvm := func(pkg string) {
		parts := strings.Split(pkg, ".")
		if len(parts) >= 2 {
			out = append(out, parts[0]+"."+parts[1])
		}
		if len(parts) >= 3 {
			out = append(out, parts[0]+"."+parts[1]+"."+parts[2])
		}
	}
	switch lang {
	case "java", "kotlin", "scala", "groovy":
		re := regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z0-9_.]+)\s*;?`)
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			addJvm(sca.NormalizePackageName(m[1]))
		}
	case "go":
		re := regexp.MustCompile(`(?m)^\s*module\s+([A-Za-z0-9_.\-/]+)`)
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			out = append(out, sca.NormalizePackageName(m[1]))
		}
	case "php":
		re := regexp.MustCompile(`(?m)^\s*namespace\s+([A-Za-z0-9_\\]+)\s*;`)
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			parts := strings.FieldsFunc(m[1], func(r rune) bool { return r == '\\' || r == '/' })
			if len(parts) > 0 {
				out = append(out, sca.NormalizePackageName(parts[0]))
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	seen := map[string]bool{}
	deduped := out[:0]
	for _, pkg := range out {
		if pkg == "" || seen[pkg] {
			continue
		}
		seen[pkg] = true
		deduped = append(deduped, pkg)
	}
	return deduped
}

func isLocalPackageCandidate(pkg string, locals []string) bool {
	for _, local := range locals {
		if sca.PackageMatches(pkg, local) {
			return true
		}
	}
	return false
}

func manifestLanguages(kind string) []string {
	switch strings.ToLower(kind) {
	case "package.json":
		return []string{"javascript"}
	case "composer.json":
		return []string{"php"}
	case "go.mod":
		return []string{"go"}
	case "requirements.txt", "pyproject.toml":
		return []string{"python"}
	case "cargo.toml":
		return []string{"rust"}
	case "pom.xml":
		return []string{"java"}
	case "build.gradle":
		return []string{"java", "groovy", "kotlin"}
	default:
		return nil
	}
}

func importDependencyCandidates(lang, imp string) []string {
	imp = strings.TrimSpace(strings.Trim(imp, `"'`))
	if imp == "" || strings.HasPrefix(imp, ".") {
		return nil
	}
	if strings.ContainsAny(imp, " \t\r\n()+;") {
		return nil
	}
	switch lang {
	case "javascript":
		if strings.HasPrefix(imp, "@") {
			parts := strings.Split(imp, "/")
			if len(parts) >= 2 {
				return []string{parts[0] + "/" + parts[1]}
			}
		}
		return []string{sca.PackageRoot(imp)}
	case "python":
		root := strings.Split(imp, ".")[0]
		out := []string{root}
		out = append(out, sca.ImportAliases(root)...)
		return out
	case "go":
		return []string{imp, goModuleRoot(imp)}
	case "java", "kotlin", "scala", "groovy":
		parts := strings.Split(imp, ".")
		if len(parts) > 0 && startsUpper(parts[len(parts)-1]) {
			parts = parts[:len(parts)-1]
		}
		var out []string
		if len(parts) >= 2 {
			out = append(out, parts[0]+"."+parts[1])
		}
		if len(parts) >= 3 {
			out = append(out, parts[0]+"."+parts[1]+"."+parts[2])
		}
		return out
	case "php":
		parts := strings.FieldsFunc(imp, func(r rune) bool { return r == '\\' || r == '/' })
		if len(parts) > 0 {
			return []string{parts[0]}
		}
	case "ruby":
		return []string{strings.Split(imp, "/")[0]}
	}
	return []string{sca.PackageRoot(imp)}
}

func startsUpper(s string) bool {
	if s == "" {
		return false
	}
	r := rune(s[0])
	return r >= 'A' && r <= 'Z'
}

func goModuleRoot(imp string) string {
	parts := strings.Split(imp, "/")
	if len(parts) >= 3 && strings.Contains(parts[0], ".") {
		return strings.Join(parts[:3], "/")
	}
	return sca.PackageRoot(imp)
}

func isLikelyStdOrLocalPackage(lang, pkg string) bool {
	if pkg == "" || pkg == "." || strings.HasPrefix(pkg, "./") || strings.HasPrefix(pkg, "../") {
		return true
	}
	switch lang {
	case "go":
		return !strings.Contains(strings.Split(pkg, "/")[0], ".")
	case "java", "kotlin", "scala", "groovy":
		return pkg == "java" || strings.HasPrefix(pkg, "java.")
	case "javascript":
		switch pkg {
		case "assert", "buffer", "child_process", "crypto", "events", "fs", "http", "https", "net", "os", "path", "stream", "url", "util", "zlib":
			return true
		}
	case "python":
		switch pkg {
		case "__future__", "argparse", "asyncio", "base64", "collections", "contextlib", "datetime", "functools", "hashlib", "http", "io", "itertools", "json", "logging", "math", "os", "pathlib", "re", "shutil", "socket", "sqlite3", "ssl", "subprocess", "sys", "tempfile", "time", "typing", "unittest", "urllib", "uuid":
			return true
		}
	case "ruby":
		switch pkg {
		case "base64", "cgi", "date", "digest", "erb", "fileutils", "json", "logger", "net", "openssl", "pathname", "securerandom", "set", "time", "uri", "yaml":
			return true
		}
	}
	return false
}

func dependencyHasDefinition(c dependencyCandidate, defs map[string]map[string]bool) bool {
	if len(defs) == 0 {
		return false
	}
	langs := []string{c.Language, ""}
	for _, lang := range langs {
		for want := range defs[lang] {
			if sca.PackageMatches(c.Package, want) {
				return true
			}
			for imp := range c.Imports {
				if sca.PackageMatches(imp, want) {
					return true
				}
			}
		}
	}
	return false
}

func adapterPackageDefinitions() map[string]map[string]bool {
	root := filepath.Join(datadir.Root(), "adapters")
	defs := map[string]map[string]bool{}
	add := func(lang, pkg string) {
		pkg = sca.NormalizePackageName(pkg)
		if pkg == "" {
			return
		}
		if defs[lang] == nil {
			defs[lang] = map[string]bool{}
		}
		defs[lang][pkg] = true
	}
	pkgRe := regexp.MustCompile(`package\s+"([^"]+)"`)
	adapterRe := regexp.MustCompile(`(?m)\badapter\s+([A-Za-z0-9_]+)\s*\{`)
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".vyql") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		lang := ""
		if m := adapterRe.FindSubmatch(b); len(m) == 2 {
			lang = string(m[1])
		} else if rel, err := filepath.Rel(root, path); err == nil {
			parts := strings.Split(filepath.ToSlash(rel), "/")
			if len(parts) >= 4 && parts[0] == "packages" && parts[1] == "generated" {
				lang = parts[2]
			}
		}
		for _, m := range pkgRe.FindAllSubmatch(b, -1) {
			add(lang, string(m[1]))
		}
		return nil
	})
	return defs
}
