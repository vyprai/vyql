package frontend

import (
	"strconv"
	"testing"

	adapterapply "github.com/vyprai/vyql/adapters"
	"github.com/vyprai/vyql/usg"
)

type packageCatalogMapping struct {
	pkg     string
	pattern string
	method  bool
	concept string
	arg     int
	recvTyp string
}

func TestConstraintAllows(t *testing.T) {
	cases := []struct {
		constraint, recvType string
		want                 bool
	}{
		{"sql.DB", "sql.DB", true},
		{"HttpServletRequest", "javax.servlet.http.HttpServletRequest", true},
		{"javax.servlet.http.HttpServletRequest", "HttpServletRequest", true},
		{"sql.DB", "redis.Client", false},
		{"sql.DB,sqlx.DB,gorm.DB", "gorm.DB", true},
		{"sql.DB,sqlx.DB,gorm.DB", "mongo.Database", false},
		{"sql.DB", "", false}, // empty recv handled by the caller, not here
	}
	for _, c := range cases {
		if got := constraintAllows(c.constraint, c.recvType); got != c.want {
			t.Errorf("constraintAllows(%q,%q)=%v want %v", c.constraint, c.recvType, got, c.want)
		}
	}
}

func TestMatchPath(t *testing.T) {
	// prefix mode: exact, dotted, subscript continuations
	if !matchPath("request.form", []string{"request.form"}, "prefix") {
		t.Error("exact prefix should match")
	}
	if !matchPath("request.form.get", []string{"request.form"}, "prefix") {
		t.Error("dotted continuation should match")
	}
	if matchPath("request.formdata", []string{"request.form"}, "prefix") {
		t.Error("a longer word should NOT prefix-match (request.formdata != request.form.)")
	}
	// contains mode: substring anywhere (Go varying receivers)
	if !matchPath("r.URL.Query.Get", []string{".URL.Query"}, "contains") {
		t.Error("contains should match a mid-path substring")
	}
	if matchPath("db.Query", []string{".URL.Query"}, "contains") {
		t.Error("contains should not falsely match an unrelated path")
	}
}

func TestPackageGatedSinkRequiresPackageEvidence(t *testing.T) {
	spec := adapterSpec{
		Name:       "python",
		Technology: "python",
		Sinks: []sinkSpec{{
			Concept:  "code.Deserialization",
			Pattern:  "yaml.load",
			Packages: []string{"pyyaml", "yaml"},
		}},
	}
	adapter := spec.sinkAdapter()

	withoutPkg := usg.NewInMemStore()
	withoutPkg.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "app.py:3"}})
	withoutPkg.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "app.py:3", "callee_path": "yaml.load", "method": "load", "arg0": "arg",
	}})
	if got := adapter.Apply(withoutPkg); len(got) != 0 {
		t.Fatalf("package-gated sink fired without evidence: %+v", got)
	}

	withImport := usg.NewInMemStore()
	withImport.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "app.py:1", "module": "yaml", "package": "yaml",
	}})
	withImport.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "app.py:3"}})
	withImport.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "app.py:3", "callee_path": "yaml.load", "method": "load", "arg0": "arg",
	}})
	if got := adapter.Apply(withImport); len(got) != 1 || got[0].NodeID != "arg" || got[0].Concept != "code.Deserialization" {
		t.Fatalf("package-gated sink did not fire with import evidence: %+v", got)
	}

	withSBOM := usg.NewInMemStore()
	withSBOM.AddNode(usg.Node{ID: "pkg:pypi/pyyaml@6.0", Type: "sbom.PackageVersion", Props: map[string]string{
		"name": "pyyaml", "version": "6.0",
	}})
	withSBOM.AddNode(usg.Node{ID: "arg", Type: "code.Arg", Props: map[string]string{"loc": "app.py:3"}})
	withSBOM.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "app.py:3", "callee_path": "yaml.load", "method": "load", "arg0": "arg",
	}})
	if got := adapter.Apply(withSBOM); len(got) != 1 || got[0].NodeID != "arg" {
		t.Fatalf("package-gated sink did not fire with SBOM evidence: %+v", got)
	}
}

func TestPackageGatedSourceRequiresPackageEvidence(t *testing.T) {
	spec := adapterSpec{
		Name:       "python",
		Technology: "python",
		Inputs: []inputSpec{{
			Concept:  "code.HttpInput",
			Paths:    []string{"flask.request.args"},
			Match:    "prefix",
			Packages: []string{"flask"},
		}},
	}
	adapter := spec.inputAdapter()

	withoutPkg := usg.NewInMemStore()
	withoutPkg.AddNode(usg.Node{ID: "src", Type: "code.Call", Props: map[string]string{
		"loc": "app.py:2", "callee_path": "flask.request.args", "method": "args",
	}})
	if got := adapter.Apply(withoutPkg); len(got) != 0 {
		t.Fatalf("package-gated source fired without evidence: %+v", got)
	}

	withPkg := usg.NewInMemStore()
	withPkg.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "app.py:1", "module": "flask", "package": "flask",
	}})
	withPkg.AddNode(usg.Node{ID: "src", Type: "code.Call", Props: map[string]string{
		"loc": "app.py:2", "callee_path": "flask.request.args", "method": "args",
	}})
	if got := adapter.Apply(withPkg); len(got) != 1 || got[0].NodeID != "src" || got[0].Concept != "code.HttpInput" {
		t.Fatalf("package-gated source did not fire with package evidence: %+v", got)
	}
}

func TestPackageGatedReceiverSourceUsesResolvedType(t *testing.T) {
	spec := adapterSpec{
		Name:       "javascript",
		Technology: "javascript",
		Inputs: []inputSpec{{
			Concept:    "code.HttpInput",
			Methods:    []string{"body"},
			Receiver:   true,
			Constraint: "express.Request",
			Packages:   []string{"express"},
		}},
	}
	adapter := spec.inputAdapter()

	withWrongReceiver := usg.NewInMemStore()
	withWrongReceiver.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "app.js:1", "module": "express", "package": "express",
	}})
	withWrongReceiver.AddNode(usg.Node{ID: "src", Type: "code.Attr", Props: map[string]string{
		"loc": "app.js:3", "callee_path": "payload.body", "method": "body",
	}})
	if got := adapter.Apply(withWrongReceiver); len(got) != 0 {
		t.Fatalf("receiver source fired without receiver type: %+v", got)
	}

	withReceiver := usg.NewInMemStore()
	withReceiver.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "app.js:1", "module": "express", "package": "express",
	}})
	withReceiver.AddNode(usg.Node{ID: "src", Type: "code.Attr", Props: map[string]string{
		"loc": "app.js:3", "callee_path": "request.body", "method": "body", "recv_type": "express.Request",
	}})
	if got := adapter.Apply(withReceiver); len(got) != 1 || got[0].NodeID != "src" || got[0].Concept != "code.HttpInput" {
		t.Fatalf("receiver source did not fire with receiver type: %+v", got)
	}
}

func TestPackageGatedControlRequiresPackageEvidence(t *testing.T) {
	spec := adapterSpec{
		Name:       "javascript",
		Technology: "javascript",
		Controls: []controlSpec{{
			Concept:  "core.HtmlEscape",
			Pattern:  "sanitize",
			ByMethod: true,
			Packages: []string{"dompurify"},
		}},
	}
	adapter := spec.controlAdapter()

	withoutPkg := usg.NewInMemStore()
	withoutPkg.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "app.js:2", "callee_path": "DOMPurify.sanitize", "method": "sanitize",
	}})
	if got := adapter.Apply(withoutPkg); len(got) != 0 {
		t.Fatalf("package-gated control fired without evidence: %+v", got)
	}

	withPkg := usg.NewInMemStore()
	withPkg.AddNode(usg.Node{ID: "imp", Type: "code.Import", Props: map[string]string{
		"loc": "app.js:1", "module": "dompurify", "package": "dompurify",
	}})
	withPkg.AddNode(usg.Node{ID: "call", Type: "code.Call", Props: map[string]string{
		"loc": "app.js:2", "callee_path": "DOMPurify.sanitize", "method": "sanitize",
	}})
	if got := adapter.Apply(withPkg); len(got) != 1 || got[0].NodeID != "call" || got[0].Concept != "core.HtmlEscape" {
		t.Fatalf("package-gated control did not fire with package evidence: %+v", got)
	}
}

func TestGroupedPackageCatalogsCoverSupportedLanguages(t *testing.T) {
	cases := []struct {
		tech    string
		ext     string
		source  packageCatalogMapping
		sink    packageCatalogMapping
		control packageCatalogMapping
	}{
		{"bash", ".sh", packageCatalogMapping{"cgi", "$QUERY_STRING", false, "code.HttpInput", 0, ""}, packageCatalogMapping{"mysql-client", "mysql", false, "code.SqlExecution", -1, ""}, packageCatalogMapping{"coreutils", "realpath", false, "core.PathCanonicalization", 0, ""}},
		{"c", ".c", packageCatalogMapping{"mongoose", "mg_get_http_var", false, "code.HttpInput", 0, ""}, packageCatalogMapping{"mysqlclient", "mysql_query", false, "code.SqlExecution", 1, ""}, packageCatalogMapping{"mysqlclient", "mysql_real_escape_string", false, "core.SqlParameterization", 0, ""}},
		{"cpp", ".cpp", packageCatalogMapping{"crow", "crow.request", false, "code.HttpInput", 0, ""}, packageCatalogMapping{"mysqlclient", "mysql_query", false, "code.SqlExecution", 1, ""}, packageCatalogMapping{"mysqlclient", "mysql_real_escape_string", false, "core.SqlParameterization", 0, ""}},
		{"csharp", ".cs", packageCatalogMapping{"Microsoft.AspNetCore.Http", "Query", true, "code.HttpInput", 0, "HttpRequest"}, packageCatalogMapping{"Dapper", "Query", true, "code.SqlExecution", 0, ""}, packageCatalogMapping{"System.Text.Encodings.Web", "HtmlEncoder.Encode", false, "core.HtmlEscape", 0, ""}},
		{"dart", ".dart", packageCatalogMapping{"shelf", "queryParameters", true, "code.HttpInput", 0, "Request"}, packageCatalogMapping{"sqflite", "rawQuery", true, "code.SqlExecution", 0, ""}, packageCatalogMapping{"dart:convert", "htmlEscape.convert", false, "core.HtmlEscape", 0, ""}},
		{"elixir", ".ex", packageCatalogMapping{"phoenix", "params", false, "code.HttpInput", 0, ""}, packageCatalogMapping{"elixir", "System.cmd", false, "code.CommandExecution", 0, ""}, packageCatalogMapping{"phoenix_html", "Phoenix.HTML.html_escape", false, "core.HtmlEscape", 0, ""}},
		{"go", ".go", packageCatalogMapping{"net/http", "Query", true, "code.HttpInput", 0, "http.Request"}, packageCatalogMapping{"database/sql", "Query", true, "code.SqlExecution", 0, ""}, packageCatalogMapping{"html", "html.EscapeString", false, "core.HtmlEscape", 0, ""}},
		{"groovy", ".groovy", packageCatalogMapping{"grails", "params", false, "code.HttpInput", 0, ""}, packageCatalogMapping{"groovy-sql", "execute", true, "code.SqlExecution", 0, ""}, packageCatalogMapping{"commons-text", "StringEscapeUtils.escapeHtml4", false, "core.HtmlEscape", 0, ""}},
		{"java", ".java", packageCatalogMapping{"javax.servlet", "getParameter", true, "code.HttpInput", 0, "HttpServletRequest"}, packageCatalogMapping{"java.sql", "executeQuery", true, "code.SqlExecution", 0, ""}, packageCatalogMapping{"commons-text", "StringEscapeUtils.escapeHtml4", false, "core.HtmlEscape", 0, ""}},
		{"javascript", ".js", packageCatalogMapping{"express", "body", true, "code.HttpInput", 0, "express.Request"}, packageCatalogMapping{"sequelize", "sequelize.query", false, "code.SqlExecution", 0, ""}, packageCatalogMapping{"dompurify", "DOMPurify.sanitize", false, "core.HtmlEscape", 0, ""}},
		{"kotlin", ".kt", packageCatalogMapping{"javax.servlet", "getParameter", true, "code.HttpInput", 0, "HttpServletRequest"}, packageCatalogMapping{"java.sql", "executeQuery", true, "code.SqlExecution", 0, ""}, packageCatalogMapping{"commons-text", "StringEscapeUtils.escapeHtml4", false, "core.HtmlEscape", 0, ""}},
		{"lua", ".lua", packageCatalogMapping{"openresty", "ngx.var.arg", false, "code.HttpInput", 0, ""}, packageCatalogMapping{"lua-resty-mysql", "db.query", false, "code.SqlExecution", 0, ""}, packageCatalogMapping{"openresty", "ngx.quote_sql_str", false, "core.SqlParameterization", 0, ""}},
		{"objc", ".m", packageCatalogMapping{"AFNetworking", "param", true, "code.HttpInput", 0, ""}, packageCatalogMapping{"FMDB", "FMDatabase.executeQuery", false, "code.SqlExecution", 0, ""}, packageCatalogMapping{"Foundation", "stringByAddingPercentEncodingWithAllowedCharacters", false, "core.RedirectAllowlist", 0, ""}},
		{"perl", ".pl", packageCatalogMapping{"CGI", "param", false, "code.HttpInput", 0, ""}, packageCatalogMapping{"DBI", "execute", true, "code.SqlExecution", 0, ""}, packageCatalogMapping{"HTML::Entities", "HTML.Entities.encode_entities", false, "core.HtmlEscape", 0, ""}},
		{"php", ".php", packageCatalogMapping{"php", "$_GET", false, "code.HttpInput", 0, ""}, packageCatalogMapping{"mysqli", "mysqli_query", false, "code.SqlExecution", 1, ""}, packageCatalogMapping{"php", "htmlspecialchars", false, "core.HtmlEscape", 0, ""}},
		{"powershell", ".ps1", packageCatalogMapping{"Azure.Functions", "$Request.Query", false, "code.HttpInput", 0, ""}, packageCatalogMapping{"SqlServer", "Invoke-Sqlcmd", false, "code.SqlExecution", 0, ""}, packageCatalogMapping{"System.Web", "HtmlEncode", false, "core.HtmlEscape", 0, ""}},
		{"python", ".py", packageCatalogMapping{"flask", "request.args", false, "code.HttpInput", 0, ""}, packageCatalogMapping{"pyyaml", "yaml.load", false, "code.Deserialization", 0, ""}, packageCatalogMapping{"markupsafe", "markupsafe.escape", false, "core.HtmlEscape", 0, ""}},
		{"ruby", ".rb", packageCatalogMapping{"rails", "params", false, "code.HttpInput", 0, ""}, packageCatalogMapping{"activerecord", "find_by_sql", true, "code.SqlExecution", 0, ""}, packageCatalogMapping{"erb", "ERB.Util.html_escape", false, "core.HtmlEscape", 0, ""}},
		{"rust", ".rs", packageCatalogMapping{"actix-web", "query", true, "code.HttpInput", 0, "HttpRequest"}, packageCatalogMapping{"sqlx", "query", true, "code.SqlExecution", 0, ""}, packageCatalogMapping{"ammonia", "ammonia.clean", false, "core.HtmlEscape", 0, ""}},
		{"scala", ".scala", packageCatalogMapping{"playframework", "getQueryString", true, "code.HttpInput", 0, "Request"}, packageCatalogMapping{"slick", "sql", false, "code.SqlExecution", 0, ""}, packageCatalogMapping{"twirl", "HtmlFormat.escape", false, "core.HtmlEscape", 0, ""}},
		{"solidity", ".sol", packageCatalogMapping{"solidity", "msg.data", false, "code.HttpInput", 0, ""}, packageCatalogMapping{"solidity", "call", true, "code.ExternalCall", 0, ""}, packageCatalogMapping{"@openzeppelin/contracts", "onlyOwner", false, "core.OwnershipCheck", 0, ""}},
		{"swift", ".swift", packageCatalogMapping{"vapor", "query", true, "code.HttpInput", 0, "Request"}, packageCatalogMapping{"fluent", "raw", true, "code.SqlExecution", 0, ""}, packageCatalogMapping{"vapor", "String.htmlEscaped", false, "core.HtmlEscape", 0, ""}},
	}

	for _, tc := range cases {
		t.Run(tc.tech, func(t *testing.T) {
			store := usg.NewInMemStore()
			for i, pkg := range []string{tc.source.pkg, tc.sink.pkg, tc.control.pkg} {
				store.AddNode(usg.Node{ID: tc.tech + ":import:" + pkg, Type: "code.Import", Props: map[string]string{
					"loc":     tc.tech + tc.ext + ":1",
					"module":  pkg,
					"package": pkg,
					"root":    pkg,
				}})
				_ = i
			}

			addCall(store, "src", tc.tech, tc.ext, tc.source, 0)
			sinkNode := addCall(store, "sink", tc.tech, tc.ext, tc.sink, tc.sink.arg)
			addCall(store, "control", tc.tech, tc.ext, tc.control, 0)

			if _, _, err := adapterapply.Apply(store, AdaptersFor(tc.tech), nil); err != nil {
				t.Fatalf("apply adapters: %v", err)
			}
			assertNodeConcept(t, store, "src", tc.source.concept)
			assertNodeConcept(t, store, sinkNode, tc.sink.concept)
			assertNodeConcept(t, store, "control", tc.control.concept)
		})
	}
}

func addCall(store usg.Store, id, tech, ext string, m packageCatalogMapping, arg int) string {
	props := map[string]string{
		"loc":         tech + ext + ":2",
		"callee_path": m.pattern,
		"method":      lastSegment(m.pattern),
	}
	if m.method {
		props["method"] = m.pattern
	}
	if m.recvTyp != "" {
		props["recv_type"] = m.recvTyp
	}
	target := id
	if arg < 0 {
		arg = 0
	}
	if id == "sink" {
		target = id + ":arg"
		argID := target
		store.AddNode(usg.Node{ID: argID, Type: "code.Arg", Props: map[string]string{"loc": tech + ext + ":2"}})
		props["arg"+strconv.Itoa(arg)] = argID
	}
	store.AddNode(usg.Node{ID: id, Type: "code.Call", Props: props})
	return target
}

func assertNodeConcept(t *testing.T, store usg.Store, nodeID, concept string) {
	t.Helper()
	labels, err := store.Labels(nodeID)
	if err != nil {
		t.Fatalf("labels(%s): %v", nodeID, err)
	}
	for _, label := range labels {
		if label.Concept == concept {
			return
		}
	}
	t.Fatalf("node %s missing %s label; got %+v", nodeID, concept, labels)
}

func lastSegment(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return s[i+1:]
		}
	}
	return s
}
