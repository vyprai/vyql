package treesitter

import (
	"testing"

	"github.com/vyprai/vyql/extract/nir"
)

func TestReplaceNameClonesReplacementExpression(t *testing.T) {
	repl := nir.Seq{Parts: []nir.Expr{nir.Name{ID: "x", Loc: "app.py:1"}}, Loc: "app.py:1"}
	ex := nir.Seq{Parts: []nir.Expr{nir.Name{ID: "x", Loc: "app.py:2"}}, Loc: "app.py:2"}

	got := replaceName(ex, "x", repl).(nir.Seq)
	got.Parts[0].(nir.Seq).Parts[0] = nir.Const{Value: "\"mutated\"", Loc: "app.py:3"}

	if repl.Parts[0].(nir.Name).ID != "x" {
		t.Fatalf("replacement expression was aliased into output: %#v", repl)
	}
}

func TestPythonSemanticReviewMarksLoopUrlFetchAndTracebackHtml(t *testing.T) {
	raw := `
def mirror(urls):
    for url in urls:
        requests.get(url, stream=True)

def error_page():
    stack = traceback.format_exc()
    return "<html><pre>%s</pre></html>" % stack
`
	got := pySemanticReviewTokens(raw, "mirror")
	for _, want := range []string{
		"python_review:loop_requests_get_url_without_validation",
		"python_review:traceback_format_exc_pre_unescaped",
		"python_review:traceback_format_exc_html_unescaped",
	} {
		if !containsString(got, want) {
			t.Fatalf("missing semantic token %q in %#v", want, got)
		}
	}
}

func TestPythonSemanticReviewDoesNotMarkGuardedLoopUrlFetchAndTracebackHtml(t *testing.T) {
	raw := `
def mirror(urls):
    for url in urls:
        validate_url(url)
        requests.get(url, stream=True)

def error_page():
    stack = html.escape(traceback.format_exc())
    return "<html><pre>%s</pre></html>" % stack
`
	got := pySemanticReviewTokens(raw, "mirror")
	for _, want := range []string{
		"python_review:loop_requests_get_url_without_validation",
		"python_review:traceback_format_exc_pre_unescaped",
		"python_review:traceback_format_exc_html_unescaped",
	} {
		if containsString(got, want) {
			t.Fatalf("guarded code emitted semantic token %q in %#v", want, got)
		}
	}
}

func TestPythonSemanticReviewMarksRequestPathPercentSLogInjection(t *testing.T) {
	raw := `
def cors_after_request(resp):
    normalized_path = unquote_plus(request.path)
    LOG.debug("Request to '%s' matches CORS resource '%s'. Using options: %s",
              request.path, get_regexp_pattern(res_regex), res_options)
    return resp
`
	got := pySemanticReviewTokens(raw, "cors_after_request")
	if !containsString(got, "python_review:request_path_percent_s_log_injection") {
		t.Fatalf("missing request path percent-s semantic token in %#v", got)
	}
}

func TestPythonSemanticReviewDoesNotMarkEscapedRequestPathPercentLog(t *testing.T) {
	for _, raw := range []string{
		`
def cors_after_request(resp):
    normalized_path = unquote_plus(request.path)
    LOG.debug("Request to '%r' matches CORS resource '%s'. Using options: %s",
              request.path, get_regexp_pattern(res_regex), res_options)
    return resp
`,
		`
def cors_after_request(resp):
    normalized_path = unquote_plus(request.path)
    LOG.debug("Request to '%s' matches CORS resource '%s'. Using options: %s",
              repr(request.path), get_regexp_pattern(res_regex), res_options)
    return resp
`,
	} {
		got := pySemanticReviewTokens(raw, "cors_after_request")
		if containsString(got, "python_review:request_path_percent_s_log_injection") {
			t.Fatalf("guarded request path logger emitted semantic token in %#v", got)
		}
	}
}

func TestPythonSemanticReviewMarksCredentialAttributeLogExposure(t *testing.T) {
	raw := `
def get(self, location):
    loc = location.store_location
    bucket = loc.bucket
    key = loc.key
    LOG.debug("Retrieved image object from S3 using s3_host=%(s3_host)s, "
              "access_key=%(accesskey)s, bucket=%(bucket)s, key=%(key)s)",
              {'s3_host': loc.s3serviceurl, 'accesskey': loc.accesskey,
               'bucket': bucket, 'key': key})
`
	got := pySemanticReviewTokens(raw, "get")
	if !containsString(got, "python_review:credential_attribute_log_exposure") {
		t.Fatalf("missing credential attribute log exposure token in %#v", got)
	}
}

func TestPythonSemanticReviewDoesNotMarkCredentialAttributeLogWithoutCredential(t *testing.T) {
	raw := `
def get(self, location):
    loc = location.store_location
    bucket = loc.bucket
    key = loc.key
    LOG.debug("Retrieved image object from S3 using s3_host=%(s3_host)s, "
              "bucket=%(bucket)s key=%(key)s)",
              {'s3_host': loc.s3serviceurl, 'bucket': bucket, 'key': key})
`
	got := pySemanticReviewTokens(raw, "get")
	if containsString(got, "python_review:credential_attribute_log_exposure") {
		t.Fatalf("omitted credential log emitted exposure token in %#v", got)
	}
}

func TestPythonSemanticReviewMarksPickleLoadsJoblibModelLoader(t *testing.T) {
	raw := `
class ClusteringModel:
    @staticmethod
    def load(model_file):
        return pickle.loads(joblib.load(str(model_file)))
`
	got := pySemanticReviewTokens(raw, "load")
	if !containsString(got, "python_review:pickle_loads_joblib_model_loader") {
		t.Fatalf("missing pickle/joblib model loader token in %#v", got)
	}
}

func TestPythonSemanticReviewDoesNotMarkRestrictedPickleLoadsJoblibModelLoader(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{name: "load", raw: `
class RestrictedUnpickler:
    @staticmethod
    def loads(data):
        return data

class ClusteringModel:
    @staticmethod
    def load(model_file):
        return RestrictedUnpickler.loads(joblib.load(str(model_file)))
`},
		{name: "load", raw: `
class ClusteringModel:
    @staticmethod
    def load(model_file):
        return safe_load(joblib.load(str(model_file)))
`},
		{name: "build", raw: `
class ClusteringModel:
    @staticmethod
    def build(model_file):
        return pickle.loads(joblib.load(str(model_file)))
`},
	} {
		got := pySemanticReviewTokens(tc.raw, tc.name)
		if containsString(got, "python_review:pickle_loads_joblib_model_loader") {
			t.Fatalf("guarded or non-loader code emitted pickle/joblib token in %#v", got)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
