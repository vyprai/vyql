package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCFunctionContextIncludesKerberosPasswordServiceArgumentToken(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "kerberos.c")
	src := []byte(`
static krb5_error_code verify_password(krb5_context context, krb5_principal principal, const char *password, krb5_principal server)
{
    krb5_creds creds;
    krb5_get_init_creds_opt gic_options;
    memset(&creds, 0, sizeof(creds));
    krb5_get_init_creds_opt_init(&gic_options);
    return krb5_get_init_creds_password(context, &creds, principal, (char *)password, NULL, NULL, 0, NULL, &gic_options);
}
`)
	if err := os.WriteFile(file, src, 0o644); err != nil {
		t.Fatal(err)
	}

	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	tokens := cFuncContextTokens(prog.Modules[0].Body, "verify_password")
	for _, want := range []string{
		"call_path:krb5_get_init_creds_password",
		"call_arg_at:krb5_get_init_creds_password:6:0",
		"call_arg_at:krb5_get_init_creds_password:7:NULL",
		"call_arg_shape_at:krb5_get_init_creds_password:7:NULL",
	} {
		if !strings.Contains(tokens, want) {
			t.Fatalf("Kerberos context missing %q; context=%q", want, tokens)
		}
	}
}
