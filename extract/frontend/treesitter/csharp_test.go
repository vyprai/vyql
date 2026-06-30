package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
)

func TestCSharpExtractsCallsInsidePreprocessorBranches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Sample.cs")
	src := `using System;
using System.Runtime.Loader;

class T {
  public static Type GetType(string typeName, bool throwOnError, bool ignoreCase) {
    try {
      return Type.GetType(typeName, throwOnError, ignoreCase);
    } catch {
#if NET5_0_OR_GREATER
      string[] splitName = typeName.Split(',');
      var asm = AssemblyLoadContext.Default.LoadFromAssemblyPath(AppContext.BaseDirectory + splitName[1].Trim() + ".dll");
      return asm.GetType(splitName[0].Trim());
#else
      throw;
#endif
    }
  }
}`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractCSharp([]string{path}, dir)
	if err != nil {
		t.Fatalf("ExtractCSharp: %v", err)
	}
	g, err := lowering.Lower(prog, false)
	if err != nil {
		t.Fatalf("Lower: %v", err)
	}
	calls, _ := g.NodesOfType("code.Call")
	for _, id := range calls {
		n, _, _ := g.GetNode(id)
		if strings.Contains(n.Prop("callee_path"), "LoadFromAssemblyPath") {
			return
		}
	}
	t.Fatal("expected LoadFromAssemblyPath call inside #if branch to be extracted")
}

func TestCSharpFunctionContextIncludesStructuredTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Sample.cs")
	src := `using System.IO;

class FileService {
  public async Task<File> Create(File file, Stream fileContent, CancellationToken cancellationToken = default) {
    file.NormalizedName = file.Name.Trim().ToLower();
    await fileStorageProvider.Upload(file.Id.ToString(), fileContent, cancellationToken);
    if (file.Extension == ".svg") {
      return file;
    }
    return file;
  }
}`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractCSharp([]string{path}, dir)
	if err != nil {
		t.Fatalf("ExtractCSharp: %v", err)
	}
	g, err := lowering.Lower(prog, false)
	if err != nil {
		t.Fatalf("Lower: %v", err)
	}
	calls, _ := g.NodesOfType("code.Call")
	for _, id := range calls {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") != "analysis.function.context" || !strings.Contains(n.Prop("str_args"), "name=Create") {
			continue
		}
		tokens := n.Prop("str_args")
		for _, want := range []string{
			"lang=csharp",
			"function_name:Create",
			"param_name:fileContent",
			"param_type:Stream",
			"call_path:fileStorageProvider.Upload",
			"call:Upload",
			"selector:file.NormalizedName",
			"identifier:fileContent",
			"literal:.svg",
		} {
			if !strings.Contains(tokens, want) {
				t.Fatalf("analysis.function.context missing %q in %q", want, tokens)
			}
		}
		return
	}
	t.Fatal("analysis.function.context for Create not found")
}

func TestCSharpFunctionContextExpressionShapeTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Sample.cs")
	src := `class Encoded {
  int Decode(Input input, int count) {
    var a = (int)input.ReadVarUInt32();
    var b = input.ReadVarUInt32() << 8;
    input.SkipBytes(count * sizeof(int));
    count += b;
    checked((int)input.ReadVarUInt32());
    checked(count * sizeof(int));
    checked(count + b);
    return count;
  }
}`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractCSharp([]string{path}, dir)
	if err != nil {
		t.Fatalf("ExtractCSharp: %v", err)
	}
	g, err := lowering.Lower(prog, false)
	if err != nil {
		t.Fatalf("Lower: %v", err)
	}
	calls, _ := g.NodesOfType("code.Call")
	for _, id := range calls {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") != "analysis.function.context" || !strings.Contains(n.Prop("str_args"), "name=Decode") {
			continue
		}
		tokens := n.Prop("str_args")
		for _, want := range []string{
			"cast_shape:CAST(int,CALL)",
			"binary_shape:CALL<<INT",
			"call_arg_shape:input.SkipBytes:ID*SIZEOF",
			"assign_op_shape:ID+=ID",
			"checked_shape:CAST(int,CALL)",
			"checked_shape:ID*SIZEOF",
			"checked_shape:ID+ID",
		} {
			if !strings.Contains(tokens, want) {
				t.Fatalf("analysis.function.context missing %q in %q", want, tokens)
			}
		}
		return
	}
	t.Fatal("analysis.function.context for Decode not found")
}

func TestCSharpJwtTokenValidationParametersObservations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Sample.cs")
	src := `class C {
  void A() {
    var first = new TokenValidationParameters {
      ValidateIssuerSigningKey = false,
      RequireSignedTokens = true
    };
    var second = new TokenValidationParameters {
      RequireSignedTokens = false
    };
  }
}`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractCSharp([]string{path}, dir)
	if err != nil {
		t.Fatalf("ExtractCSharp: %v", err)
	}
	g, err := lowering.Lower(prog, false)
	if err != nil {
		t.Fatalf("Lower: %v", err)
	}
	calls, _ := g.NodesOfType("code.Call")
	var requireSignedFalse, validateIssuerFalse int
	for _, id := range calls {
		n, _, _ := g.GetNode(id)
		switch n.Prop("callee_path") {
		case "analysis.csharp.jwt_require_signed_tokens_false":
			requireSignedFalse++
		case "analysis.csharp.jwt_validate_issuer_signing_key_false":
			validateIssuerFalse++
		}
	}
	if requireSignedFalse != 1 || validateIssuerFalse != 1 {
		t.Fatalf("JWT observations = requireSigned:%d validateIssuer:%d, want 1/1", requireSignedFalse, validateIssuerFalse)
	}
}

func TestCSharpDetectsUnencodedCASTicketQueryParameter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "UrlUtil.cs")
	src := `using System.Web;

class UrlUtil {
  public static string Vulnerable(string ticket, bool gateway) {
    var ub = new EnhancedUriBuilder("https://cas.example/serviceValidate");
    ub.QueryItems.Add(CasAuthentication.TicketValidator.ServiceParameterName, HttpUtility.UrlEncode(BuildService(gateway)));
    ub.QueryItems.Add(CasAuthentication.TicketValidator.ArtifactParameterName, ticket);
    return ub.Uri.AbsoluteUri;
  }

  public static string Fixed(string ticket, bool gateway) {
    var ub = new EnhancedUriBuilder("https://cas.example/serviceValidate");
    ub.QueryItems.Add(CasAuthentication.TicketValidator.ServiceParameterName, HttpUtility.UrlEncode(BuildService(gateway)));
    ub.QueryItems.Add(CasAuthentication.TicketValidator.ArtifactParameterName, HttpUtility.UrlEncode(ticket));
    return ub.Uri.AbsoluteUri;
  }
}`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractCSharp([]string{path}, dir)
	if err != nil {
		t.Fatalf("ExtractCSharp: %v", err)
	}
	g, err := lowering.Lower(prog, false)
	if err != nil {
		t.Fatalf("Lower: %v", err)
	}
	calls, _ := g.NodesOfType("code.Call")
	var vulnerable, fixed bool
	for _, id := range calls {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") != "analysis.csharp.cas_unencoded_ticket_query_parameter" {
			continue
		}
		tokens := n.Prop("str_args")
		if strings.Contains(tokens, "function_name:Vulnerable") {
			vulnerable = true
		}
		if strings.Contains(tokens, "function_name:Fixed") {
			fixed = true
		}
	}
	if !vulnerable {
		t.Fatalf("unencoded CAS ticket query parameter observation was not emitted")
	}
	if fixed {
		t.Fatalf("encoded CAS ticket query parameter was marked vulnerable")
	}
}
