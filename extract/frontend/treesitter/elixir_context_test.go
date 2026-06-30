package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
)

func TestElixirFunctionContextIncludesCallInventory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "worker.ex")
	src := []byte(`defmodule NodeJS.Worker do
  def handle_call({module, args, opts}, _from, [_, port] = state) do
    timeout = Keyword.get(opts, :timeout)
    body = Jason.encode!([Tuple.to_list(module), args, false])
    Port.command(port, "#{body}\n")
    get_response(~c"", timeout)
  end
end
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractElixir([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.function.context" && strings.Contains(n.Prop("str_args"), "name=handle_call") {
			args := n.Prop("str_args")
			for _, want := range []string{
				"lang=elixir",
				"call_path:Keyword.get",
				"call_path:Jason.encode!",
				"call_path:Tuple.to_list",
				"call_path:Port.command",
				"call_path:get_response",
				"function_name:handle_call",
				"identifier:timeout",
				"port_protocol:request_response_missing_correlation",
			} {
				if !strings.Contains(args, want) {
					t.Fatalf("Elixir function context missing %q; context=%q", want, args)
				}
			}
			return
		}
	}
	t.Fatalf("analysis.function.context for handle_call not found")
}

func TestElixirFunctionContextDoesNotMarkCorrelatedPortResponses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "worker.ex")
	src := []byte(`defmodule NodeJS.Worker do
  defp extract_uid(data), do: {"0", data}

  def handle_call({module, args, opts}, _from, %{port: port, uid_counter: uid_counter} = state) do
    timeout = Keyword.get(opts, :timeout)
    uid = Integer.to_string(uid_counter)
    body = Jason.encode!([uid, Tuple.to_list(module), args, false])
    Port.command(port, "#{body}\n")
    get_response(~c"", timeout, port, uid)
  end
end
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractElixir([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == "analysis.function.context" && strings.Contains(n.Prop("str_args"), "name=handle_call") {
			if strings.Contains(n.Prop("str_args"), "port_protocol:request_response_missing_correlation") {
				t.Fatalf("correlated Elixir port protocol should not emit missing-correlation token; context=%q", n.Prop("str_args"))
			}
			return
		}
	}
	t.Fatalf("analysis.function.context for correlated handle_call not found")
}
