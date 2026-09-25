package lowering

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/solvers"
	"github.com/vyprai/vyql/internal/usg"
)

// parameterMemberFixture is the shape rank 3455 was blocked on: an endpoint whose
// argument a framework builds from a schema class, where the validation the framework
// applies (the class's field validator) is written in a third file and so is a call in
// neither the endpoint's graph nor anything the endpoint calls.
const parameterMemberAPI = `from python_on_whales.utils import run as docker_run_cmd
from shared.schemas.command_schemas import RunCommandRequestBodySchema


@router.post("/run")
async def run(body: RunCommandRequestBodySchema) -> tuple[str, str]:
    _command = DOCKER.config.docker_cmd + body.command
    return await asyncall(
        lambda: docker_run_cmd(_command),
    )
`

const parameterMemberSchema = `from pydantic import BaseModel, field_validator


class RunCommandRequestBodySchema(BaseModel):
    command: list[str]

    @field_validator("command")
    @classmethod
    def validate_cmd(cls, cmd) -> list[str]:
        return command_validator(cmd)
`

func lowerPythonFiles(t *testing.T, files map[string]string) (usg.Store, []usg.Node) {
	t.Helper()
	dir := t.TempDir()
	paths := make([]string, 0, len(files))
	for name, src := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		paths = append(paths, p)
	}
	prog, err := treesitter.ExtractPython(paths, dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	nodes, _ := g.AllNodes()
	return g, nodes
}

// TestLowerParameterMemberDominatesEndpointSink pins the gap itself: the validation a
// framework applies while building a handler's arguments must be a call in the handler's
// own graph, ahead of its sinks, so a control anchored on it dominates the endpoint's
// sink. Before the member event existed the validator lived only in the schema class's
// function — a different function's region — and solvers.Dominates (intraprocedural by
// construction) could never credit it.
func TestLowerParameterMemberDominatesEndpointSink(t *testing.T) {
	g, nodes := lowerPythonFiles(t, map[string]string{
		"command_api.py":                    parameterMemberAPI,
		"shared/schemas/command_schemas.py": parameterMemberSchema,
	})
	var event, sink, param string
	for _, n := range nodes {
		switch {
		case n.Prop("callee_path") == "analysis.parameter.member":
			event = n.ID
			for _, want := range []string{
				"function_name:run",
				"param_name:body",
				"param_type:RunCommandRequestBodySchema",
				"member_name:validate_cmd",
				"decorator_method:field_validator",
			} {
				if !strings.Contains(n.Prop("str_args"), want) {
					t.Fatalf("member event missing %q: %q", want, n.Prop("str_args"))
				}
			}
		case n.Prop("callee_path") == "python_on_whales.utils.run":
			sink = n.ID
		case n.Type == "code.Param" && n.Prop("name") == "body":
			param = n.ID
		}
	}
	if event == "" || sink == "" || param == "" {
		t.Fatalf("event=%q sink=%q param=%q", event, sink, param)
	}
	if !solvers.Dominates(g, event, sink) {
		t.Fatalf("member event %s does not dominate endpoint sink %s", event, sink)
	}
	// the event also flows to the parameter it validates, so a source labelled on the
	// member's evidence reaches the argument the endpoint actually reads.
	outs, _ := g.OutEdges(event, "FLOWS")
	for _, e := range outs {
		if e.Dst == param {
			return
		}
	}
	t.Fatalf("member event does not flow to the parameter")
}

// TestLowerParameterMemberNeedsFrameworkEntry pins the boundary: an argument nothing
// external populates is not one a framework built, so an ordinary function naming a
// validating class as a parameter type mints no member event — the event is evidence a
// framework stands between a caller and the body, not a fact about the type alone.
func TestLowerParameterMemberNeedsFrameworkEntry(t *testing.T) {
	_, nodes := lowerPythonFiles(t, map[string]string{
		"plain_caller.py": `from shared.schemas.command_schemas import RunCommandRequestBodySchema


def assemble(body: RunCommandRequestBodySchema) -> str:
    return body.command
`,
		"shared/schemas/command_schemas.py": parameterMemberSchema,
	})
	for _, n := range nodes {
		if n.Prop("callee_path") == "analysis.parameter.member" {
			t.Fatalf("member event minted without framework-built arguments: %q", n.Prop("str_args"))
		}
	}
}
