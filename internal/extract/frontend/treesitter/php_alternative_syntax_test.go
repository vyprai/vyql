package treesitter_test

import (
	"testing"
)

// PHP's alternative syntax writes a branch body as `:` … `endif;` instead of `{}`:
// `if ($rows = $stmt->fetchAll()):` … `endif;`, `foreach ($rows as $row):` …
// `endforeach;`, `while ($row = fetch()):` … `endwhile;`. Those bodies are colon_block
// nodes, so the branch flattener took them as brace-less single statements and dropped
// them: no node inside a colon_block was built, so nothing inside it was labelled, traced
// or reported. Every test here passes a parameter straight into a call inside the block,
// so the flow exists only if the statement inside the block was lowered at all.

func TestPHPAlternativeSyntaxIfBodyLowersStatements(t *testing.T) {
	g := phpLowerFile(t, "AltIf.php", `<?php
function dump($res) {
  if ($res):
    if_sink($res);
  endif;
  if ($res):
    then_sink($res);
  elseif ($res):
    elseif_sink($res);
  else:
    else_sink($res);
  endif;
}`)
	counts := countCalls(t, g)
	for _, sink := range []string{"if_sink", "then_sink", "elseif_sink", "else_sink"} {
		if counts[sink] != 1 {
			t.Fatalf("%s lowered %d times, want exactly 1: its statement is not inside the graph (%v)", sink, counts[sink], counts)
		}
		if !phpParamReachesCall(t, g, "$res", sink) {
			t.Fatalf("$res does not reach %s", sink)
		}
	}
}

func TestPHPAlternativeSyntaxLoopBodyLowersStatements(t *testing.T) {
	g := phpLowerFile(t, "AltLoop.php", `<?php
function dump($res) {
  while ($res):
    while_sink($res);
  endwhile;
  foreach (wrap($res) as $row):
    foreach_sink($row);
  endforeach;
}`)
	counts := countCalls(t, g)
	for _, sink := range []string{"while_sink", "foreach_sink", "wrap"} {
		if counts[sink] != 1 {
			t.Fatalf("%s lowered %d times, want exactly 1: its statement is not inside the graph (%v)", sink, counts[sink], counts)
		}
	}
	if !phpParamReachesCall(t, g, "$res", "while_sink") {
		t.Fatalf("$res does not reach while_sink")
	}
	if !phpParamReachesCall(t, g, "$res", "foreach_sink") {
		t.Fatalf("$res does not reach foreach_sink")
	}
}

// The shape templates actually write: the block is interleaved with the markup around it,
// so nothing marks the statements out as a body — they are just the PHP openings between
// the tags. This is the form the corpus's own `<?php if (isset($_GET['search'])) :?>`
// wrapper takes, and it was as invisible as any other colon_block.
func TestPHPAlternativeSyntaxBlockInTemplateLowersStatements(t *testing.T) {
	g := phpLowerFile(t, "section_online_users.tpl.php",
		`<input <?php if ($show): ?>value=<?php echo html_escape($row['name']); ?><?php endif; ?> ng-model="query">`)
	counts := countCalls(t, g)
	for _, sink := range []string{"html_escape"} {
		if counts[sink] != 1 {
			t.Fatalf("%s lowered %d times, want exactly 1: its statement is not inside the graph (%v)", sink, counts[sink], counts)
		}
	}
}
