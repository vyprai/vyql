#!/usr/bin/env bash
# Materialise every benchmark corpus into a persistent directory OUTSIDE this
# repository, and expose it at the paths the benchmark commands document.
#
#   ./benchmarks/fetch-corpora.sh          # fetch anything missing, update nothing
#   ./benchmarks/fetch-corpora.sh --update # also git-pull each corpus already present
#
# The corpora live outside the repo on purpose. BenchmarkJava and BenchmarkPython
# are GPL and must never be vendored here; the rest are simply large and belong to
# other projects. Cloning them takes minutes and the RealVuln repo set is 66
# separate clones, so this script is idempotent: everything already fetched is
# left alone unless --update is passed.
#
# /tmp/bench is kept as a symlink farm pointing at the persistent copy, because
# that is the BENCH_DIR path in CLAUDE.md and benchmarks/RESULTS.md. /tmp is
# cleared on reboot; re-running this script restores the links without refetching.
set -euo pipefail

CORPORA="${VYQL_BENCH_CORPORA:-$HOME/workspace/vypr/benchmark-corpora}"
LINKS="${VYQL_BENCH_LINKS:-/tmp/bench}"
UPDATE=0
[ "${1:-}" = "--update" ] && UPDATE=1

mkdir -p "$CORPORA" "$LINKS"

clone() { # $1=dir-name  $2=url
  local dest="$CORPORA/$1"
  if [ -d "$dest/.git" ]; then
    if [ "$UPDATE" = 1 ]; then
      echo "== updating $1"
      git -C "$dest" pull --ff-only --quiet || echo "   (pull skipped: $1)"
    else
      echo "== $1 present"
    fi
  else
    echo "== cloning $1"
    git clone --depth 1 --quiet "$2" "$dest"
  fi
  ln -sfn "$dest" "$LINKS/$1"
}

clone BenchmarkJava      https://github.com/OWASP-Benchmark/BenchmarkJava.git
clone BenchmarkPython    https://github.com/OWASP-Benchmark/BenchmarkPython.git
clone ports              https://github.com/vyprai/vypr-owasp-ports.git
clone Real-Vuln-Benchmark https://github.com/kolega-ai/Real-Vuln-Benchmark.git

# RealVuln ships ground truth only; the code it scores is 66 further clones that
# its own script fetches into repos/ (~1 GB, several minutes on a cold run).
RV="$CORPORA/Real-Vuln-Benchmark"
want=$(find "$RV/ground-truth" -maxdepth 1 -mindepth 1 -type d | wc -l | tr -d ' ')
have=$(find "$RV/repos" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
if [ "$have" -lt "$want" ]; then
  echo "== fetching RealVuln target repos ($have/$want present)"
  (cd "$RV" && python3 clone_repos.py)
else
  echo "== RealVuln target repos present ($have/$want)"
fi

echo
echo "corpora: $CORPORA"
echo "linked at: $LINKS"
