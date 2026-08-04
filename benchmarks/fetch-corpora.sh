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

clone() { # $1=dir-name  $2=url  [$3=optional]
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
    if ! git clone --depth 1 --quiet "$2" "$dest" 2>/dev/null; then
      if [ "${3:-}" = "optional" ]; then
        echo "   (skipped: $2 is not reachable -- the suites below do not need it)"
        return 0
      fi
      echo "error: could not clone $2" >&2
      return 1
    fi
  fi
  ln -sfn "$dest" "$LINKS/$1"
}

# The two protected public suites. Everything the README and CONTRIBUTING ask you
# to reproduce needs only these.
clone BenchmarkJava      https://github.com/OWASP-Benchmark/BenchmarkJava.git
clone BenchmarkPython    https://github.com/OWASP-Benchmark/BenchmarkPython.git

# The synthetic language ports are first-party and the repository is not public,
# so this is expected to skip for most people. Their scores are recorded in
# RESULTS.md and are NOT comparable to the public suites above.
clone ports              https://github.com/vyprai/vypr-owasp-ports.git optional

clone Real-Vuln-Benchmark https://github.com/kolega-ai/Real-Vuln-Benchmark.git optional

# RealVuln ships ground truth only; the code it scores is 66 further clones its
# own script fetches into repos/ -- roughly 1 GB and several minutes. That is a
# lot to spend on a corpus you may not want, so it is opt-in.
RV="$CORPORA/Real-Vuln-Benchmark"
if [ ! -d "$RV/ground-truth" ]; then
  :
elif [ "${VYQL_FETCH_REALVULN:-0}" != "1" ]; then
  echo "== RealVuln target repos skipped (set VYQL_FETCH_REALVULN=1 to fetch ~1 GB)"
else
  want=$(find "$RV/ground-truth" -maxdepth 1 -mindepth 1 -type d | wc -l | tr -d ' ')
  have=$(find "$RV/repos" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
  if [ "$have" -lt "$want" ]; then
    echo "== fetching RealVuln target repos ($have/$want present)"
    (cd "$RV" && python3 clone_repos.py)
  else
    echo "== RealVuln target repos present ($have/$want)"
  fi
fi

echo
echo "corpora: $CORPORA"
echo "linked at: $LINKS"
