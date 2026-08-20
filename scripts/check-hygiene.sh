#!/usr/bin/env bash
# Publication hygiene gate. Every check here corresponds to a defect that was
# actually found while opening this repository up, and exists so that defect
# cannot come back quietly. Each one prints what it found before failing.
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0

# This script is excluded from its own scans: the patterns it searches for are
# necessarily present in it.
report() { # $1=label, rest=matches
  echo "FAIL: $1"
  printf '%s\n' "$2" | head -20 | sed 's/^/    /'
  fail=1
}

echo "== no emoji =="
# Typographic arrows are not emoji and are used deliberately in trace output.
hits="$(grep -rIP '[\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}\x{2B00}-\x{2BFF}\x{FE0F}]' . \
  --exclude-dir=.git --exclude-dir=bin --exclude=check-hygiene.sh 2>/dev/null || true)"
[ -n "$hits" ] && report "emoji found" "$hits"

echo "== no absolute personal paths =="
hits="$(grep -rInE '/(Users|home)/[a-zA-Z0-9_.-]+/' . \
  --exclude-dir=.git --exclude-dir=bin --exclude=check-hygiene.sh 2>/dev/null || true)"
[ -n "$hits" ] && report "absolute personal filesystem path" "$hits"

echo "== no references to unpublished content =="
# cve-1000 is exempt inside the coverage gate that reads it: those are functional
# paths in a test that skips when the corpus is absent, not citations a reader
# would try to follow.
hits="$(grep -rInE '(^|[^a-zA-Z])(plan/|poc/|design/|nomad\.md)' . \
  --exclude-dir=.git --exclude-dir=bin --exclude=check-hygiene.sh 2>/dev/null \
  | grep -v 'designDir' || true)"
[ -n "$hits" ] && report "reference to content not in this repository" "$hits"

echo "== no internal module path =="
hits="$(grep -rIn 'github.com/vypr/vyql' . --exclude-dir=.git --exclude-dir=bin --exclude=check-hygiene.sh 2>/dev/null || true)"
[ -n "$hits" ] && report "github.com/vypr/vyql is a different account; use github.com/vyprai/vyql" "$hits"

echo "== the data directory is not ignored =="
# A gitignore pattern without a trailing slash matches directories too, so a
# root-level `vyql` entry would silently drop a checked-in knowledge tree when
# one is present. CI fetches definitions into ./vyql when the tree is absent.
for p in vyql/README.md vyql/ontology/concepts vyql/bindings; do
  if git check-ignore -q --no-index "$p" 2>/dev/null; then
    report "gitignore excludes the runtime data directory ($p)" "$(git check-ignore -v --no-index "$p")"
  fi
done

echo "== no build artifacts committed =="
# `go build -o vyql` from the root writes vyql/vyql, because vyql/ is a directory.
# It is 70 MB and it is not source. More generally, nothing large and executable
# belongs in a source tree.
stray="$(git ls-files -z | xargs -0 -n 200 ls -l 2>/dev/null \
  | awk '$1 ~ /^-rwx/ && $5 > 1048576 {print $NF}' || true)"
if [ -n "$stray" ]; then
  report "executable larger than 1 MB is tracked" "$stray"
fi

echo "== grammar licenses present =="
for d in internal/extract/frontend/treesitter/grammars/*/; do
  [ -s "$d/LICENSE" ] || { echo "FAIL: missing license for $(basename "$d")"; fail=1; }
done

echo "== legal files present =="
for f in LICENSE NOTICE THIRD_PARTY_NOTICES.md vyql/taxonomy/ATTRIBUTION.md; do
  [ -s "$f" ] || { echo "FAIL: missing $f"; fail=1; }
done

echo "== third-party notices current =="
if command -v go-licenses >/dev/null 2>&1; then
  before="$(cat THIRD_PARTY_NOTICES.md)"
  ./scripts/gen-third-party-notices.sh >/dev/null 2>&1 || true
  if [ "$before" != "$(cat THIRD_PARTY_NOTICES.md)" ]; then
    printf '%s' "$before" > THIRD_PARTY_NOTICES.md
    echo "FAIL: THIRD_PARTY_NOTICES.md is stale -- run scripts/gen-third-party-notices.sh"
    fail=1
  fi
else
  echo "  (skipped: go-licenses not installed)"
fi

[ "$fail" -eq 0 ] && echo "hygiene OK"
exit "$fail"
