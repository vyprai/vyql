#!/usr/bin/env bash
# Regenerate the vendored tree-sitter grammars that ship no usable Go bindings.
#
# Most language grammars provide a bindings/go package with a committed parser.c,
# and are used directly (see go.mod). A few do NOT:
#   - PowerShell (airbus-cert): ships a committed parser.c + scanner.c but no Go
#     binding → we VENDOR src/* and wrap it (grammars/powershell).
#   - Swift (alex-pinkus): ships a Go binding but NO committed parser.c → we run
#     `tree-sitter generate` on its grammar.js, then vendor + wrap (grammars/swift).
#   - (Perl, Solidity, Objective-C follow the same generate-or-vendor pattern.)
#
# The generated/vendored parser.c is COMMITTED so `go build` needs no CLI. Run this
# only to refresh a grammar. Requires: go, npx, the tree-sitter CLI
# (`npm i -g tree-sitter-cli`).
#
# Usage:  go/scripts/vendor-grammars.sh [powershell|swift|perl|solidity|all]
set -euo pipefail
cd "$(dirname "$0")/.."                      # go/
GRAMMARS="extract/frontend/treesitter/grammars"
MC="$(go env GOMODCACHE)"
TS="${TS:-tree-sitter}"                       # override with TS=/path/to/tree-sitter

modver() { ls -d "$MC/$1"@* 2>/dev/null | sort -V | tail -1; }

# copy_license brings the upstream LICENSE along with the sources. Redistributing
# these grammars requires it, and a refresh that silently dropped it would put the
# release out of compliance — so a miss is a loud warning, not a silent skip.
copy_license() { # $1=module  $2=dest-pkg
  local d f; d="$(modver "$1")"
  if [ -n "$d" ]; then
    for f in LICENSE LICENSE.md LICENSE.txt LICENCE COPYING; do
      if [ -f "$d/$f" ]; then
        cp "$d/$f" "$GRAMMARS/$2/LICENSE"
        chmod u+w "$GRAMMARS/$2/LICENSE"
        return 0
      fi
    done
  fi
  echo "WARNING: no upstream license found for $2 — fetch it by hand before releasing" >&2
  return 1
}

vendor_committed() { # $1=module  $2=dest-pkg  $3=lang
  local d; d="$(modver "$1")"
  mkdir -p "$GRAMMARS/$2/tree_sitter"
  cp "$d/src/parser.c" "$d/src/scanner.c" "$GRAMMARS/$2/" 2>/dev/null || \
     cp "$d/src/parser.c" "$GRAMMARS/$2/"
  cp "$d/src/tree_sitter/"*.h "$GRAMMARS/$2/tree_sitter/"
  chmod -R u+w "$GRAMMARS/$2"
  copy_license "$1" "$2" || true
  echo "vendored $3 from committed parser.c ($1)"
}

vendor_generated() { # $1=module  $2=dest-pkg  $3=lang
  local d t; d="$(modver "$1")"; t="$(mktemp -d)"
  # grammar.js may require ./lib helpers (e.g. perl); copy them too.
  cp -R "$d/grammar.js" "$d/tree-sitter.json" "$d/src" "$t/" 2>/dev/null || true
  [ -d "$d/lib" ] && cp -R "$d/lib" "$t/"
  chmod -R u+w "$t"
  ( cd "$t" && "$TS" generate >/dev/null )
  mkdir -p "$GRAMMARS/$2/tree_sitter"
  cp "$t/src/parser.c" "$GRAMMARS/$2/"
  cp "$t/src/scanner.c" "$GRAMMARS/$2/" 2>/dev/null || true
  cp "$t/src/"*.h "$GRAMMARS/$2/" 2>/dev/null || true   # custom scanner headers (tsp_*.h, bsearch.h)
  cp "$t/src/tree_sitter/"*.h "$GRAMMARS/$2/tree_sitter/"
  chmod -R u+w "$GRAMMARS/$2"; rm -rf "$t"
  copy_license "$1" "$2" || true
  echo "generated + vendored $3 ($1)"
}

vendor_curl() { # $1=grammar.js-raw-url  $2=dest-pkg  $3=lang  (for grammars with no Go module)
  local t; t="$(mktemp -d)"; mkdir -p "$t/src"
  curl -fsSL "$1" -o "$t/grammar.js"
  curl -fsSL "${1%grammar.js}src/scanner.c" -o "$t/src/scanner.c" 2>/dev/null || true
  [ -s "$t/src/scanner.c" ] || rm -f "$t/src/scanner.c"
  ( cd "$t" && "$TS" generate >/dev/null )
  mkdir -p "$GRAMMARS/$2/tree_sitter"
  cp "$t/src/parser.c" "$GRAMMARS/$2/"
  cp "$t/src/scanner.c" "$GRAMMARS/$2/" 2>/dev/null || true
  cp "$t/src/tree_sitter/"*.h "$GRAMMARS/$2/tree_sitter/"
  chmod -R u+w "$GRAMMARS/$2"; rm -rf "$t"
  echo "curl-fetched + generated + vendored $3 ($1)"
}

case "${1:-all}" in
  powershell) vendor_committed github.com/airbus-cert/tree-sitter-powershell powershell powershell ;;
  swift)      vendor_generated github.com/alex-pinkus/tree-sitter-swift swift swift ;;
  perl)       vendor_generated github.com/tree-sitter-perl/tree-sitter-perl perl perl ;;
  solidity)   vendor_curl https://raw.githubusercontent.com/JoranHonig/tree-sitter-solidity/master/grammar.js solidity solidity ;;
  all)        vendor_committed github.com/airbus-cert/tree-sitter-powershell powershell powershell
              vendor_generated github.com/alex-pinkus/tree-sitter-swift swift swift
              vendor_generated github.com/tree-sitter-perl/tree-sitter-perl perl perl ;;
  *) echo "unknown grammar: $1"; exit 1 ;;
esac
echo "done — rebuild with: go build ./..."
