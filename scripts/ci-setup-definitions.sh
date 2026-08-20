#!/bin/sh
# Fetch free definitions with tests into a temp data root for CI, and move any
# in-repo vyql/ tree out of the way so Lookup cannot find it.
#
#   eval "$(scripts/ci-setup-definitions.sh)"
#
# Sets:
#   VYQL_DEFINITIONS  absolute path to the fetched data root (use with -data)
#   VYQL_HOME         same path, for `go test` which has no -data flag
#
# Writes both to $GITHUB_ENV when that file exists.
set -eu

root="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
dest="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/vyql-definitions"

chmod +x "$root/scripts/fetch-free-definitions.sh"
"$root/scripts/fetch-free-definitions.sh" --with-tests "$dest"

# An in-repo vyql/ would win searchUp from package directories under the module.
# CI must not depend on that tree: it goes away when definitions leave this repo.
if [ -e "$root/vyql" ] || [ -L "$root/vyql" ]; then
	aside="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/vyql-checked-in-tree"
	rm -rf "$aside"
	mv "$root/vyql" "$aside"
fi

printf 'export VYQL_DEFINITIONS=%s\n' "$dest"
printf 'export VYQL_HOME=%s\n' "$dest"

if [ -n "${GITHUB_ENV:-}" ]; then
	{
		echo "VYQL_DEFINITIONS=$dest"
		echo "VYQL_HOME=$dest"
	} >> "$GITHUB_ENV"
fi
