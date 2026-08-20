#!/usr/bin/env bash
# Pack the vyql/ data root into a definitions tarball for CDN publish.
#
#   scripts/pack-definitions.sh --version X.Y.Z --channel free|commercial --out DIR \
#       [--url URL] [--include-tests]
#
# Channel comes from the publish tag (definitions/vX.Y.Z[-free]), not from filtering
# files here. Free tags belong on the definitions/free branch; commercial tags on main.
#
# Semver bump guidance:
#   patch — content fix within the channel
#   minor — new detections on this channel
#   major — breaking data-layout change, or (commercial) new paid-tier content
#
# By default the customer runtime bundle omits vyql/tests/ (corpus specs are not
# required to scan). Pass --include-tests for the CI / benchmarks pack that public
# and private test jobs consume. The archive is a data root (ontology/, packs/,
# taxonomy/, …) so consumers can unpack it directly into a VYQL_HOME tree.
set -euo pipefail

die() { printf 'pack-definitions: %s\n' "$*" >&2; exit 1; }

version=""
channel=""
out=""
url=""
include_tests=0

while [ $# -gt 0 ]; do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    --channel) channel="${2:-}"; shift 2 ;;
    --out) out="${2:-}"; shift 2 ;;
    --url) url="${2:-}"; shift 2 ;;
    --include-tests) include_tests=1; shift ;;
    -h|--help)
      printf 'usage: %s --version X.Y.Z --channel free|commercial --out DIR [--url URL] [--include-tests]\n' "$0"
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$version" ] || die "--version is required"
[ -n "$channel" ] || die "--channel is required"
[ -n "$out" ] || die "--out is required"

case "$version" in
  [0-9]*.[0-9]*.[0-9]*)
    # Reject four-part numbers and prerelease suffixes in the public contract.
    case "$version" in
      *.*.*.*|*-*)
        die "version must be bare X.Y.Z (got $version)"
        ;;
    esac
    ;;
  *) die "version must be semver X.Y.Z (got $version)" ;;
esac

case "$channel" in
  free|commercial) ;;
  *) die "--channel must be free or commercial (got $channel)" ;;
esac

if [ -z "$url" ]; then
  case "$channel-$include_tests" in
    free-0) url="https://dl.vyprsec.ai/vyql/definitions/free/latest.tar.gz" ;;
    free-1) url="https://dl.vyprsec.ai/vyql/definitions/free/with-tests/latest.tar.gz" ;;
    commercial-0) url="gs://vypr-vyql-definitions-commercial/latest.tar.gz" ;;
    commercial-1) url="gs://vypr-vyql-definitions-commercial/with-tests/latest.tar.gz" ;;
  esac
fi

root="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
src="$root/vyql"
[ -d "$src/ontology/concepts" ] || die "missing $src/ontology/concepts"
[ -d "$src/packs" ] || die "missing $src/packs"
[ -d "$src/taxonomy" ] || die "missing $src/taxonomy"
if [ "$include_tests" -eq 1 ]; then
  [ -d "$src/tests" ] || die "missing $src/tests"
fi

mkdir -p "$out"
stage="$(mktemp -d "${TMPDIR:-/tmp}/pack-definitions.XXXXXX")"
trap 'rm -rf "$stage"' EXIT INT TERM

# Copy the data root. Runtime packs drop tests; CI packs keep them.
if command -v rsync >/dev/null 2>&1; then
  if [ "$include_tests" -eq 1 ]; then
    rsync -a --exclude README.md "$src/" "$stage/"
  else
    rsync -a --exclude tests --exclude README.md "$src/" "$stage/"
  fi
else
  if [ "$include_tests" -eq 1 ]; then
    tar -C "$src" -cf - --exclude README.md . | tar -C "$stage" -xf -
  else
    tar -C "$src" -cf - --exclude tests --exclude README.md . | tar -C "$stage" -xf -
  fi
fi

[ -d "$stage/ontology/concepts" ] || die "stage missing ontology/concepts"
[ -d "$stage/packs" ] || die "stage missing packs"
[ -d "$stage/taxonomy" ] || die "stage missing taxonomy"
if [ "$include_tests" -eq 1 ]; then
  [ -d "$stage/tests" ] || die "stage missing tests"
else
  [ ! -d "$stage/tests" ] || die "tests must not be in the runtime bundle"
fi

# Self-describing install: vyql update reads this without a side cache.
python3 - "$stage/definitions.meta.json" "$version" "$channel" "$include_tests" <<'PY'
import json, sys
path, version, channel, include_tests = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(path, "w", encoding="utf-8") as f:
    json.dump(
        {
            "version": version,
            "channel": channel,
            "tests": include_tests == "1",
        },
        f,
        indent=2,
    )
    f.write("\n")
PY
printf '%s\n' "$version" > "$stage/VERSION"

archive="$out/definitions.tar.gz"
tar -C "$stage" -czf "$archive" .

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$out" && sha256sum definitions.tar.gz > definitions.tar.gz.sha256)
  sha="$(awk '{print $1}' "$out/definitions.tar.gz.sha256")"
elif command -v shasum >/dev/null 2>&1; then
  (cd "$out" && shasum -a 256 definitions.tar.gz > definitions.tar.gz.sha256)
  sha="$(awk '{print $1}' "$out/definitions.tar.gz.sha256")"
else
  die "neither sha256sum nor shasum found"
fi

python3 - "$out/latest.json" "$version" "$channel" "$sha" "$url" "$include_tests" <<'PY'
import json, sys
path, version, channel, sha, url, include_tests = sys.argv[1:7]
with open(path, "w", encoding="utf-8") as f:
    json.dump(
        {
            "version": version,
            "channel": channel,
            "tests": include_tests == "1",
            "sha256": sha,
            "url": url,
        },
        f,
        indent=2,
    )
    f.write("\n")
PY

variant="runtime"
[ "$include_tests" -eq 1 ] && variant="with-tests"
printf 'pack-definitions: wrote %s (%s %s %s sha256=%s)\n' \
  "$archive" "$channel" "$version" "$variant" "$sha"
