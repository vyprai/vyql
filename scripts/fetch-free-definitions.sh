#!/bin/sh
# Fetch the free definitions tarball from dl.vyprsec.ai and unpack it
# so DEST is a vyql/ data root (ontology/concepts, packs, taxonomy).
#
#   scripts/fetch-free-definitions.sh [--with-tests] DEST
#
# Without --with-tests, reads packaging/definitions-free.url: URL, then sha256
# or "pending". "pending" verifies against the CDN sibling .sha256. A 64-hex pin
# must match the archive, so a tagged engine keeps the definitions it was built with.
#
# With --with-tests, reads vyql/definitions/free/with-tests/latest.json and
# unpacks the bundle that includes vyql/tests/ for CI.
#
# All downloads use https://dl.vyprsec.ai only.
set -eu

die() { printf 'fetch-free-definitions: %s\n' "$*" >&2; exit 1; }

with_tests=false
while [ $# -gt 0 ]; do
	case "$1" in
		--with-tests)
			with_tests=true
			shift
			;;
		--)
			shift
			break
			;;
		-*)
			die "unknown option $1"
			;;
		*)
			break
			;;
	esac
done

dest="${1:-}"
[ -n "$dest" ] || die "usage: $0 [--with-tests] DEST"

# Resolved here, before anything changes directory. Unpacking happens from a
# temporary working directory, so a relative DEST would be written there and
# deleted with it: the caller gets no data directory, and the post-condition
# below passes because it is relative to the same wrong place. Callers do pass
# relative paths -- `make fetch-definitions` and the release archive both do.
case "$dest" in
	/*) ;;
	*) dest="$(pwd)/$dest" ;;
esac

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }
need curl
need tar
need python3

root="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"

url=""
want=""

# curl_cdn retries when the CDN still serves a stale miss after a publish.
curl_cdn() {
	# usage: curl_cdn -o FILE URL   or   curl_cdn URL  (stdout)
	_attempt=1
	_max=6
	while :; do
		if curl -fsSL -H 'Cache-Control: no-cache' "$@"; then
			return 0
		fi
		if [ "$_attempt" -ge "$_max" ]; then
			return 1
		fi
		sleep $((_attempt * 2))
		_attempt=$((_attempt + 1))
	done
}

if [ "$with_tests" = true ]; then
	manifest="https://dl.vyprsec.ai/vyql/definitions/free/with-tests/latest.json"
	json="$(curl_cdn "$manifest")" || die "fetch $manifest"
	url="$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["url"])')"
	want="$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256"])')"
	case "$url" in
		https://dl.vyprsec.ai/*) ;;
		*) die "manifest url must be https://dl.vyprsec.ai/...; got $url" ;;
	esac
else
	pin="$root/packaging/definitions-free.url"
	[ -f "$pin" ] || die "missing $pin"
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
			\#*|"") continue ;;
		esac
		if [ -z "$url" ]; then
			url="$line"
			continue
		fi
		if [ -z "$want" ]; then
			want="$line"
			continue
		fi
	done < "$pin"
	[ -n "$url" ] || die "$pin has no URL"
	case "$url" in
		https://dl.vyprsec.ai/*) ;;
		*) die "pin URL must be https://dl.vyprsec.ai/...; got $url" ;;
	esac
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
cd "$tmp"

archive="${url##*/}"
[ -n "$archive" ] || archive="definitions.tar.gz"
curl_cdn -o "$archive" "$url" || die "download failed: $url"

got=""
if command -v sha256sum >/dev/null 2>&1; then
	got="$(sha256sum "$archive" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
	got="$(shasum -a 256 "$archive" | awk '{print $1}')"
else
	die "neither sha256sum nor shasum found"
fi

case "$want" in
	pending)
		curl_cdn -o "$archive.sha256" "${url}.sha256" \
			|| die "no ${url}.sha256 (set a sha256 pin in packaging/definitions-free.url)"
		if command -v sha256sum >/dev/null 2>&1; then
			sha256sum -c "$archive.sha256"
		else
			shasum -a 256 -c "$archive.sha256"
		fi >/dev/null || die "checksum mismatch against ${url}.sha256"
		;;
	[a-fA-F0-9]*)
		[ "${#want}" -eq 64 ] || die "sha256 must be 64 hex digits or 'pending'"
		[ "$got" = "$want" ] || die "checksum mismatch: got $got want $want"
		;;
	*) die "sha256 must be 64 hex digits or 'pending'; got $want" ;;
esac

mkdir -p extracted
tar -xzf "$archive" -C extracted

find_root() {
	if [ -d "$1/ontology/concepts" ] && [ -d "$1/packs" ] && [ -d "$1/taxonomy" ]; then
		printf '%s' "$1"
		return 0
	fi
	return 1
}

data=""
if data_cand="$(find_root "$tmp/extracted")"; then
	data="$data_cand"
else
	set -- "$tmp/extracted"/*
	if [ "$#" -eq 1 ] && [ -d "$1" ] && data_cand="$(find_root "$1")"; then
		data="$data_cand"
	fi
fi
[ -n "$data" ] || die "archive did not contain ontology/concepts, packs and taxonomy"

mkdir -p "$dest"
rm -rf "$dest"
mkdir -p "$dest"
tar -C "$data" -cf - . | tar -C "$dest" -xf -
[ -d "$dest/ontology/concepts" ] || die "unpack did not produce $dest/ontology/concepts"

if [ "$with_tests" = true ]; then
	[ -d "$dest/tests" ] || die "with-tests bundle did not contain tests/"
fi
