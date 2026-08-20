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

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }
need curl
need tar
need python3

root="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"

url=""
want=""

if [ "$with_tests" = true ]; then
	# Prefer the GCS origin for CI. The CDN front (dl.vyprsec.ai) can keep a
	# cached 404 for an hour after a new with-tests object is published.
	manifest_cdn="https://dl.vyprsec.ai/vyql/definitions/free/with-tests/latest.json"
	manifest_gcs="https://storage.googleapis.com/dl.vyprsec.ai/vyql/definitions/free/with-tests/latest.json"
	json=""
	if ! json="$(curl -fsSL "$manifest_cdn")"; then
		json="$(curl -fsSL "$manifest_gcs")" || die "fetch $manifest_cdn (and GCS fallback $manifest_gcs)"
	fi
	url="$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["url"])')"
	want="$(printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256"])')"
	case "$url" in
		https://dl.vyprsec.ai/*) ;;
		*) die "manifest url must be https://dl.vyprsec.ai/...; got $url" ;;
	esac
	# Download the archive from GCS when the CDN path fails (same object).
	url_gcs="https://storage.googleapis.com/dl.vyprsec.ai/${url#https://dl.vyprsec.ai/}"
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
if ! curl -fsSL -o "$archive" "$url"; then
	if [ "$with_tests" = true ] && [ -n "${url_gcs:-}" ]; then
		curl -fsSL -o "$archive" "$url_gcs" || die "download failed: $url and $url_gcs"
	else
		die "download failed: $url"
	fi
fi

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
		curl -fsSL -o "$archive.sha256" "${url}.sha256" \
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
if find_root "$tmp/extracted"; then
	data="$tmp/extracted"
else
	set -- "$tmp/extracted"/*
	if [ "$#" -eq 1 ] && [ -d "$1" ] && find_root "$1"; then
		data="$1"
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
