#!/bin/sh
# Fetch the pinned free definitions tarball from dl.vyprsec.ai and unpack it
# so DEST is a vyql/ data root (ontology/concepts, packs, taxonomy).
#
#   scripts/fetch-free-definitions.sh DEST
#
# Reads packaging/definitions-free.url: URL, then sha256 or "pending".
# "pending" verifies against the CDN sibling .sha256. A 64-hex pin must match
# the archive, so a tagged engine keeps the definitions it was built with.
set -eu

die() { printf 'fetch-free-definitions: %s\n' "$*" >&2; exit 1; }

dest="${1:-}"
[ -n "$dest" ] || die "usage: $0 DEST"

root="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
pin="$root/packaging/definitions-free.url"
[ -f "$pin" ] || die "missing $pin"

url=""
want=""
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

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }
need curl
need tar

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
cd "$tmp"

archive="${url##*/}"
[ -n "$archive" ] || archive="definitions.tar.gz"
curl -fsSL -o "$archive" "$url" || die "download failed: $url"

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
		[ "${#want}" -eq 64 ] || die "pin sha256 must be 64 hex digits or 'pending'"
		[ "$got" = "$want" ] || die "checksum mismatch: got $got want $want (bump packaging/definitions-free.url)"
		;;
	*) die "pin sha256 must be 64 hex digits or 'pending'; got $want" ;;
esac

mkdir -p extracted
tar -xzf "$archive" -C extracted

# The archive may be the data root itself, or a single top-level directory
# (often named vyql) that is the data root.
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
# Copy contents into dest so dest IS the data root, matching stage/.../vyql.
tar -C "$data" -cf - . | tar -C "$dest" -xf -
[ -d "$dest/ontology/concepts" ] || die "unpack did not produce $dest/ontology/concepts"
