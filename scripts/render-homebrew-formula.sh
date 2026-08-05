#!/bin/sh
# Render the Homebrew formula for a published release.
#
#   scripts/render-homebrew-formula.sh v0.2.1 > Formula/vyql.rb
#
# The checksums come from the .sha256 files published beside each archive, so
# the formula pins what was actually released rather than what a local build
# happens to produce.
#
# The formula in the tap is generated, not hand-maintained: edit
# packaging/homebrew/vyql.rb.tmpl and the next release carries the change.
set -eu

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "usage: $0 <version, e.g. v0.2.1>" >&2; exit 2; }
case "$VERSION" in
    v*) ;;
    *) VERSION="v${VERSION}" ;;
esac
BARE="${VERSION#v}"

REPO="${VYQL_REPO:-vyprai/vyql}"
BASE="https://github.com/${REPO}/releases/download/${VERSION}"
TMPL="$(dirname "$0")/../packaging/homebrew/vyql.rb.tmpl"
[ -f "$TMPL" ] || { echo "missing template: $TMPL" >&2; exit 1; }

# A .sha256 file names the archive after the digest, so take the first field.
# An empty digest would render a formula that fails to install with a checksum
# mismatch, which is a far more confusing failure than stopping here.
digest() {
    # Retry on HTTP errors too: run straight after a release is published, the
    # assets can 404 for a few seconds before they are servable.
    out="$(curl -fsSL --retry 6 --retry-delay 5 --retry-all-errors \
        "${BASE}/vyql_${VERSION}_$1.tar.gz.sha256")" \
        || { echo "no checksum published for $1 at ${VERSION}" >&2; exit 1; }
    d="$(printf '%s' "$out" | awk 'NR==1 {print $1}')"
    case "$d" in
        ????????????????????????????????????????????????????????????????) ;;
        *) echo "checksum for $1 is not a sha256 digest: '$d'" >&2; exit 1 ;;
    esac
    printf '%s' "$d"
}

sed \
    -e "s|@@VERSION@@|${BARE}|g" \
    -e "s|@@SHA256_DARWIN_ARM64@@|$(digest darwin_arm64)|g" \
    -e "s|@@SHA256_DARWIN_AMD64@@|$(digest darwin_amd64)|g" \
    -e "s|@@SHA256_LINUX_ARM64@@|$(digest linux_arm64)|g" \
    -e "s|@@SHA256_LINUX_AMD64@@|$(digest linux_amd64)|g" \
    "$TMPL"
