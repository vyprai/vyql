#!/bin/sh
# Install VyQL.
#
#   curl -fsSL https://dl.vyprsec.ai/vyql/install.sh | sh
#
# This file is also served at that URL. A copy that drifts from this one is a
# copy that installs something nobody reviewed, so publishing it is a step in
# release automation rather than a manual upload.
#
# Environment:
#   VYQL_VERSION           release to install (default: the latest)
#   VYQL_INSTALL_DIR       where the release is unpacked (default: ~/.local/share/vyql)
#   VYQL_BIN_DIR           where the binary is linked  (default: ~/.local/bin)
#   VYQL_INSTALL_BASE_URL  mirror serving <base>/<version>/<asset>
#                          (default: the GitHub release downloads)
#
# POSIX sh on purpose: this runs before VyQL is installed, on whatever shell the
# machine has, and bashisms are how an installer breaks on the one platform
# nobody tested.
set -eu

REPO="vyprai/vyql"
INSTALL_DIR="${VYQL_INSTALL_DIR:-${HOME}/.local/share/vyql}"
BIN_DIR="${VYQL_BIN_DIR:-${HOME}/.local/bin}"

say() { printf '%s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"
}

detect_platform() {
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Linux)  goos=linux ;;
        Darwin) goos=darwin ;;
        MINGW*|MSYS*|CYGWIN*)
            die "VyQL does not publish Windows binaries. Use WSL, or run it in CI
     with the GitHub Action: https://github.com/marketplace/actions/vyql-security-scan" ;;
        *) die "unsupported operating system: $os (VyQL publishes Linux and macOS builds)" ;;
    esac
    case "$arch" in
        x86_64|amd64)  goarch=amd64 ;;
        arm64|aarch64) goarch=arm64 ;;
        *) die "unsupported architecture: $arch (VyQL publishes amd64 and arm64)" ;;
    esac
    printf '%s_%s' "$goos" "$goarch"
}

latest_version() {
    # The redirect from /releases/latest carries the tag, so this needs no API
    # token and does not count against the unauthenticated rate limit the way
    # the JSON endpoint does.
    url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
        "https://github.com/${REPO}/releases/latest" 2>/dev/null)" || return 1
    printf '%s' "${url##*/}"
}

verify_checksum() {
    # archive and its .sha256 must be in the current directory, because the
    # checksum file names the archive without a path.
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c "$1.sha256"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -c "$1.sha256"
    else
        die "neither sha256sum nor shasum found; cannot verify the download"
    fi
}

need curl
need tar

platform="$(detect_platform)"

version="${VYQL_VERSION:-}"
if [ -z "$version" ]; then
    version="$(latest_version)" || die "could not determine the latest release; set VYQL_VERSION"
    [ -n "$version" ] || die "could not determine the latest release; set VYQL_VERSION"
fi
case "$version" in
    v*) ;;
    *) version="v${version}" ;;
esac

name="vyql_${version}_${platform}"
# Release assets come from GitHub, which is where the checksums and build
# provenance live. VYQL_INSTALL_BASE_URL points the download at a mirror that
# serves the same "<base>/<version>/<asset>" layout.
base="${VYQL_INSTALL_BASE_URL:-https://github.com/${REPO}/releases/download}/${version}"

say "vyql ${version} for ${platform}"

tmp="$(mktemp -d)"
# Leaving a half-downloaded archive behind on failure is how a retry picks up a
# corrupt file and reports something baffling.
trap 'rm -rf "$tmp"' EXIT INT TERM
cd "$tmp"

say "  downloading"
curl -fsSLO "${base}/${name}.tar.gz" \
    || die "no release asset ${name}.tar.gz — check that ${version} exists and publishes ${platform}"
curl -fsSLO "${base}/${name}.tar.gz.sha256" \
    || die "no checksum for ${name}.tar.gz"

say "  verifying"
verify_checksum "${name}.tar.gz" >/dev/null \
    || die "checksum mismatch — the download is corrupt or has been tampered with; not installing"

say "  unpacking"
mkdir -p "$INSTALL_DIR"
# Replace any previous copy of this exact version rather than untarring over it,
# so a file removed upstream does not survive in the installed tree.
rm -rf "${INSTALL_DIR:?}/${name}"
tar -xzf "${name}.tar.gz" -C "$INSTALL_DIR"

[ -x "${INSTALL_DIR}/${name}/bin/vyql" ] || die "archive did not contain bin/vyql"
[ -d "${INSTALL_DIR}/${name}/vyql" ] || die "archive did not contain the vyql/ data directory"

mkdir -p "$BIN_DIR"
# A shim rather than a symlink. VyQL finds its data next to the binary, and
# releases up to v0.2.0 report the symlink's own path when asked where they are,
# so a symlinked binary searches the wrong directory and exits with
# "could not locate the data directory". `exec` on the real path is right for
# every release, before and after that is fixed.
cat > "${BIN_DIR}/vyql" <<SHIM
#!/bin/sh
exec "${INSTALL_DIR}/${name}/bin/vyql" "\$@"
SHIM
chmod +x "${BIN_DIR}/vyql"

# Run it the way it will actually be invoked. An install that unpacks but cannot
# start is worse than one that failed outright.
#
# Not piped into head: a pipeline reports the last command's status, so
# `vyql version | head -1` succeeds even when vyql panics.
if ! version_out="$("${BIN_DIR}/vyql" version 2>&1)"; then
    printf '%s\n' "$version_out" >&2
    die "installed, but ${BIN_DIR}/vyql failed to run"
fi
installed="$(printf '%s\n' "$version_out" | head -1)"
[ -n "$installed" ] || die "installed, but ${BIN_DIR}/vyql printed no version"

say ""
say "  ${installed}"
say "  command ${BIN_DIR}/vyql"
say "  data    ${INSTALL_DIR}/${name}/vyql"

case ":${PATH}:" in
    *":${BIN_DIR}:"*) ;;
    *)
        say ""
        say "  ${BIN_DIR} is not on your PATH. Add it:"
        say "    export PATH=\"${BIN_DIR}:\$PATH\""
        ;;
esac

say ""
say "  vyql scan .          scan the working directory"
say "  vyql explain .       why each finding fired"
