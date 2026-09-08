#!/usr/bin/env sh
# VEXOR installer — Linux, Debian/Ubuntu, Termux, macOS.
#
# One-line install:
#   sh -c "$(curl -fsSL https://raw.githubusercontent.com/0xamirdev/vexor/main/scripts/install.sh)"
#
# How it works:
#   1. Detects OS and CPU architecture, picks a prebuilt release binary.
#   2. Installs it into the first writable bin directory on PATH (or a
#      standard location it then appends to the user's shell profile).
#   3. Falls back to `go install` when no prebuilt binary matches and Go
#      is available.
#
# The script only touches user-writable locations. It never requires root,
# never hardcodes machine-specific paths, and never needs the repository.
set -eu

REPO_SLUG="github.com/0xamirdev/vexor"
BIN_NAME="vexor"
BASE="https://github.com/${REPO_SLUG}"

say()  { printf '\033[36m[+]\033[0m %s\n' "$1"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$1"; }
die()  { printf '\033[31m[-]\033[0m %s\n' "$1"; exit 1; }

# --------------------------------------------------------------- platform
OS="$(uname -s)"
ARCH="$(uname -m)"
case "${OS}" in
    Linux* | *Termux*) GOOS="linux" ;;
    Darwin*)           GOOS="darwin" ;;
    *) die "unsupported OS: ${OS}" ;;
esac
case "${ARCH}" in
    x86_64 | amd64)  GOARCH="amd64" ;;
    aarch64 | arm64) GOARCH="arm64" ;;
    *) die "unsupported architecture: ${ARCH}" ;;
esac
ASSET="vexor-${GOOS}-${GOARCH}"
say "platform: ${GOOS}/${GOARCH}"

# ------------------------------------------------------------- target dir
# First writable bin dir already on PATH wins; otherwise fall back to
# standard user locations the profile can pick up. TARGET_DIR overrides
# everything (used by CI and by power users).
TARGET="${TARGET_DIR:-}"
if [ -z "${TARGET}" ]; then
    for d in "${HOME}/.local/bin" /data/data/com.termux/files/usr/bin /usr/local/bin; do
        if [ -d "$d" ] && [ -w "$d" ] && case ":${PATH}:" in *":${d}:"*) true ;; *) false ;; esac; then
            TARGET="$d"; break
        fi
    done
fi
if [ -z "${TARGET}" ]; then
    for d in "${HOME}/.local/bin" /data/data/com.termux/files/usr/bin /usr/local/bin; do
        if { [ -d "$d" ] && [ -w "$d" ]; } || mkdir -p "$d" 2>/dev/null; then
            TARGET="$d"; break
        fi
    done
fi
[ -n "${TARGET}" ] || die "no writable install directory found; set TARGET_DIR and re-run."
say "install directory: ${TARGET}"

# --------------------------------------------------------------- fetch
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

fetch_prebuilt() {
    VER="$(curl -fsSL -H 'Accept: application/vnd.github+json' "${BASE}/releases/latest" -o "${TMP}/meta.json" &&
        sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${TMP}/meta.json" | head -n1)"
    [ -n "${VER}" ] || return 1
    say "latest release: ${VER}"
    curl -fL --progress-bar "${BASE}/releases/download/${VER}/${ASSET}" -o "${TMP}/${BIN_NAME}" || return 1
    chmod +x "${TMP}/${BIN_NAME}"
    # Sanity check: the asset must run on this machine.
    "${TMP}/${BIN_NAME}" --version > /dev/null 2>&1 || return 1
    mv "${TMP}/${BIN_NAME}" "${TARGET}/${BIN_NAME}"
}

fetch_via_go() {
    command -v go > /dev/null 2>&1 || return 1
    if [ -n "${VEXOR_BUILD_FROM_DIR:-}" ] && [ -d "${VEXOR_BUILD_FROM_DIR}" ]; then
        say "building from local source: ${VEXOR_BUILD_FROM_DIR}"
        # -o takes a full path: a bare name would land in the package
        # directory regardless of GOBIN.
        (cd "${VEXOR_BUILD_FROM_DIR}" && go build -o "${TARGET}/${BIN_NAME}" ./cmd/vexor) || return 1
    else
        say "installing via go install..."
        GOBIN="${TARGET}" go install "${REPO_SLUG}/cmd/vexor@latest" || return 1
    fi
}

install_via_pkg() {
    command -v pkg > /dev/null 2>&1 || return 1
    pkg install -y golang
    fetch_via_go
}

install_via_apt() {
    command -v apt > /dev/null 2>&1 || return 1
    apt update -qq && apt install -y golang-go
    fetch_via_go
}

say "downloading prebuilt binary..."
if ! fetch_prebuilt; then
    warn "prebuilt binary unavailable — falling back to source install."
    if ! fetch_via_go; then
        say "attempting to install a Go toolchain first..."
        if install_via_pkg || install_via_apt; then
            fetch_via_go || die "go install failed."
        else
            die "install Go >= 1.24 from https://go.dev/dl/ then re-run this script."
        fi
    fi
fi

# --------------------------------------------------------------- PATH fix
case ":${PATH}:" in
    *":${TARGET}:"*) ;;
    *)
        warn "${TARGET} is not on your PATH — adding it to your shell profile."
        # .profile covers sh/login shells; .bashrc covers interactive bash.
        # A fresh user has neither, so create .profile when missing.
        RC="${HOME}/.profile"
        [ -f "${RC}" ] || { : > "${RC}"; }
        if ! grep -qs "PATH=.*${TARGET}" "${RC}"; then
            printf '\n# added by the VEXOR installer\nexport PATH="$PATH:%s"\n' "${TARGET}" >> "${RC}"
            say "PATH updated. Open a new shell or run: export PATH=\"\$PATH:${TARGET}\""
        fi
        ;;
esac

# --------------------------------------------------------------- verify
if [ -x "${TARGET}/${BIN_NAME}" ]; then
    say "installed: ${TARGET}/${BIN_NAME}"
    "${TARGET}/${BIN_NAME}" --version
    say "works from anywhere:  cd /tmp && ${BIN_NAME} --version"
else
    die "installation could not be verified."
fi
