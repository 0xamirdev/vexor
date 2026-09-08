#!/usr/bin/env sh
# VEXOR installer — Linux, Termux, macOS.
#
# Usage:
#   sh -c "$(curl -fsSL https://raw.githubusercontent.com/0xamirdev/vexor/main/scripts/install.sh)"
#
# Or from a clone:
#   ./scripts/install.sh
#
# The script never hardcodes an absolute source path: it installs through
# `go install`, which only needs Go and network access.
set -eu

REPO="github.com/0xamirdev/vexor"
CMD="${REPO}/cmd/vexor"

say() { printf '\033[36m[+]\033[0m %s\n' "$1"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$1"; }
die() { printf '\033[31m[-]\033[0m %s\n' "$1"; exit 1; }

# 1. Go toolchain ------------------------------------------------------
if ! command -v go > /dev/null 2>&1; then
    warn "Go is not installed."
    if command -v apt > /dev/null 2>&1; then
        say "installing golang via apt (Debian/Ubuntu/Termux proot)..."
        apt update -qq && apt install -y golang-go
    elif command -v pkg > /dev/null 2>&1; then
        say "installing golang via pkg (Termux)..."
        pkg install -y golang
    else
        die "please install Go >= 1.24 from https://go.dev/dl/ and re-run."
    fi
fi

GOVER=$(go env GOVERSION | tr -d 'go')
say "Go ${GOVER} found"

# 2. Install ------------------------------------------------------------
say "installing VEXOR via go install..."
go install "${CMD}@latest"

# 3. PATH hygiene -------------------------------------------------------
GOBIN_DIR="$(go env GOPATH)/bin"
case ":${PATH}:" in
    *":${GOBIN_DIR}:"*) ;;
    *)
        warn "${GOBIN_DIR} is not on your PATH."
        say "adding it to your shell profile..."
        for rc in "${HOME}/.profile" "${HOME}/.bashrc" "${HOME}/.zshrc"; do
            [ -f "$rc" ] || continue
            if ! grep -qs "GOPATH/bin" "$rc"; then
                printf '\nexport PATH="$PATH:%s"\n' "${GOBIN_DIR}" >> "$rc"
            fi
        done
        say "restart your shell or run: export PATH=\"\$PATH:${GOBIN_DIR}\""
        ;;
esac

# 4. Verify -------------------------------------------------------------
if command -v vexor > /dev/null 2>&1; then
    say "installed: $(command -v vexor)"
    vexor --version
    say "try it from anywhere:  cd /tmp && vexor --version"
else
    die "installation finished but 'vexor' is not on PATH yet — open a new shell and run: vexor --version"
fi
