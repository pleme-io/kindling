#!/bin/sh
# Kindling bootstrap — take a bare laptop to a working dev environment.
#
# Usage:
#   curl -sSfL https://raw.githubusercontent.com/pleme-io/kindling/main/scripts/bootstrap.sh | sh
#   curl -sSfL https://raw.githubusercontent.com/pleme-io/kindling/main/scripts/bootstrap.sh | sh -s -- --org pleme-io
#
set -eu

REPO="pleme-io/kindling"
INSTALL_DIR="$HOME/.local/bin"

main() {
    detect_platform
    download_kindling
    run_bootstrap "$@"
}

detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Darwin) OS_LOWER="darwin" ;;
        Linux)  OS_LOWER="linux" ;;
        *)      echo "Error: unsupported OS: $OS" >&2; exit 1 ;;
    esac

    case "$ARCH" in
        x86_64)         ARCH_LOWER="x86_64" ;;
        aarch64|arm64)  ARCH_LOWER="aarch64" ;;
        *)              echo "Error: unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac

    if [ "$OS_LOWER" = "darwin" ]; then
        TARGET="${ARCH_LOWER}-apple-darwin"
    else
        TARGET="${ARCH_LOWER}-unknown-linux-musl"
    fi
}

download_kindling() {
    # Skip download if kindling is already on PATH
    if command -v kindling >/dev/null 2>&1; then
        KINDLING="kindling"
        echo ":: kindling already installed at $(command -v kindling)"
        return
    fi

    if [ -x "$INSTALL_DIR/kindling" ]; then
        KINDLING="$INSTALL_DIR/kindling"
        echo ":: kindling found at $KINDLING"
        return
    fi

    DOWNLOAD_URL="https://github.com/$REPO/releases/latest/download/kindling-${TARGET}"
    echo ":: Downloading kindling for ${TARGET}..."

    mkdir -p "$INSTALL_DIR"
    if command -v curl >/dev/null 2>&1; then
        curl -sSfL "$DOWNLOAD_URL" -o "$INSTALL_DIR/kindling"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$INSTALL_DIR/kindling" "$DOWNLOAD_URL"
    else
        echo "Error: curl or wget is required" >&2
        exit 1
    fi

    chmod +x "$INSTALL_DIR/kindling"
    KINDLING="$INSTALL_DIR/kindling"
    echo ":: Installed kindling to $KINDLING"
}

run_bootstrap() {
    echo ":: Running kindling bootstrap..."
    "$KINDLING" bootstrap --no-confirm "$@"
}

main "$@"
