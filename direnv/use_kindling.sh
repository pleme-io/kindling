#!/usr/bin/env bash
# Direnv library function for kindling.
# Install: symlink or copy to ~/.config/direnv/lib/kindling.sh
# Usage in .envrc:
#   use_kindling
#   use flake

use_kindling() {
    # Check if nix is already available
    if command -v nix >/dev/null 2>&1; then
        return 0
    fi

    # Check well-known nix paths and source profile if found
    for p in /nix/var/nix/profiles/default/bin/nix "$HOME/.nix-profile/bin/nix"; do
        if [ -x "$p" ]; then
            # shellcheck disable=SC1091
            eval "$(dirname "$p")/../etc/profile.d/nix.sh" 2>/dev/null || true
            export PATH="$(dirname "$p"):$PATH"
            return 0
        fi
    done

    # Find or download kindling
    local kindling=""
    if command -v kindling >/dev/null 2>&1; then
        kindling="kindling"
    elif [ -x "$HOME/.local/bin/kindling" ]; then
        kindling="$HOME/.local/bin/kindling"
    else
        log_status "downloading kindling..."
        local os arch target
        os="$(uname -s | tr '[:upper:]' '[:lower:]')"
        arch="$(uname -m)"
        case "$arch" in arm64) arch="aarch64" ;; esac
        if [ "$os" = "darwin" ]; then
            target="${arch}-apple-darwin"
        else
            target="${arch}-unknown-linux-musl"
        fi
        mkdir -p "$HOME/.local/bin"
        curl -sSfL "https://github.com/pleme-io/kindling/releases/latest/download/kindling-${target}" \
            -o "$HOME/.local/bin/kindling"
        chmod +x "$HOME/.local/bin/kindling"
        kindling="$HOME/.local/bin/kindling"
    fi

    # Run kindling ensure (handles consent + install)
    "$kindling" ensure || return 1

    # Source nix daemon profile
    if [ -e '/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh' ]; then
        # shellcheck disable=SC1091
        . '/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh'
    fi
}
