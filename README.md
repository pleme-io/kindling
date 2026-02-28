# Kindling

Cross-platform unattended Nix installer with a full bootstrap chain: nix → direnv → tend → workspace repos.

## Quick Start

One command to go from bare laptop to working dev environment:

```sh
curl -sSfL https://raw.githubusercontent.com/pleme-io/kindling/main/scripts/bootstrap.sh | sh
```

With a GitHub org for automatic workspace setup:

```sh
curl -sSfL https://raw.githubusercontent.com/pleme-io/kindling/main/scripts/bootstrap.sh | sh -s -- --org pleme-io
```

## What It Does

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  1. Nix     │───▶│  2. direnv  │───▶│  3. tend    │───▶│  4. repos   │
│  installer  │    │  + hook     │    │  + config   │    │  tend sync  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

1. **Nix** — Detects or installs Nix using the official nix-installer
2. **direnv** — Installs direnv via `nix profile`, injects shell hook, installs `use_kindling` lib
3. **tend** — Installs tend via `nix profile`, generates starter workspace config
4. **Repos** — Runs `tend sync` to clone all org repositories

## Supported Platforms

| Platform | Architecture | Status |
|----------|-------------|--------|
| macOS    | arm64 (Apple Silicon) | Supported |
| macOS    | x86_64 (Intel) | Supported |
| Linux    | x86_64 | Supported |
| Linux    | aarch64 | Supported |
| WSL2     | x86_64 / aarch64 | Supported (auto-detects, skips systemd if absent) |

## Commands

### `kindling bootstrap`

Full bootstrap chain. Takes a bare machine to a working development environment.

```sh
kindling bootstrap [--skip-direnv] [--skip-tend] [--org ORG] [--no-confirm]
```

| Flag | Description |
|------|-------------|
| `--skip-direnv` | Skip direnv installation and shell hook setup |
| `--skip-tend` | Skip tend installation and repo sync |
| `--org ORG` | GitHub org for tend workspace config generation |
| `--no-confirm` | Skip all confirmation prompts |

### `kindling install`

Download and run the Nix installer.

```sh
kindling install [--backend upstream|determinate] [--no-confirm]
```

### `kindling check`

Check Nix installation status, platform info, and version.

```sh
kindling check
```

### `kindling ensure`

Ensure Nix is installed (designed as a direnv integration point). Auto-installs based on config or prompts on first use.

```sh
kindling ensure [--version ">=2.24"]
```

### `kindling uninstall`

Uninstall Nix using the install receipt left by nix-installer.

```sh
kindling uninstall
```

## Direnv Integration

Add to any project's `.envrc`:

```sh
use_kindling
use flake
```

`use_kindling` will:
1. Check if Nix is on PATH
2. If not, check well-known nix paths and source the profile
3. If still missing, download kindling and run `kindling ensure`
4. Source the nix-daemon profile

The `use_kindling` function is automatically installed to `~/.config/direnv/lib/kindling.sh` by `kindling bootstrap`.

## Configuration

Config file: `~/.config/kindling/config.toml`

```toml
auto_install = true    # Auto-install nix without prompting
backend = "upstream"   # "upstream" or "determinate"
```

## Building from Source

With Nix:

```sh
nix build
```

With Cargo:

```sh
cargo build --release
```

## License

MIT
