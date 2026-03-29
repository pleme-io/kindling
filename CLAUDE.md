# kindling

Cross-platform unattended Nix installer, fleet manager, and server bootstrap
daemon. Rust CLI with NixOS and home-manager modules.

---

## AMI-Related Subcommands

### `kindling ami-build`

Runs inside the Packer build instance. 5 phases:

1. **Nix access-tokens** -- writes GITHUB_TOKEN to `/etc/nix/github-access-token`
2. **nixos-rebuild switch** -- installs the full NixOS config from the flake ref
3. **Clean K3s state** -- stops K3s, removes `/var/lib/rancher/k3s/server/`
   entirely (datastore + TLS + creds) so kindling-init can seed deterministic PKI
4. **AMI validation** -- delegates to `ami-test` (11 checks)
5. **Cleanup** -- nix-collect-garbage, remove build-time secrets, rotate journals, fstrim

Flags: `--skip-rebuild` (for testing), `--skip-validation` (for non-K3s profiles like attic).

### `kindling ami-test`

Static AMI validation before Packer snapshots. 11 checks:

| Check | What it validates |
|-------|-------------------|
| `kindling-binary` | kindling CLI is in PATH |
| `k3s-binary` | K3s is installed |
| `wireguard-tools` | wg CLI is available |
| `nixos-rebuild` | nixos-rebuild is available |
| `kindling-init-service` | kindling-init.service is enabled |
| `nix-daemon` | nix-daemon.socket or .service is enabled |
| `amazon-init-disabled` | amazon-init.service is NOT enabled (kindling-init replaces it) |
| `k3s-no-stale-state` | No K3s datastore in the AMI (clean for PKI seeding) |
| `no-stale-tls` | No stale TLS certs (K3s would ignore seeded PKI) |
| `no-leaked-secrets` | No cluster-config.json, server-state.json, or /run/secrets.d entries |
| `network-connectivity` | cache.nixos.org is reachable |

### `kindling ami-integration-test`

Runs on a test instance booted from a freshly built AMI with test userdata. 3 phases:

1. **Wait for kindling-init** -- polls systemd until `ActiveState=active, SubState=exited`
2. **Validate bootstrap state** -- checks `/var/lib/kindling/server-state.json` has `phase: complete`
3. **Validate orchestration** -- WireGuard interface, WireGuard config, K3s API (node Ready), kubectl namespaces

Exit 1 fails the Packer test, which triggers AMI deregistration.

### `kindling init`

The unified cloud bootstrap entry point. Runs as `kindling-init.service` (systemd oneshot, `Before=k3s.service`).

1. Read EC2 userdata from `/etc/ec2-metadata/user-data`
2. Detect format (raw JSON or bash heredoc with `PANGEA_CONFIG_EOF` delimiter)
3. Extract and validate cluster config JSON
4. Write to `/etc/pangea/cluster-config.json` with mode 0640
5. Delegate to the bootstrap state machine

#### Dual-Sentinel Role Selection

kindling-init writes a sentinel file to select the K3s role for this node:

- `/var/lib/kindling/server-mode` -- server role (k3s.service)
- `/var/lib/kindling/agent-mode` -- agent role (k3s-agent.service)

The blackmatter-kubernetes K3s NixOS module uses systemd `ConditionPathExists`
on these files: `k3s.service` starts only if `server-mode` exists,
`k3s-agent.service` starts only if `agent-mode` exists. If neither exists
(e.g. during AMI build), neither K3s service starts. This replaces the old
`systemctl mask/enable` approach which raced with systemd ordering.

### Bootstrap State Machine (14 phases)

```
Pending → ConfigLoaded → SecretsProvisioned → WireguardFastStart →
IdentityWritten → NixRebuildRunning → NixRebuildComplete →
WireguardWaiting → WireguardReady → K3sWaiting → K3sReady →
FluxcdBootstrapping → FluxcdReady → Complete
```

State persists to `/var/lib/kindling/server-state.json` -- re-running resumes
from the last good phase. The role sentinel file (see above) is written during
the `write_k3s_runtime_config` step within the K3s config generation phase.

---

## `skip_nix_rebuild` in ClusterConfig

For integration tests, the AMI already has the full NixOS config. When
`skip_nix_rebuild: true`:

- Bootstrap skips the nixos-rebuild phase
- Provisions secrets (VPN keys, K3s token) to `/run/secrets.d/`
- Writes K3s `config.yaml` from bootstrap data
- K3s auto-starts via systemd: kindling-init has `Before=k3s.service`

This is the key mechanism that makes AMI testing fast -- no rebuild, just
secret provisioning and service startup.

---

## NixOS Module (`nixosModules.default`)

Defined in `module/nixos.nix`. Creates systemd services:

- **kindling-init.service** (default) -- `Type=oneshot`, `RemainAfterExit=true`,
  `Before=k3s.service`, `After=fetch-ec2-metadata.service`.
  `ExecCondition` checks userdata exists (skips cleanly on AMI build instances).
- **kindling-server-bootstrap.service** (legacy, opt-in via `legacyBootstrap`)
- **kindling-daemon.service** -- monitoring REST/GraphQL API, starts after init + K3s

The `Before=k3s.service` ordering is critical: it ensures VPN and secrets are
provisioned before K3s starts, preventing race conditions where K3s generates
its own CA before kindling can seed deterministic PKI.

---

## Other Subcommands

| Command | Purpose |
|---------|---------|
| `install` | Download and run Nix installer |
| `uninstall` | Uninstall Nix using install receipt |
| `check` | Check Nix installation status |
| `ensure` | Ensure Nix is installed (direnv integration) |
| `bootstrap` | Full bare-machine bootstrap: nix, direnv, tend, profile, apply |
| `daemon` | REST + GraphQL + telemetry daemon |
| `profile list/show` | List/inspect available profiles from kindling-profiles |
| `apply` | Regenerate Nix config from node.yaml and rebuild |
| `fleet status/apply` | Check connectivity / deploy to remote nodes |
| `server bootstrap/status` | K3s cluster bootstrap and health |
| `vpn keygen/profiles/validate` | WireGuard key management |
| `report` | Node runtime report (table/JSON, push to fleet controller) |
| `query` | Query a kindling daemon's REST API |

---

## Structure

```
src/
  commands/           CLI subcommand handlers
    ami_build.rs      AMI build orchestration (5 phases)
    ami_test.rs       Static AMI validation (11 checks)
    ami_integration_test.rs  Full boot orchestration test
    init.rs           Cloud userdata → bootstrap state machine
    server.rs         K3s cluster bootstrap/status
    vpn.rs            WireGuard key management
    ...
  server/
    bootstrap.rs      14-phase bootstrap state machine
    cluster_config.rs ClusterConfig type (skip_nix_rebuild, vpn, bootstrap_secrets)
    wireguard_fast.rs Fast WireGuard setup (before nixos-rebuild)
    health.rs         K3s + FluxCD health checks
  vpn/                VPN link management
  node_identity/      Node identity types
module/
  default.nix         Home-manager module (daemon)
  nixos.nix           NixOS module (kindling-init, legacy bootstrap, daemon)
```
