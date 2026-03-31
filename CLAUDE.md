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
the orchestrator config step (K3s or kubeadm, based on `distribution` field).

---

## Multi-Distribution Support

The `distribution` field in `ClusterConfig` selects the Kubernetes distribution:

- `"k3s"` (default) -- existing K3s pipeline via `generate_k3s_config_yaml` + `write_k3s_runtime_config`
- `"kubernetes"` -- upstream kubeadm via `kubeadm::generate_kubeadm_config` + `kubeadm::write_kubeadm_config`

The bootstrap state machine is distribution-aware: the orchestrator config phase
routes to the correct config generator. All other phases (WireGuard, secrets,
identity, FluxCD) are shared. Helper methods `is_k3s()` and `is_kubernetes()`
on `ClusterConfig` make routing explicit.

### Kubeadm Config Generation (`server/kubeadm.rs`)

- **CP init** (`cluster_init: true`, `role: "server"`): generates `ClusterConfiguration` + `InitConfiguration` YAML
  - API server advertise address from VPN IP
  - cert SANs from explicit config + VPN addresses
  - etcd local datadir, pod/service CIDRs, bootstrap token
- **Join** (workers or secondary CP): generates `JoinConfiguration` YAML
  - Discovery via bootstrap token + CA cert hash
  - CP join includes `controlPlane` stanza with advertise address + certificate key

Config written to `/etc/kubernetes/kubeadm-config.yaml`. The NixOS profile
(`k8s-cloud-server`) provides kubelet, containerd, etcd, kubeadm via nixpkgs.

### AMI Validation (`kindling ami-test --distribution kubernetes`)

Kubernetes AMIs validate: `kubeadm-binary`, `kubelet-binary`, `containerd-config`, `etcd-binary`
instead of K3s-specific checks.

---

## Node Name Generation (`derive_hostname`)

K3s rejects duplicate hostnames in a cluster. AMI-built nodes all share the same
base hostname (e.g., "ami-builder"), so kindling-init generates a unique K3s
`node-name` from the cluster config:

```
{cluster_name}-{role}-{node_index}
```

Examples:
- `prod-us-east-server-0` (server, index 0)
- `prod-us-east-agent-1` (agent, index 1)
- `cluster-test-server-0` (test cluster CP)

Implementation: `ClusterConfig::derive_hostname()` in `server/cluster_config.rs`.
Called during `generate_k3s_config_yaml()` to write the `node-name:` line in
`/etc/rancher/k3s/config.yaml`.

---

## Server-Only Config Gating

K3s agent will fatal-error on config keys that are only valid for `k3s server`
(e.g., `disable-network-policy`, `tls-san`, `cluster-init`). The config generator
gates these behind a role check:

```rust
if config.role == "server" {
    // disable-network-policy, tls-san, cluster-init
}
```

**Server-only keys** (only written when `role == "server"`):
- `disable-network-policy: true` -- prevents crashes when WireGuard interfaces
  coexist with Flannel
- `tls-san:` -- VPN addresses added as SANs so K3s cert is valid over VPN
- `cluster-init: true` -- first server initializes the cluster

**Common keys** (written for both server and agent):
- `node-name:` -- unique name from `derive_hostname()`
- `token:` -- K3s join token from `bootstrap_secrets`
- `server:` -- join URL (agent nodes, and secondary servers)

Implementation: `generate_k3s_config_yaml()` in `server/bootstrap.rs`.

---

## Cluster Test Flow (ami-forge Integration)

When ami-forge runs `cluster-test`, kindling-init is the init system on each
test instance. The flow:

1. **ami-forge** launches EC2 instances with JSON userdata containing:
   - `role` ("server" or "agent")
   - `cluster_name`, `node_index`
   - `skip_nix_rebuild: true` (AMI already has full config)
   - `vpn` links with ephemeral WireGuard keys
   - `bootstrap_secrets` with K3s token

2. **kindling-init.service** starts on boot:
   - Reads userdata from `/etc/ec2-metadata/user-data`
   - Writes role sentinel (`/var/lib/kindling/server-mode` or `agent-mode`)
   - Provisions secrets to `/run/secrets.d/`
   - Generates `/etc/rancher/k3s/config.yaml` (with role gating)
   - Sets up WireGuard interface (fast-start, before nixos-rebuild)
   - Skips nixos-rebuild (AMI is pre-built)

3. **systemd** evaluates `ConditionPathExists` on K3s services:
   - `k3s.service` starts if `/var/lib/kindling/server-mode` exists
   - `k3s-agent.service` starts if `/var/lib/kindling/agent-mode` exists

4. **ami-forge** validates via SSH + EC2 tag polling:
   - WireGuard interface up
   - K3s nodes Ready
   - VPN handshakes established
   - kubectl namespaces accessible

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
    bootstrap.rs      14-phase bootstrap state machine (distribution-aware)
    cluster_config.rs ClusterConfig type (skip_nix_rebuild, vpn, bootstrap_secrets)
    kubeadm.rs        Kubeadm config generation (init + join YAML)
    wireguard_fast.rs Fast WireGuard setup (before nixos-rebuild)
    health.rs         K3s + FluxCD health checks
  vpn/                VPN link management
  node_identity/      Node identity types
module/
  default.nix         Home-manager module (daemon)
  nixos.nix           NixOS module (kindling-init, legacy bootstrap, daemon)
```
