# Bootstrap as Convergence Delta

kindling-init is the convergence delta applied to a pre-converged AMI checkpoint.
The AMI contains the full system closure. kindling-init applies the minimal
runtime transformation: identity + secrets + role selection.

## The Delta

```
AMI (checkpoint)
  → kindling-init reads EC2 user_data
    → Phase: ConfigLoaded (parse cluster config)
    → Phase: SecretsProvisioned (write keys to /run/secrets.d/)
    → Phase: HostnameSet (write role sentinel: server-mode|agent-mode)
    → Phase: K3sConfigWritten (generate /etc/rancher/k3s/config.yaml)
    → Phase: WireguardStarted (fast-start VPN interface)
    → Phase: WireguardReady (verify connectivity)
    → Phase: FluxcdConfigWritten (write bootstrap manifest)
    → Phase: Complete (persist state, exit)
  → systemd starts K3s (ConditionPathExists on sentinel)
  → K3s applies FluxCD manifests
  → FluxCD reconciles from Git
```

Total delta time: ~10 seconds of file writes + K3s startup.
No package installs. No nixos-rebuild. No downloads.

## Convergence Context

The bootstrap has different contexts at different phases:

| Phase | Context | What's Available |
|-------|---------|-----------------|
| ConfigLoaded | Boot | Network, EC2 metadata, no secrets |
| SecretsProvisioned | Boot | Network, secrets in /run/secrets.d/ |
| WireguardStarted | Boot | VPN tunnel, operator reachable |
| K3sConfigWritten | Boot | K3s config ready, not yet running |
| Complete | Runtime | Full cluster, all services |

Invariants are evaluated in their matching context:
- Security gate (`validate_vpn_security`) runs at ConfigLoaded
- VPN connectivity check runs at WireguardStarted
- K3s readiness runs at integration test time (runtime context)

## State Machine Persistence

`/var/lib/kindling/server-state.json` records the current phase.
If kindling-init is interrupted and re-run, it resumes from the last
completed phase. This is idempotent convergence — re-running the delta
produces the same result.

## 18 AMI Gates

The AMI checkpoint is verified by 18 gates before snapshot.
See `docs/convergence-ami.md` in kindling-profiles for the full list.
These gates ensure the delta will succeed: if the AMI passes all 18,
the bootstrap will converge correctly for ANY cluster configuration
passed via user_data.
