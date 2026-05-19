# Kindling NixOS module — server mode (K3s bootstrap + daemon)
#
# Namespace: services.kindling.server.*
#
# Generates up to four systemd services:
#   - kindling-init.service (Type=oneshot, RemainAfterExit) — reads cloud
#     userdata, extracts cluster config, runs the bootstrap state machine.
#     Replaces both amazon-init and the old kindling-server-bootstrap.
#   - kindling-server-bootstrap.service (legacy, opt-in via legacyBootstrap)
#   - kindling-pki-seed.service (opt-in via pkiSeed.enable) — kasou-VM
#     counterpart to kindling-init: copies decrypted k3s PKI from sops-nix
#     into /var/lib/rancher/k3s/server/tls/ before k3s.service starts.
#   - kindling-daemon.service (after init + k3s)
{
  lib,
  config,
  pkgs,
  ...
}:
with lib; let
  cfg = config.services.kindling.server;
in {
  options.services.kindling.server = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable Kindling server mode (K3s cluster bootstrap)";
    };

    package = mkOption {
      type = types.package;
      default = pkgs.kindling;
      description = "Kindling package";
    };

    configPath = mkOption {
      type = types.str;
      default = "/etc/pangea/cluster-config.json";
      description = "Path to the cluster-config.json written by kindling init";
    };

    legacyBootstrap = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Use the legacy kindling-server-bootstrap.service instead of
        kindling-init.service. Only enable this for backward compatibility
        with nodes that still rely on amazon-init writing the config file.
      '';
    };

    timeoutStartSec = mkOption {
      type = types.int;
      default = 120;
      description = "Timeout for kindling-init.service (seconds). Default 120 for max-baked AMI. Set to 1800 for force_rebuild.";
    };

    # ── Deterministic PKI seed (kasou-VM counterpart to kindling-init) ──
    #
    # On kasou-managed local-VM k3s servers there's no EC2 userdata, so
    # `kindling-init` cleanly skips via its ExecCondition. Those clusters
    # instead seed `/var/lib/rancher/k3s/server/tls/` from sops-nix-
    # decrypted files at `/run/secrets/clusters/<cluster>/tls/*` —
    # operator-facing surface in `kindling pki mint` / `kindling pki seed`,
    # and the consumer wiring in pleme-io/nix/profiles/nixos-k3s-vm.
    #
    # Shared invariant with kindling-init: `Before=k3s.service`. k3s only
    # auto-generates a CA when none exists in the TLS dir, so seeding the
    # bag before first k3s start is what makes the kubeconfig stable
    # across VM reboots. Available even when `server.enable = false`
    # because kasou VMs only need this primitive, not the full server
    # bootstrap (no userdata, no kindling daemon HTTP API).
    pkiSeed = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Run `kindling pki seed --source sops-nix` from a oneshot ordered
          Before=k3s.service. Default off because AMI clusters get their
          PKI via the kindling-init / userdata path.
        '';
      };

      cluster = mkOption {
        type = types.str;
        default = "";
        example = "engenho-local";
        description = ''
          Cluster name used to locate sops-nix-decrypted PKI files at
          `/run/secrets/clusters/<cluster>/tls/`. Must match the prefix
          the operator used when running `kindling pki mint --cluster
          <name>`.
        '';
      };

      package = mkOption {
        type = types.package;
        default = pkgs.kindling;
        description = "Kindling package providing the `kindling pki seed` binary.";
      };
    };

    daemon = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Enable the kindling daemon after bootstrap (monitoring API)";
      };

      httpAddr = mkOption {
        type = types.str;
        default = "0.0.0.0:9100";
        description = "HTTP listen address for daemon REST/GraphQL APIs";
      };

      logLevel = mkOption {
        type = types.str;
        default = "info";
        description = "Log level for the daemon";
      };
    };
  };

  config = lib.mkMerge [
    # ─────────────────────────────────────────────────────────────────
    # Full server-mode bootstrap (kindling-init + legacy + daemon).
    # Gated on `services.kindling.server.enable` — AMI/EC2 clusters opt
    # in here; kasou local-VM clusters typically leave this off and
    # enable only the pkiSeed primitive below.
    # ─────────────────────────────────────────────────────────────────
    (mkIf cfg.enable {
      # Ensure state directory exists
      systemd.tmpfiles.rules = [
        "d /var/lib/kindling 0755 root root -"
        "d /etc/kindling 0755 root root -"
      ];

      # ── kindling-init — the unified init service (default) ───────────
      #
      # Reads EC2 userdata directly, extracts the cluster config JSON
      # (from raw JSON or bash heredoc), writes it to configPath, then
      # runs the full bootstrap state machine. Replaces both amazon-init
      # and the old kindling-server-bootstrap service.
      systemd.services.kindling-init = mkIf (!cfg.legacyBootstrap) {
        description = "Kindling init — read cloud metadata + bootstrap K3s cluster";
        after = ["fetch-ec2-metadata.service" "network-online.target"];
        before = ["k3s.service" "k3s-agent.service" "fluxcd-bootstrap.service"];
        wants = ["network-online.target" "fetch-ec2-metadata.service"];
        wantedBy = ["multi-user.target"];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          # Only run if EC2 metadata was fetched (userdata file exists and is non-empty).
          # On AMI build instances there's no userdata — service skips cleanly.
          ExecCondition = "${pkgs.bash}/bin/bash -c 'test -s /etc/ec2-metadata/user-data'";
          ExecStart = "${cfg.package}/bin/kindling init --userdata /etc/ec2-metadata/user-data --config-out ${cfg.configPath}";
          StandardOutput = "journal";
          StandardError = "journal";
          TimeoutStartSec = toString cfg.timeoutStartSec;
        };

        path = with pkgs; [
          wireguard-tools
          iproute2
          iptables
          curl
          awscli2
          kubectl
          systemd
        ];
      };

      # NOTE: AMI / EC2 consumers should explicitly set
      # `virtualisation.amazon-init.enable = false` in their own nixos
      # config — kindling-init replaces amazon-init's role. The
      # disable used to live here; it was removed because the kindling
      # module is also imported into kasou local-VM nixos systems
      # where the amazon-init option doesn't exist (eval-time
      # "option does not exist" error). The AMI cluster's config
      # already sets it false; the line was redundant defence.

      # ── Legacy bootstrap (opt-in) ────────────────────────────────────
      #
      # Preserved for backward compatibility. Requires amazon-init to
      # write the config file before this service starts.
      systemd.services.kindling-server-bootstrap = mkIf cfg.legacyBootstrap {
        description = "Kindling server bootstrap — K3s cluster setup (legacy)";
        after = ["network-online.target" "amazon-init.service" "cloud-init.target"];
        wants = ["network-online.target"];
        wantedBy = ["multi-user.target"];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecCondition = "${pkgs.bash}/bin/bash -c 'test -f ${cfg.configPath}'";
          ExecStart = "${cfg.package}/bin/kindling server bootstrap --config ${cfg.configPath}";
          StandardOutput = "journal";
          StandardError = "journal";
          TimeoutStartSec = "1800";
        };

        path = with pkgs; [
          nix
          git
          kubectl
          nixos-rebuild
        ];
      };

      # ── Daemon service — provides monitoring API after bootstrap ─────
      systemd.services.kindling-daemon = mkIf cfg.daemon.enable {
        description = "Kindling daemon — server monitoring REST/GraphQL API";
        after =
          if cfg.legacyBootstrap
          then ["kindling-server-bootstrap.service" "k3s.service"]
          else ["kindling-init.service" "k3s.service"];
        requires =
          if cfg.legacyBootstrap
          then ["kindling-server-bootstrap.service"]
          else ["kindling-init.service"];
        wantedBy = ["multi-user.target"];

        serviceConfig = {
          ExecStart = lib.concatStringsSep " " [
            "${cfg.package}/bin/kindling"
            "daemon"
            "--http-addr"
            cfg.daemon.httpAddr
            "--log-level"
            cfg.daemon.logLevel
          ];
          Restart = "on-failure";
          RestartSec = 5;
          StandardOutput = "journal";
          StandardError = "journal";
        };
      };
    })

    # ─────────────────────────────────────────────────────────────────
    # PKI seed primitive (independent of `server.enable`).
    # Kasou local-VM clusters enable just this to get deterministic
    # PKI without dragging in the EC2/userdata bootstrap path.
    # ─────────────────────────────────────────────────────────────────
    (mkIf cfg.pkiSeed.enable {
      assertions = [
        {
          assertion = cfg.pkiSeed.cluster != "";
          message = ''
            services.kindling.server.pkiSeed.enable = true requires
            services.kindling.server.pkiSeed.cluster to be set (the
            sops path prefix under clusters/<name>/tls/).
          '';
        }
      ];

      systemd.services.kindling-pki-seed = {
        description = "Kindling PKI seed — copy k3s CA from sops-nix before k3s.service";
        before = ["k3s.service" "k3s-agent.service"];
        requiredBy = ["k3s.service"];
        wantedBy = ["multi-user.target"];
        after = ["sops-install-secrets.service"];
        wants = ["sops-install-secrets.service"];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          # Cleanly skip if sops hasn't decrypted (or this cluster's
          # bag isn't in sops yet). Matches kindling-init's "no
          # userdata, exit zero" shape so a misconfigured cluster
          # boots with k3s' auto-generated CA — same broken state as
          # pre-fix, surfaced via journalctl rather than masquerading
          # as a silent regression.
          ExecCondition = "${pkgs.bash}/bin/bash -c 'test -d /run/secrets/clusters/${cfg.pkiSeed.cluster}/tls'";
          ExecStart = "${cfg.pkiSeed.package}/bin/kindling pki seed --source sops-nix --cluster ${cfg.pkiSeed.cluster}";
          StandardOutput = "journal";
          StandardError = "journal";
        };
      };
    })
  ];
}
