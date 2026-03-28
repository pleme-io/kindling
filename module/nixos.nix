# Kindling NixOS module — server mode (K3s bootstrap + daemon)
#
# Namespace: services.kindling.server.*
#
# Generates up to three systemd services:
#   - kindling-init.service (Type=oneshot, RemainAfterExit) — reads cloud
#     userdata, extracts cluster config, runs the bootstrap state machine.
#     Replaces both amazon-init and the old kindling-server-bootstrap.
#   - kindling-server-bootstrap.service (legacy, opt-in via legacyBootstrap)
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

  config = mkIf cfg.enable {
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
        # Allow time for nixos-rebuild + K3s + FluxCD
        TimeoutStartSec = "1800";
      };

      path = with pkgs; [
        nix
        git
        kubectl
        nixos-rebuild
        wireguard-tools
        iproute2
      ];
    };

    # Disable amazon-init — kindling-init replaces it
    virtualisation.amazon-init.enable = mkIf (!cfg.legacyBootstrap) (lib.mkForce false);

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
  };
}
