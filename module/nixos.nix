# Kindling NixOS module — server mode (K3s bootstrap + daemon)
#
# Namespace: services.kindling.server.*
#
# Generates two systemd services:
#   - kindling-server-bootstrap.service (Type=oneshot, RemainAfterExit)
#   - kindling-daemon.service (after bootstrap + k3s)
{
  lib,
  config,
  pkgs,
  ...
}:
with lib; let
  cfg = config.services.kindling.server;
  daemonCfg = config.services.kindling.daemon or {};
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
      description = "Path to the cluster-config.json written by cloud-init";
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

    # Bootstrap service — runs once, remains after exit
    #
    # Ordering: amazon-init.service (NixOS EC2 userdata handler) writes
    # /etc/pangea/cluster-config.json, then this service picks it up.
    # NixOS does NOT have cloud-init.target — it uses amazon-init.service.
    # On non-EC2 platforms with real cloud-init, cloud-init.target is listed
    # as a soft dependency (systemd silently ignores missing units in After=).
    systemd.services.kindling-server-bootstrap = {
      description = "Kindling server bootstrap — K3s cluster setup";
      after = ["network-online.target" "amazon-init.service" "cloud-init.target"];
      wants = ["network-online.target"];
      wantedBy = ["multi-user.target"];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # Only run if cloud-init has written the cluster config.
        # On AMI build instances there's no config — service skips cleanly.
        ExecCondition = "${pkgs.bash}/bin/bash -c 'test -f ${cfg.configPath}'";
        ExecStart = "${cfg.package}/bin/kindling server bootstrap --config ${cfg.configPath}";
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
      ];
    };

    # Daemon service — provides monitoring API after bootstrap
    systemd.services.kindling-daemon = mkIf cfg.daemon.enable {
      description = "Kindling daemon — server monitoring REST/GraphQL API";
      after = ["kindling-server-bootstrap.service" "k3s.service"];
      requires = ["kindling-server-bootstrap.service"];
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
