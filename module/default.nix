# Kindling home-manager module — daemon (REST + GraphQL + telemetry)
#
# Namespace: services.kindling.daemon.*
#
# The daemon provides REST and GraphQL APIs for managing the Nix installation
# on the node, with optional telemetry push to Vector.
#
# Module factory: receives { hmHelpers } from flake.nix, returns HM module.
{ hmHelpers }:
{
  lib,
  config,
  pkgs,
  ...
}:
with lib; let
  inherit (hmHelpers) mkLaunchdService mkSystemdService;
  daemonCfg = config.services.kindling.daemon;
  isDarwin = pkgs.stdenv.isDarwin;

  logDir = if isDarwin
    then "${config.home.homeDirectory}/Library/Logs"
    else "${config.home.homeDirectory}/.local/share/kindling/logs";

  # ── Daemon TOML config (generated from nix options) ──────────────────
  kindlingDaemonConfig = pkgs.writeText "kindling-daemon.toml"
    (lib.generators.toTOML {} ({
      auto_install = true;
      backend = "upstream";
      daemon = {
        http_addr = daemonCfg.httpAddr;
        grpc_addr = daemonCfg.grpcAddr;
        log_level = daemonCfg.logLevel;
        telemetry = {
          enabled = daemonCfg.telemetry.enable;
          vector_url = daemonCfg.telemetry.vectorUrl;
          push_interval_secs = daemonCfg.telemetry.pushIntervalSecs;
          node_id = daemonCfg.telemetry.nodeId;
        };
        gc = {
          schedule_secs = daemonCfg.gc.scheduleSecs;
        };
      };
    }));
in {
  options.services.kindling.daemon = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable Kindling daemon (REST + GraphQL API for Nix management)";
    };

    package = mkOption {
      type = types.package;
      default = pkgs.kindling;
      description = "Kindling package";
    };

    httpAddr = mkOption {
      type = types.str;
      default = "127.0.0.1:9100";
      description = "HTTP listen address for REST and GraphQL APIs";
    };

    grpcAddr = mkOption {
      type = types.str;
      default = "127.0.0.1:9101";
      description = "gRPC listen address (requires grpc feature)";
    };

    logLevel = mkOption {
      type = types.str;
      default = "info";
      description = "Log level (trace, debug, info, warn, error)";
    };

    telemetry = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable telemetry push to Vector";
      };

      vectorUrl = mkOption {
        type = types.str;
        default = "http://localhost:8686";
        description = "Vector HTTP source endpoint URL";
      };

      pushIntervalSecs = mkOption {
        type = types.int;
        default = 60;
        description = "Telemetry push interval in seconds";
      };

      nodeId = mkOption {
        type = types.str;
        default = "";
        description = "Node identifier for telemetry (auto-detects hostname if empty)";
      };
    };

    gc = {
      scheduleSecs = mkOption {
        type = types.int;
        default = 0;
        description = "Automatic GC schedule in seconds (0 = disabled, 86400 = daily)";
      };
    };
  };

  # ── Config ─────────────────────────────────────────────────────────
  config = mkMerge [
    # Darwin: launchd agent
    (mkIf (daemonCfg.enable && isDarwin) (mkMerge [
      {
        home.activation.kindling-log-dir = lib.hm.dag.entryAfter ["writeBoundary"] ''
          run mkdir -p "${logDir}"
        '';
      }

      (mkLaunchdService {
        name = "kindling-daemon";
        label = "io.pleme.kindling-daemon";
        command = "${daemonCfg.package}/bin/kindling";
        args = ["daemon" "--config" "${kindlingDaemonConfig}"];
        logDir = logDir;
      })

      # Log rotation: newsyslog on Darwin
      {
        home.file.".newsyslog.d/kindling.conf".text = ''
          # logfilename          [owner:group]    mode count size  when  flags [/pid_file] [sig_num]
          ${logDir}/kindling-daemon.out.log       644  3     10240 *     GN
          ${logDir}/kindling-daemon.err.log       644  3     10240 *     GN
        '';
      }
    ]))

    # Linux: systemd service
    (mkIf (daemonCfg.enable && !isDarwin) (mkMerge [
      (mkSystemdService {
        name = "kindling-daemon";
        description = "Kindling daemon — Nix management REST/GraphQL API";
        command = "${daemonCfg.package}/bin/kindling";
        args = ["daemon" "--config" "${kindlingDaemonConfig}"];
      })
    ]))
  ];
}
