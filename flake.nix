{
  description = "kindling — cross-platform unattended Nix installer";

  nixConfig = {
    allow-import-from-derivation = true;
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    crate2nix.url = "github:nix-community/crate2nix";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.fenix.follows = "fenix";
    };
    devenv = {
      url = "github:cachix/devenv";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    crate2nix,
    flake-utils,
    substrate,
    devenv,
    ...
  }: let
    standardFlake = (import "${substrate}/lib/rust-tool-release-flake.nix" {
      inherit nixpkgs crate2nix flake-utils devenv;
    }) {
      toolName = "kindling";
      src = self;
      repo = "pleme-io/kindling";
    };

    # Slim `kindling-pki` build: same crate, `--no-default-features`,
    # drops aws-sdk-ec2 + aws-config + their transitive ~150 crates.
    # Build time falls from ~10-20 min (and OOM-prone on 6-8 GB builders)
    # to ~2 min with a ~7.4 MB binary. Consumers that only need `pki seed`
    # / `pki provision` (kasou local-VM nixos contexts) pick this output;
    # AMI consumers keep the default (full-features) build.
    slimKindlingFor = system: let
      pkgs = import nixpkgs { inherit system; };
      # Use the COMMITTED Cargo.nix (no crate2nix IFD) to keep
      # evaluation cheap. Cargo.nix is regenerated explicitly via
      # `nix run .#regenerate-cargo-nix` after Cargo.lock changes;
      # bypassing the IFD avoids dragging in crate2nix's full build
      # closure (proc-macro-error-attr, version_check, structopt-derive)
      # on every consumer eval.
      generated = import ./Cargo.nix {
        inherit pkgs;
        rootFeatures = [ ];  # drops `default = ["aws"]`
        defaultCrateOverrides = pkgs.defaultCrateOverrides // {};
      };
    in generated.rootCrate.build;
  in
    standardFlake
    // {
      packages = nixpkgs.lib.recursiveUpdate (standardFlake.packages or {}) (
        nixpkgs.lib.genAttrs [ "aarch64-linux" "aarch64-darwin" "x86_64-linux" "x86_64-darwin" ]
          (system: { kindling-pki = slimKindlingFor system; })
      );

      homeManagerModules.default = import ./module {
        hmHelpers = import "${substrate}/lib/hm-service-helpers.nix" { lib = nixpkgs.lib; };
      };

      nixosModules.default = import ./module/nixos.nix;
    };
}
