{
  description = "kindling — cross-platform unattended Nix installer";

  nixConfig = {
    allow-import-from-derivation = true;
  };

  inputs = {
    nixpkgs.follows = "substrate/nixpkgs";
    crate2nix.url = "github:nix-community/crate2nix";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    substrate = {
      url = "github:pleme-io/substrate";
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
      # Pure-dispatch via substrate's lockfile-builder. Spec lives in
      # Cargo.build-spec.json; rootFeatures = [] strips the default
      # "aws" feature for the slim build.
      lockfileBuilder = import "${substrate}/lib/build/rust/lockfile-builder.nix" { inherit pkgs; };
      plemeCrateOverrides = import "${substrate}/lib/build/rust/pleme-crate-overrides.nix";
      generated = lockfileBuilder.mkProject {
        src = self;
        defaultCrateOverrides = pkgs.defaultCrateOverrides // plemeCrateOverrides;
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
