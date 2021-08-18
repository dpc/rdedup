{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };

    # borked: https://github.com/nix-community/fenix/issues/20
    # fenix = {
    #   url = "github:nix-community/fenix";
    #   inputs.nixpkgs.follows = "nixpkgs";
    # };
    naersk = {
      url = "github:nmattia/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, rust-overlay, naersk, nixpkgs, flake-utils, flake-compat }:
    let
      rustChannel = "stable";
    in
    flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [
          rust-overlay.overlay

          (self: super:
            {
              rustc = self.rust-bin.${rustChannel}.latest.default;
              cargo = self.rust-bin.${rustChannel}.latest.default;
            }
          )
        ];
      };
      naersk-lib = naersk.lib."${system}";
    in {
      # packages.rdedup-lib = naersk-lib.buildPackage {
      #   pname = "rdedup-lib";
      #   root = ./.;
      #   cargoBuildOptions = x: x ++ [ "-p" "rdedup-lib" ];
      #   cargoTestOptions = x: x ++ [ "-p" "rdedup-lib" ];
      # };

      # packages.rdedup = naersk-lib.buildPackage {
      #   # pname = "rdedup";
      #   root = ./.;
      #   # buildInputs = [ self.packages.${system}.rdedup-lib ];
      # };
      packages.rdedup = naersk-lib.buildPackage ./.;

      defaultPackage = self.packages.${system}.rdedup;
      defaultApp = self.packages.${system}.rdedup;

      # `nix develop`
      devShell = pkgs.mkShell
        {
          inputsFrom = builtins.attrValues self.packages.${system};
          nativeBuildInputs = (with pkgs;
            [
              nixpkgs-fmt
              cargo-watch
              pkgs.rust-bin.${rustChannel}.latest.rust-analysis
              pkgs.rust-bin.${rustChannel}.latest.rls
              pkgs.rust-bin.${rustChannel}.latest.rustc
              pkgs.rust-bin.${rustChannel}.latest.cargo
            ]);
          RUST_SRC_PATH = "${pkgs.rust-bin.${rustChannel}.latest.rust-src}/lib/rustlib/src/rust/library";
        };

        # devShell =
        # # pkgs.mkShell { buildInputs = [ self.packages.${system}.rdedup ]; };
        # pkgs.mkShell {
        #   nativeBuildInputs = [ fenix.packages.${system}.stable.rustc ];
        #   buildInputs = with pkgs; [ pkgconfig libsodium lzma openssl fenix.packages.x86_64-linux.rust-analyzer ];
        # };
  });
}
