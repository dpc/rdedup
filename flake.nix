{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";

    mozillapkgs = {
      url = "github:mozilla/nixpkgs-mozilla";
      flake = false;
    };
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
      url = "github:dpc/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, naersk, nixpkgs, flake-utils, flake-compat, mozillapkgs }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = nixpkgs.legacyPackages."${system}";

      # Get a specific rust version
      mozilla = pkgs.callPackage (mozillapkgs + "/package-set.nix") {};
      channel = (mozilla.rustChannelOf {
        # date = "2020-01-01"; # get the current date with `date -I`
        channel = "stable";
        sha256 = "KXx+ID0y4mg2B3LHp7IyaiMrdexF6octADnAtFIOjrY=";
      });
      rust = channel.rust;

      naersk-lib = naersk.lib."${system}".override {
        cargo = rust;
        rustc = rust;
      };
    in rec {
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
          buildInputs = [ pkgs.libsodium pkgs.lzma pkgs.openssl ];
          nativeBuildInputs = (with pkgs;
            [
              pkgconfig
              # nixpkgs-fmt
              # cargo-watch
              rust-analyzer
              # rustc
              # cargo
              rust
            ]);
          RUST_SRC_PATH = "${channel.rust-src}/lib/rustlib/src/rust/library";
        };

        # devShell =
        # # pkgs.mkShell { buildInputs = [ self.packages.${system}.rdedup ]; };
        # pkgs.mkShell {
        #   nativeBuildInputs = [ fenix.packages.${system}.stable.rustc ];
        #   buildInputs = with pkgs; [ pkgconfig libsodium lzma openssl fenix.packages.x86_64-linux.rust-analyzer ];
        # };
  });
}
