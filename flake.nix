{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    naersk = {
      url = "github:nmattia/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, fenix, naersk, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
    let pkgs = nixpkgs.legacyPackages.${system};
    in {
      packages.rdedup = (naersk.lib.${system}.override {
        inherit (fenix.packages.${system}.minimal) cargo rustc;
      }).buildPackage {
        pname = "rdedup";
        root = ./.;
      };

      defaultPackage = self.packages.${system}.rdedup;
      defaultApp = self.packages.${system}.rdedup;

      devShell =
        # pkgs.mkShell { buildInputs = [ self.packages.${system}.rdedup ]; };
        pkgs.mkShell {
          nativeBuildInputs = [ fenix.packages.${system}.minimal.rustc ];
          buildInputs = with pkgs; [ pkgconfig libsodium lzma openssl fenix.packages.x86_64-linux.rust-analyzer ];
        };
  });
}
