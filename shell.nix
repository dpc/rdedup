# Run `nix-shell` to be able
# to build Grin on NixOS.
{ pkgs ? import <nixpkgs> {} }:

pkgs.stdenv.mkDerivation {
  name = "rdedup";

  buildInputs = with pkgs; [
    ncurses cmake gcc openssl libsodium lzma libsodium clang_39
    rustup
  ];

  shellHook = with pkgs; ''
      LD_LIBRARY_PATH=${ncurses}/lib/:$LD_LIBRARY_PATH
      PKG_CONFIG_PATH=${openssl.dev}/lib/pkgconfig:$PKG_CONFIG_PATH
      LD_LIBRARY_PATH=${libsodium}/lib/:$LD_LIBRARY_PATH
      LD_LIBRARY_PATH=${lzma}/lib/:$LD_LIBRARY_PATH
      LIBRARY_PATH=${zlib}/lib/:$LIBRARY_PATH
      PKG_CONFIG_PATH=${libsodium.dev}/lib/pkgconfig:$PKG_CONFIG_PATH
      PKG_CONFIG_PATH=${lzma.dev}/lib/pkgconfig:$PKG_CONFIG_PATH
      LD_LIBRARY_PATH=${llvmPackages.libclang}/lib/:$LD_LIBRARY_PATH

      export PKG_CONFIG_PATH LD_LIBRARY_PATH
  '';
}
