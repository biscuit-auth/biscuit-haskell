{ pkgs ? import <nixpkgs> {} }: with pkgs;

mkShell {
  buildInputs = [
    haskell.compiler.ghc8107
    pkg-config
    libsodium
    zlib
    haskellPackages.hlint
    haskellPackages.stylish-haskell
    cabal-install
    ghcid
  ];
}
