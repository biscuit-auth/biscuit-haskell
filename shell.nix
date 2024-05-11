{ pkgs ? import <nixpkgs> {} }: with pkgs;

mkShell {
  buildInputs = [
    haskell.compiler.ghc94
    haskell-language-server
    pkg-config
    libsodium
    zlib
    haskellPackages.hlint
    haskellPackages.stylish-haskell
    cabal-install
    ghcid
  ];
}
