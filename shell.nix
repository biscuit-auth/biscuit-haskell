{ pkgs ? import <nixpkgs> {} }: with pkgs;

mkShell {
  buildInputs = [
    haskell.compiler.ghc8104
    haskellPackages.c2hs
    haskellPackages.stylish-haskell
    pkg-config
    libsodium
    zlib
  ];
}
