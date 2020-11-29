{ pkgs ? import <nixpkgs> {} }: with pkgs;
stdenv.mkDerivation {
  pname = "biscuit";
  version = "0.6.0";
  phases = "installPhase";
  installPhase = ''
    mkdir -p $out/lib
    cp ${./libbiscuit_auth.so} $out/lib/libbiscuit_auth.so
    chmod u+w $out/lib/libbiscuit_auth.so
    patchelf --set-rpath ${glibc}/lib $out/lib/libbiscuit_auth.so
  '';
}

