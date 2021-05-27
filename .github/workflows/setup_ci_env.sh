#!/usr/bin/env bash

set -euo pipefail

CI_OS=$(uname -s)

install_deps_linux() {
  echo "Setting up the environment for linux"
  sudo apt-get update && sudo apt install -y libsodium-dev
  echo "$HOME/.ghcup/bin" >> "$GITHUB_PATH"
  echo "HOME/.cabal/bin" >> "$GITHUB_PATH"
  echo "HOME/.local/bin" >> "$GITHUB_PATH"
}

install_deps_darwin() {
  echo "Setting up the environment for macOS"
  brew update
  brew install libsodium
}

case $CI_OS in
  Linux) install_deps_linux;;
  Darwin) install_deps_darwin;;
esac

cabal install c2hs
