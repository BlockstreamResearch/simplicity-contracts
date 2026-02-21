#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

"$ROOT_DIR/scripts/build_wallet_abi_bindings_kmp.sh"

if [ -x "$ROOT_DIR/crates/wallet-abi-bindings/android_bindings/gradlew" ]; then
  "$ROOT_DIR/crates/wallet-abi-bindings/android_bindings/gradlew" -p "$ROOT_DIR/crates/wallet-abi-bindings/android_bindings" :lib:publishToMavenLocal
else
  gradle -p "$ROOT_DIR/crates/wallet-abi-bindings/android_bindings" :lib:publishToMavenLocal
fi

