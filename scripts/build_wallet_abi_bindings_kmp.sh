#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CRATE="wallet-abi-bindings"
LIB_NAME="walletabi"
OUT_BASE="target/release/walletabi"
BINDINGS_DIR="crates/wallet-abi-bindings/android_bindings/lib/src"
KMP_CONFIG="crates/wallet-abi-bindings/uniffi.kotlin-multiplatform.toml"

find_objdump() {
  if command -v llvm-objdump >/dev/null 2>&1; then
    echo "llvm-objdump"
    return 0
  fi
  if command -v objdump >/dev/null 2>&1; then
    echo "objdump"
    return 0
  fi
  return 1
}

extract_uniffi_contract_version() {
  local objdump_bin="$1"
  local lib_path="$2"
  local symbol_addr start_addr stop_addr hex_value dec_value

  symbol_addr="$("$objdump_bin" -t "$lib_path" 2>/dev/null | awk '/ffi_walletabi_uniffi_contract_version$/ { print $1; exit }')"
  if [ -z "${symbol_addr:-}" ]; then
    return 1
  fi

  start_addr="0x${symbol_addr#0x}"
  stop_addr=$(printf "0x%x" "$((16#${symbol_addr#0x} + 0x10))")

  hex_value="$("$objdump_bin" -d --start-address="$start_addr" --stop-address="$stop_addr" "$lib_path" 2>/dev/null \
    | sed -nE 's/.*mov[[:space:]]+w0, #0x([0-9a-fA-F]+).*/\1/p' \
    | head -n1)"
  if [ -n "${hex_value:-}" ]; then
    printf "%s\n" "$((16#$hex_value))"
    return 0
  fi

  dec_value="$("$objdump_bin" -d --start-address="$start_addr" --stop-address="$stop_addr" "$lib_path" 2>/dev/null \
    | sed -nE 's/.*mov[[:space:]]+w0, #([0-9]+).*/\1/p' \
    | head -n1)"
  if [ -n "${dec_value:-}" ]; then
    printf "%s\n" "$dec_value"
    return 0
  fi

  return 1
}

align_kotlin_contract_versions() {
  local contract_version="$1"
  shift
  local file
  for file in "$@"; do
    [ -f "$file" ] || continue
    perl -0pi -e "s/val bindingsContractVersion = \\d+/val bindingsContractVersion = ${contract_version}/g" "$file"
  done
}

for cmd in cargo gobley-uniffi-bindgen; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
done

if ! command -v cargo-ndk >/dev/null 2>&1 && ! command -v cargo >/dev/null 2>&1; then
  echo "Missing cargo/cargo-ndk" >&2
  exit 1
fi

# iOS libs
IPHONEOS_DEPLOYMENT_TARGET=12.0 MACOSX_DEPLOYMENT_TARGET=11.0 cargo build --release --target aarch64-apple-ios -p "$CRATE"
IPHONEOS_DEPLOYMENT_TARGET=12.0 MACOSX_DEPLOYMENT_TARGET=11.0 cargo build --release --target aarch64-apple-ios-sim -p "$CRATE"
IPHONEOS_DEPLOYMENT_TARGET=12.0 MACOSX_DEPLOYMENT_TARGET=11.0 cargo build --release --target x86_64-apple-ios -p "$CRATE"

mkdir -p target/lipo-ios-sim/release
lipo \
  target/aarch64-apple-ios-sim/release/lib${LIB_NAME}.a \
  target/x86_64-apple-ios/release/lib${LIB_NAME}.a \
  -create -output target/lipo-ios-sim/release/lib${LIB_NAME}.a

# Android shared libs
cargo ndk -t aarch64-linux-android -o "$OUT_BASE/android/jniLibs" build -p "$CRATE"
cargo ndk -t armv7-linux-androideabi -o "$OUT_BASE/android/jniLibs" build -p "$CRATE"
cargo ndk -t i686-linux-android -o "$OUT_BASE/android/jniLibs" build -p "$CRATE"
cargo ndk -t x86_64-linux-android -o "$OUT_BASE/android/jniLibs" build -p "$CRATE"

# JVM native lib (macOS arm64)
MACOSX_DEPLOYMENT_TARGET=11.0 cargo build --release --target aarch64-apple-darwin -p "$CRATE"

# Generate Kotlin MPP bindings from the iOS static library
gobley-uniffi-bindgen \
  --config "$KMP_CONFIG" \
  --library "target/aarch64-apple-ios/release/lib${LIB_NAME}.a" \
  --out-dir "$OUT_BASE/kotlin-multiplatform"

mkdir -p "$BINDINGS_DIR"
cp -a "$OUT_BASE/kotlin-multiplatform"/* "$BINDINGS_DIR"/

# Keep generated Kotlin bindings in lockstep with the compiled Rust scaffolding.
# gobley-uniffi-bindgen may be on a different UniFFI contract than the Rust crate.
OBJ_DUMP_BIN="$(find_objdump || true)"
ANDROID_LIB="$OUT_BASE/android/jniLibs/arm64-v8a/lib${LIB_NAME}.so"
if [ -n "$OBJ_DUMP_BIN" ] && [ -f "$ANDROID_LIB" ]; then
  if CONTRACT_VERSION="$(extract_uniffi_contract_version "$OBJ_DUMP_BIN" "$ANDROID_LIB")"; then
    align_kotlin_contract_versions "$CONTRACT_VERSION" \
      "$BINDINGS_DIR/androidMain/kotlin/walletabi/walletabi.android.kt" \
      "$BINDINGS_DIR/jvmMain/kotlin/walletabi/walletabi.jvm.kt"
    echo "Aligned Kotlin bindings UniFFI contract version to ${CONTRACT_VERSION}."
  else
    echo "WARN: Could not infer UniFFI contract version from ${ANDROID_LIB}; leaving generated Kotlin contract unchanged." >&2
  fi
else
  echo "WARN: objdump unavailable or ${ANDROID_LIB} missing; leaving generated Kotlin contract unchanged." >&2
fi

# Keep compatibility with cinterop definitions expecting walletabiFFI.h.
if [ -f "$BINDINGS_DIR/nativeInterop/cinterop/headers/walletabi/walletabi.h" ]; then
  cp "$BINDINGS_DIR/nativeInterop/cinterop/headers/walletabi/walletabi.h" \
     "$BINDINGS_DIR/nativeInterop/cinterop/headers/walletabi/walletabiFFI.h"
fi

mkdir -p "$BINDINGS_DIR/androidMain/jniLibs"
cp -a "$OUT_BASE/android/jniLibs"/* "$BINDINGS_DIR/androidMain/jniLibs/"

mkdir -p "$BINDINGS_DIR/libs/ios-arm64"
mkdir -p "$BINDINGS_DIR/libs/ios-simulator-arm64"
cp "target/aarch64-apple-ios/release/lib${LIB_NAME}.a" "$BINDINGS_DIR/libs/ios-arm64/"
cp "target/lipo-ios-sim/release/lib${LIB_NAME}.a" "$BINDINGS_DIR/libs/ios-simulator-arm64/"

mkdir -p "$BINDINGS_DIR/jvmMain/resources/darwin-aarch64"
cp "target/aarch64-apple-darwin/release/lib${LIB_NAME}.dylib" "$BINDINGS_DIR/jvmMain/resources/darwin-aarch64/"

echo "wallet-abi KMP bindings generated under $BINDINGS_DIR"
