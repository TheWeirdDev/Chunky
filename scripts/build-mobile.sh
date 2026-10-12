#!/usr/bin/env bash
# Build chunky for Android and iOS, and package each binary as dist/chunky-<target>.zip,
# the same layout as the release assets.
#
# Usage: scripts/build-mobile.sh [android|ios|all]   (default: all)
#
# Android (Linux or macOS host):
#   ANDROID_NDK   NDK install directory, e.g. /path/to/Android-SDK/ndk/30.0.16248370
#
# iOS on macOS:
#   Uses Xcode and ad-hoc signs the binary with codesign.
#
# iOS on Linux (requires THEOS):
#   THEOS_TOOLS   THEOS darwin-tools bin directory (provides ld and ar)
#   LDID          optional path to ldid, used to sign the binary
#   ENTITLEMENTS  optional entitlements plist for ldid (default: ent.xml)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
DIST="$ROOT/dist"
ANDROID_TARGET=aarch64-linux-android
IOS_TARGET=aarch64-apple-ios

usage() {
    sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

package() {
    local target=$1
    local out="$DIST/chunky-$target.zip"
    mkdir -p "$DIST"
    rm -f "$out"
    (cd "target/$target/release" && zip -q -j "$out" chunky)
    echo "Packaged $out"
}

build_android() {
    : "${ANDROID_NDK:?set ANDROID_NDK to an Android NDK directory}"
    local host_tag=linux-x86_64
    if [[ "$(uname -s)" == Darwin ]]; then
        host_tag=darwin-x86_64
    fi
    local bin="$ANDROID_NDK/toolchains/llvm/prebuilt/$host_tag/bin"
    local clang="$bin/${ANDROID_TARGET}21-clang"
    [[ -x "$clang" ]] || { echo "error: $clang not found; check ANDROID_NDK" >&2; exit 1; }

    rustup target add "$ANDROID_TARGET"
    # The linker and C compiler for the target, and the NDK tools on PATH for OpenSSL's build.
    ANDROID_NDK_HOME="$ANDROID_NDK" \
    ANDROID_NDK_ROOT="$ANDROID_NDK" \
    CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$clang" \
    CC_aarch64_linux_android="$clang" \
    AR_aarch64_linux_android="$bin/llvm-ar" \
    PATH="$bin:$PATH" \
        cargo build --release --target "$ANDROID_TARGET"
    package "$ANDROID_TARGET"
}

build_ios() {
    rustup target add "$IOS_TARGET"
    if [[ "$(uname -s)" == Darwin ]]; then
        cargo build --release --target "$IOS_TARGET"
        codesign --force -s - "target/$IOS_TARGET/release/chunky"
    else
        : "${THEOS_TOOLS:?set THEOS_TOOLS to the THEOS darwin-tools bin directory}"
        # OpenSSL's build also needs a ranlib that understands Mach-O archives.
        CARGO_TARGET_AARCH64_APPLE_IOS_LINKER="$THEOS_TOOLS/ld" \
        AR_aarch64_apple_ios="$THEOS_TOOLS/ar" \
        RANLIB="$THEOS_TOOLS/ranlib" \
            cargo build --release --target "$IOS_TARGET"
        if [[ -n "${LDID:-}" ]]; then
            "$LDID" -S"${ENTITLEMENTS:-$ROOT/ent.xml}" "target/$IOS_TARGET/release/chunky"
        fi
    fi
    package "$IOS_TARGET"
}

case "${1:-all}" in
    android) build_android ;;
    ios) build_ios ;;
    all) build_android; build_ios ;;
    -h|--help) usage ;;
    *) usage >&2; exit 2 ;;
esac
