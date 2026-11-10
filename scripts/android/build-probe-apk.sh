#!/usr/bin/env bash
# Builds the probe app of GVXIP-006 for ANDROID_ABI (default arm64-v8a). The app
# packs androidprobe and rungv as native libraries, and its instrumentation
# starts one of them as untrusted_app.
#
# Usage: scripts/android/build-probe-apk.sh OUT.apk
set -euo pipefail
source "$(dirname "$0")/lib.sh"

out=${1:?usage: build-probe-apk.sh OUT.apk}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

android_go_lib "$work" libandroidprobe.so ./tools/androidprobe
android_go_lib "$work" librungv.so ./cmd/rungv
android_javac "$work/classes" "$android_root/tools/androidprobe/apk/src"
android_apk "$out" "$android_root/tools/androidprobe/apk/AndroidManifest.xml" "$work/classes" "$work"
echo "$out"
