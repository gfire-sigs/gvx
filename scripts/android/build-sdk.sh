#!/usr/bin/env bash
# Builds the Android library of GVXIP-006 and its sample app for android/arm64.
#
# OUT/gvx-android.aar holds the Java class dev.gfire.gvx.Gvx and librungv.so.
# OUT/gvx-sample.apk is the sample app, which runs one rungv command in a
# foreground service (android/sample).
#
# Usage: scripts/android/build-sdk.sh OUT_DIR
set -euo pipefail
source "$(dirname "$0")/lib.sh"

out=${1:?usage: build-sdk.sh OUT_DIR}
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

android_go_lib "$work" librungv.so ./cmd/rungv

# The library archive: classes.jar, a library manifest, and jni/<abi>/*.so.
android_javac "$work/lib-classes" "$android_root/android/library/src"
mkdir -p "$work/aar/jni/arm64-v8a"
"$JAVA_HOME/bin/jar" --create --file "$work/aar/classes.jar" -C "$work/lib-classes" .
cp "$work/lib/arm64-v8a/librungv.so" "$work/aar/jni/arm64-v8a/"
cat >"$work/aar/AndroidManifest.xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="dev.gfire.gvx">
    <uses-sdk android:minSdkVersion="31" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
</manifest>
EOF
rm -f "$out/gvx-android.aar"
(cd "$work/aar" && zip -q -r "$out/gvx-android.aar" AndroidManifest.xml classes.jar jni)

# The sample app compiles against the library sources.
android_javac "$work/sample-classes" "$android_root/android/library/src" "$android_root/android/sample/src"
android_apk "$out/gvx-sample.apk" "$android_root/android/sample/AndroidManifest.xml" "$work/sample-classes" "$work"
echo "$out/gvx-android.aar"
echo "$out/gvx-sample.apk"
