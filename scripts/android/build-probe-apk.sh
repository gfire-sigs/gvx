#!/usr/bin/env bash
# Builds the probe app of GVXIP-006 for android/arm64.
#
# The app packs androidprobe and rungv as native libraries, so Android
# extracts them to the native library directory, where an app may run them.
# The build uses the SDK tools only (javac, d8, aapt2, zipalign, apksigner).
#
# Usage: scripts/android/build-probe-apk.sh OUT.apk
# Needs: ANDROID_HOME, JAVA_HOME, build-tools 36.1.0, platforms;android-36.
set -euo pipefail

out=${1:?usage: build-probe-apk.sh OUT.apk}
root=$(cd "$(dirname "$0")/../.." && pwd)
sdk=${ANDROID_HOME:?set ANDROID_HOME}
bt="$sdk/build-tools/${ANDROID_BUILD_TOOLS:-36.1.0}"
jar="$sdk/platforms/${ANDROID_PLATFORM:-android-36}/android.jar"
src="$root/tools/androidprobe/apk"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/lib/arm64-v8a" "$work/classes" "$work/dex"
(
	cd "$root"
	GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o "$work/lib/arm64-v8a/libandroidprobe.so" ./tools/androidprobe
	GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o "$work/lib/arm64-v8a/librungv.so" ./cmd/rungv
)

"$JAVA_HOME/bin/javac" -nowarn -source 11 -target 11 -cp "$jar" -d "$work/classes" \
	$(find "$src/src" -name '*.java')
"$bt/d8" --min-api 31 --lib "$jar" --output "$work/dex" $(find "$work/classes" -name '*.class')

"$bt/aapt2" link -o "$work/base.apk" -I "$jar" --manifest "$src/AndroidManifest.xml"
(cd "$work/dex" && zip -q "$work/base.apk" classes.dex)
# Native libraries stay uncompressed and page-aligned for a 16 KB page device.
(cd "$work" && zip -q -0 "$work/base.apk" lib/arm64-v8a/*.so)
"$bt/zipalign" -f -P 16 4 "$work/base.apk" "$work/aligned.apk"

keystore=${PROBE_KEYSTORE:-$HOME/.android/gvx-probe.keystore}
if [ ! -f "$keystore" ]; then
	mkdir -p "$(dirname "$keystore")"
	"$JAVA_HOME/bin/keytool" -genkeypair -keystore "$keystore" -storepass android -keypass android \
		-alias probe -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=gvx probe" >/dev/null
fi
"$bt/apksigner" sign --ks "$keystore" --ks-pass pass:android --key-pass pass:android \
	--out "$out" "$work/aligned.apk"
echo "$out"
