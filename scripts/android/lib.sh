# Shared steps of the Android builds of GVXIP-006. Source this file.
#
# The builds use the SDK tools only: javac, d8, aapt2, zipalign, apksigner.
# Needs: ANDROID_HOME, JAVA_HOME, build-tools 36.1.0, platforms;android-36.

android_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
android_sdk=${ANDROID_HOME:?set ANDROID_HOME}
android_bt="$android_sdk/build-tools/${ANDROID_BUILD_TOOLS:-36.1.0}"
android_jar="$android_sdk/platforms/${ANDROID_PLATFORM:-android-36}/android.jar"

# android_go_lib DIR NAME PKG builds the Go command PKG for android/arm64 as
# DIR/lib/arm64-v8a/NAME, so Android extracts it to the native library
# directory, where an app may run it.
android_go_lib() {
	mkdir -p "$1/lib/arm64-v8a"
	(cd "$android_root" && GOOS=android GOARCH=arm64 CGO_ENABLED=0 \
		go build -trimpath -o "$1/lib/arm64-v8a/$2" "$3")
}

# android_javac OUT SRC... compiles the Java sources under each SRC to OUT.
android_javac() {
	local out=$1
	shift
	mkdir -p "$out"
	"$JAVA_HOME/bin/javac" -nowarn -source 11 -target 11 -cp "$android_jar" -d "$out" \
		$(find "$@" -name '*.java')
}

# android_apk OUT.apk MANIFEST CLASSES WORK packs an APK from a manifest, a
# class directory, and the native libraries under WORK/lib, and signs it.
android_apk() {
	local out=$1 manifest=$2 classes=$3 work=$4
	mkdir -p "$work/dex"
	"$android_bt/d8" --min-api 31 --lib "$android_jar" --output "$work/dex" \
		$(find "$classes" -name '*.class')
	"$android_bt/aapt2" link -o "$work/base.apk" -I "$android_jar" --manifest "$manifest"
	(cd "$work/dex" && zip -q "$work/base.apk" classes.dex)
	# Native libraries stay uncompressed and page-aligned for a 16 KB page device.
	(cd "$work" && zip -q -0 "$work/base.apk" lib/arm64-v8a/*.so)
	"$android_bt/zipalign" -f -P 16 4 "$work/base.apk" "$work/aligned.apk"
	local keystore=${ANDROID_KEYSTORE:-$HOME/.android/gvx-debug.keystore}
	if [ ! -f "$keystore" ]; then
		mkdir -p "$(dirname "$keystore")"
		"$JAVA_HOME/bin/keytool" -genkeypair -keystore "$keystore" -storepass android \
			-keypass android -alias gvx -keyalg RSA -keysize 2048 -validity 10000 \
			-dname "CN=gvx debug" >/dev/null
	fi
	"$android_bt/apksigner" sign --ks "$keystore" --ks-pass pass:android \
		--key-pass pass:android --out "$out" "$work/aligned.apk"
}
