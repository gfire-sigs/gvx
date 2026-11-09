#!/usr/bin/env bash
# Runs the Android probe and the systrap guest probes on the device that adb
# selects, as the shell user (GVXIP-006 P1-4). It builds rungv and the probe
# for the ABI of the device and the guests for Linux on the same architecture,
# pushes them to /data/local/tmp/gvx-smoke, and fails when a guest does not
# print its result.
#
# Go links android/amd64 only with cgo, so an x86_64 device needs the NDK:
# set ANDROID_NDK_HOME, or install an NDK under ANDROID_HOME/ndk.
#
# Usage: scripts/android/emulator-smoke.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
dir=/data/local/tmp/gvx-smoke

abi=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
case "$abi" in
arm64-v8a)
	arch=arm64
	android_env=(GOOS=android GOARCH=arm64 CGO_ENABLED=0)
	;;
x86_64)
	arch=amd64
	ndk=${ANDROID_NDK_HOME:-$(ls -d "${ANDROID_HOME:?set ANDROID_HOME}"/ndk/* | sort -V | tail -1)}
	host=$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64
	android_env=(GOOS=android GOARCH=amd64 CGO_ENABLED=1 "CC=$ndk/toolchains/llvm/prebuilt/$host/bin/x86_64-linux-android31-clang")
	;;
*)
	echo "unsupported ABI $abi" >&2
	exit 1
	;;
esac

cd "$root"
env "${android_env[@]}" go build -trimpath -o "$work/rungv" ./cmd/rungv
env "${android_env[@]}" go build -trimpath -o "$work/androidprobe" ./tools/androidprobe
# Each guest and the line that it prints when all its checks pass.
guests=(
	"gostatic:recover boom"
	"regprobe:REGPROBE-OK"
	"sigframeprobe:SIGFRAMEPROBE-OK"
	"forkprobe:FORKPROBE-OK"
	"cowprobe:COWPROBE-OK"
	"codewrite:CODEWRITE-OK"
	"spareprobe:SPAREPROBE-OK"
)
for g in "${guests[@]}"; do
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -o "$work/${g%%:*}" "./internal/acceptprog/${g%%:*}"
done

adb shell "rm -rf $dir && mkdir -p $dir/cache"
adb push "$work"/* "$dir/" >/dev/null
adb shell "getprop ro.build.version.release; getconf PAGE_SIZE; uname -rm"

echo "== androidprobe report"
adb shell "cd $dir && ./androidprobe report" || true

failed=0
for g in "${guests[@]}"; do
	name=${g%%:*} want=${g#*:}
	out=$(adb shell "cd $dir && HOME=$dir XDG_CACHE_HOME=$dir/cache timeout 900 ./rungv run -platform=systrap -net=none -bin ./$name 2>&1" | tr -d '\r') || true
	if grep -qF -- "$want" <<<"$out"; then
		echo "PASS $name"
	else
		echo "FAIL $name"
		echo "$out" | tail -40
		failed=1
	fi
done
exit $failed
