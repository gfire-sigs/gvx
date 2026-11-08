#!/usr/bin/env bash
# Runs the Android probe and the systrap guest probes on the device that adb
# selects, as the shell user (GVXIP-006 P1-4). It builds rungv and the probe
# for android/arm64 and the guests for linux/arm64, pushes them to
# /data/local/tmp/gvx-smoke, and fails when a guest does not print its result.
#
# Usage: scripts/android/emulator-smoke.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
dir=/data/local/tmp/gvx-smoke

cd "$root"
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o "$work/rungv" ./cmd/rungv
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o "$work/androidprobe" ./tools/androidprobe
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
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o "$work/${g%%:*}" "./internal/acceptprog/${g%%:*}"
done

adb shell "rm -rf $dir && mkdir -p $dir/cache"
adb push "$work"/* "$dir/" >/dev/null
adb shell "getprop ro.build.version.release; getconf PAGE_SIZE; uname -r"

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
