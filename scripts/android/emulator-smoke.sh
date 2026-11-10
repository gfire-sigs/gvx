#!/usr/bin/env bash
# Runs the Android probe, the systrap guest probes, the untrusted_app probe APK,
# and the sample foreground-service APK on the device that adb selects
# (GVXIP-006 P1-4).
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
mkdir -p "$work/bins"
env "${android_env[@]}" go build -trimpath -o "$work/bins/rungv" ./cmd/rungv
env "${android_env[@]}" go build -trimpath -o "$work/bins/androidprobe" ./tools/androidprobe
for g in gostatic regprobe sigframeprobe forkprobe cowprobe codewrite spareprobe membarrierprobe eintrprobe fsfeatures voltree; do
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags=-linkmode=internal -o "$work/bins/$g" "./internal/acceptprog/$g"
done
GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags="-linkmode=internal -T 0x1001000" -o "$work/bins/brkgrow" ./internal/acceptprog/brkgrow

adb shell "rm -rf $dir && mkdir -p $dir/cache $dir/tmp $dir/cws $dir/fsws $dir/vws"
adb push "$work/bins"/* "$dir/" >/dev/null
adb shell "getprop ro.build.version.release; getconf PAGE_SIZE; uname -rm"

failed=0

echo "== androidprobe report (shell)"
report_out=$(adb shell "cd $dir && ./androidprobe report 2>&1" | tr -d '\r') || failed=1
echo "$report_out"
if grep -q " FAIL " <<<"$report_out" || ! grep -q "^mmap_min_addr " <<<"$report_out"; then
	echo "FAIL androidprobe-report-shell"
	failed=1
else
	echo "PASS androidprobe-report-shell"
fi

# run_guest LABEL WANT ARG... runs rungv with ARG... as shell and checks that
# it exits with 0, prints no FAIL line, and prints each "|"-separated pattern
# of WANT.
run_guest() {
	local label=$1 want=$2 out rc=0 pat
	shift 2
	out=$(adb shell "cd $dir && HOME=$dir TMPDIR=$dir/tmp XDG_CACHE_HOME=$dir/cache timeout 900 ./rungv run -platform=systrap -net=none $* 2>&1" | tr -d '\r') || rc=$?
	local ok=1
	if [ "$rc" -ne 0 ] || grep -qE '(^|\n)FAIL ' <<<"$out"; then
		ok=0
	fi
	IFS='|' read -ra pats <<<"$want"
	for pat in "${pats[@]}"; do
		if ! grep -qF -- "$pat" <<<"$out"; then
			ok=0
		fi
	done
	if [ "$ok" -eq 1 ]; then
		echo "PASS $label"
	else
		echo "FAIL $label (exit $rc)"
		echo "$out" | tail -40
		failed=1
	fi
}

echo "== guest probes (shell)"
run_guest gostatic "recover boom" -bin ./gostatic
run_guest regprobe "REGPROBE-OK" -bin ./regprobe
run_guest sigframeprobe "SIGFRAMEPROBE-OK" -bin ./sigframeprobe
run_guest forkprobe "FORKPROBE-OK" -bin ./forkprobe
run_guest cowprobe "COWPROBE-OK" -bin ./cowprobe
run_guest spareprobe "SPAREPROBE-OK" -bin ./spareprobe
run_guest brkgrow "brk grew 1024 MiB" -bin ./brkgrow
run_guest membarrierprobe "DONE" -bin ./membarrierprobe checks
run_guest eintrprobe "DONE" -bin ./eintrprobe checks 10
run_guest codewrite "PASS shared-file-writes:/workspace|PASS shared-file-writes:/mnt|CODEWRITE-OK" \
	"-workspace=$dir/cws" "--mount=type=volume,src=$dir/cvol.ext4,dst=/mnt,driver=ext4lite" \
	-bin ./codewrite dir=/workspace dir=/mnt
run_guest fsfeatures-hostfs "hostfs ok" "-workspace=$dir/fsws" -bin ./fsfeatures hostfs /workspace
run_guest fsfeatures-ext4lite "ext4lite ok" "--mount=type=volume,src=$dir/fsvol.ext4,dst=/mnt,driver=ext4lite" \
	-bin ./fsfeatures ext4lite /mnt
run_guest voltree-write-hostfs "write ok" "-workspace=$dir/vws" -bin ./voltree write /workspace
run_guest voltree-verify-hostfs "verify ok" "-workspace=$dir/vws" -bin ./voltree verify /workspace
run_guest voltree-write-ext4lite "write ok" "--mount=type=volume,src=$dir/vvol.ext4,dst=/mnt,driver=ext4lite" \
	-bin ./voltree write /mnt
run_guest voltree-verify-ext4lite "verify ok" "--mount=type=volume,src=$dir/vvol.ext4,dst=/mnt,driver=ext4lite" \
	-bin ./voltree verify /mnt

echo "== probe APK (untrusted_app)"
ANDROID_ABI=$abi scripts/android/build-probe-apk.sh "$work/probe.apk" >/dev/null
adb install -r "$work/probe.apk" >/dev/null

app_report=$(scripts/android/run-probe.sh libandroidprobe.so report | tr -d '\r')
echo "$app_report"
if grep -qF "exit code 0" <<<"$app_report" && ! grep -q " FAIL " <<<"$app_report"; then
	echo "PASS app-probe-report"
else
	echo "FAIL app-probe-report"
	failed=1
fi

app_guests_out=$(scripts/android/run-probe.sh libandroidprobe.so guests @FILES@/guests | tr -d '\r')
if ! grep -qF "exit code 0" <<<"$app_guests_out"; then
	echo "FAIL app-probe-guests"
	echo "$app_guests_out"
	failed=1
fi

app_elves=(guest-pie guest-fixed-0x10000 guest-fixed-0x400000)
if [ "$abi" = arm64-v8a ]; then
	app_elves+=(guest-shared-page)
fi
for g in "${app_elves[@]}"; do
	out=$(scripts/android/run-probe.sh librungv.so run -platform=systrap -net=none -bin "@FILES@/guests/$g" | tr -d '\r')
	if grep -qF "$g ok" <<<"$out" && grep -qF "exit code 0" <<<"$out"; then
		echo "PASS app-$g"
	else
		echo "FAIL app-$g"
		echo "$out"
		failed=1
	fi
done

echo "== sample foreground service APK (untrusted_app)"
ANDROID_ABI=$abi scripts/android/build-sdk.sh "$work/sdk" >/dev/null
adb install -r "$work/sdk/gvx-sample.apk" >/dev/null
adb shell "cat $dir/gostatic | run-as dev.gfire.gvx.sample sh -c 'mkdir -p files && rm -f files/run.log && cat > files/gostatic && chmod 755 files/gostatic'"
adb shell am start-foreground-service -n dev.gfire.gvx.sample/.RunService \
	--esa args run,-platform=systrap,-net=none,-bin,./gostatic >/dev/null

svc_log=""
for _ in $(seq 1 60); do
	svc_log=$(adb shell "run-as dev.gfire.gvx.sample cat files/run.log 2>/dev/null" | tr -d '\r' || true)
	if grep -q '^exit ' <<<"$svc_log"; then
		break
	fi
	sleep 1
done
if grep -qF "recover boom" <<<"$svc_log" && grep -qx "exit 0" <<<"$svc_log"; then
	echo "PASS sample-service-gostatic"
else
	echo "FAIL sample-service-gostatic"
	echo "$svc_log"
	adb logcat -d -s gvx:* AndroidRuntime:E | tail -40 || true
	failed=1
fi

exit $failed
