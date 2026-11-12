#!/usr/bin/env bash
# Runs the Android probe, the systrap, hostfs, and ext4lite package tests, the
# offline e2e test suite, the untrusted_app probe APK, and the sample
# foreground-service APK on the device that adb selects (GVXIP-006 P1-4).
#
# Go links android/amd64 only with cgo, so an x86_64 device needs the NDK:
# set ANDROID_NDK_HOME, or install an NDK under ANDROID_HOME/ndk. The script
# disables the Android phantom process killer during the test run and restores
# the monitor setting in its EXIT trap.
#
# Usage: scripts/android/emulator-smoke.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
cleanup() {
	rm -rf "$work"
	adb shell "rm -rf /data/local/tmp/gvx-smoke; settings delete global settings_enable_monitor_phantom_procs; device_config delete activity_manager max_phantom_processes; device_config set_sync_disabled_for_tests none" >/dev/null 2>&1 || true
	adb unroot >/dev/null 2>&1 || true
	adb wait-for-device >/dev/null 2>&1 || true
}
trap cleanup EXIT
dir=/data/local/tmp/gvx-smoke

abi=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
ANDROID_ABI=$abi
source "$(dirname "$0")/lib.sh"
android_go_env
arch=$android_arch

cd "$root"
mkdir -p "$work/bins"
env "${android_env[@]}" go build -trimpath -ldflags="-s -w" -o "$work/bins/rungv" ./cmd/rungv
env "${android_env[@]}" go build -trimpath -ldflags="-s -w" -o "$work/bins/lockdownprobe" ./internal/lockdownprobe/cmd/lockdownprobe
env "${android_env[@]}" go build -trimpath -ldflags="-s -w" -o "$work/bins/androidprobe" ./tools/androidprobe
env "${android_env[@]}" go test -c -trimpath -ldflags="-s -w" -o "$work/bins/systrap.test" ./pkg/sentry/platform/systrap
env "${android_env[@]}" go test -c -trimpath -ldflags="-s -w" -o "$work/bins/hostfs.test" ./pkg/sentry/fsimpl/hostfs
env "${android_env[@]}" go test -c -trimpath -ldflags="-s -w" -o "$work/bins/ext4lite.test" ./pkg/sentry/fsimpl/ext4lite
env "${android_env[@]}" go test -c -trimpath -ldflags="-s -w" -o "$work/bins/e2e.test" ./e2e
GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$work/bins/rungv-static" ./cmd/rungv
for g in gostatic regprobe sigframeprobe forkprobe cowprobe codewrite spareprobe membarrierprobe eintrprobe fsfeatures voltree compatprobe microbench parityprobe nodeprobe cpumaxprobe ptracegs brkgrow checkpointprobe; do
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags=-linkmode=internal -o "$work/bins/$g" "./internal/acceptprog/$g"
done
GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags="-linkmode=internal -T 0x1001000" -o "$work/bins/brkgrow-0x1001000" ./internal/acceptprog/brkgrow

adb shell "settings put global settings_enable_monitor_phantom_procs false; device_config set_sync_disabled_for_tests persistent; device_config put activity_manager max_phantom_processes 2147483647" >/dev/null 2>&1 || true
adb shell "rm -rf $dir && mkdir -p $dir/cache $dir/tmp $dir/vws"
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

run_test_suite() {
	local label=$1 bin=$2 timeout=$3 keep=${4:-0} extra=${5:-} rc=0
	echo "== $label"
	adb shell "umask 022 && cd $dir && HOME=$dir TMPDIR=$dir/tmp XDG_CACHE_HOME=$dir/cache GVX_E2E_OFFLINE=1 GVX_PREBUILT_DIR=$dir ./$bin -test.v -test.count=1 -test.timeout=$timeout $extra 2>&1" | tr -d '\r' || rc=$?
	if [ "$keep" -eq 0 ]; then
		adb shell "rm -f $dir/$bin" || true
	fi
	if [ "$rc" -eq 0 ]; then
		echo "PASS $label"
	else
		echo "FAIL $label (exit $rc)"
		failed=1
	fi
}

run_test_suite "systrap.test (shell)" systrap.test 10m
run_test_suite "ext4lite.test (shell)" ext4lite.test 10m
run_test_suite "e2e.test (shell)" e2e.test 30m 1

# Switch adbd to root only for the hostfs and overlay hard-link suites, because
# Android's shell SELinux domain denies linkat(2) on /data/local/tmp.
switch_adb_uid() {
	local want_uid=$1 mode=$2 uid=""
	adb "$mode" >/dev/null 2>&1 || return 1
	for _ in $(seq 1 30); do
		adb wait-for-device >/dev/null 2>&1 || true
		uid=$(adb shell id -u 2>/dev/null | tr -d '\r' || true)
		if [ "$uid" = "$want_uid" ]; then
			return 0
		fi
		sleep 1
	done
	return 1
}

# run_shell runs cmd in the adb shell, and it passes only when the exit status
# equals want_rc (default 0), the output holds want, and no line says FAIL. The
# pipefail option makes the status the one of adb, which returns the status of
# the remote command.
run_shell() {
	local label=$1 want=$2 cmd=$3 want_rc=${4:-0} out rc=0
	out=$(adb shell "umask 022 && cd $dir && HOME=$dir TMPDIR=$dir/tmp XDG_CACHE_HOME=$dir/cache $cmd 2>&1" | tr -d '\r') || rc=$?
	if [ "$rc" -eq "$want_rc" ] && grep -qF "$want" <<<"$out" && ! grep -qE '(^| )FAIL ' <<<"$out"; then
		echo "PASS $label"
	else
		echo "FAIL $label (exit $rc, want $want_rc)"
		echo "$out" | head -n 40
		failed=1
	fi
}

if switch_adb_uid 0 root; then
	run_shell voltree-write-hostfs "write ok" "./rungv run -platform=systrap -net=none -workspace=$dir/vws -bin=$dir/voltree -- write /workspace"
	run_shell voltree-verify-hostfs "verify ok" "./rungv run -platform=systrap -net=none -workspace=$dir/vws -bin=$dir/voltree -- verify /workspace"
	run_test_suite "hostfs.test (root)" hostfs.test 10m
	run_test_suite "e2e.test hostfs overlay (root)" e2e.test 10m 0 "'-test.run=^TestE2EOverlayUpper/.*/hostfs-(bind|volume)$'"
	adb shell "rm -rf $dir/cache $dir/tmp $dir/vws && mkdir -p $dir/cache $dir/tmp && chown -R shell:shell $dir" || true
	if ! switch_adb_uid 2000 unroot; then
		echo "FAIL adb-unroot"
		failed=1
	fi
elif [ "${CI:-}" = true ]; then
	echo "FAIL adb-root"
	failed=1
else
	echo "SKIP root-hostfs-suites (adb root unavailable on user build)"
	adb shell "rm -f $dir/hostfs.test $dir/e2e.test" || true
fi

echo "== probe APK (untrusted_app)"
ANDROID_ABI=$abi scripts/android/build-probe-apk.sh "$work/probe.apk" >/dev/null
adb install -r "$work/probe.apk" >/dev/null

app_report=$(scripts/android/run-probe.sh libandroidprobe.so report | tr -d '\r') || true
echo "$app_report"
if grep -qF "exit code 0" <<<"$app_report" && ! grep -q " FAIL " <<<"$app_report"; then
	echo "PASS app-probe-report"
else
	echo "FAIL app-probe-report"
	failed=1
fi

app_guests_out=$(scripts/android/run-probe.sh libandroidprobe.so guests @FILES@/guests | tr -d '\r') || true
if ! grep -qF "exit code 0" <<<"$app_guests_out"; then
	echo "FAIL app-probe-guests"
	echo "$app_guests_out"
	failed=1
fi

# BuildSharedPageGuestELF64 emits arm64 instructions; linux16k.yml runs
# guest-shared-page in CI, and an arm64-v8a Android target runs it here.
app_elves=(guest-pie guest-fixed-0x10000 guest-fixed-0x400000)
if [ "$abi" = arm64-v8a ]; then
	app_elves+=(guest-shared-page)
fi
for g in "${app_elves[@]}"; do
	want="$g ok"
	if [ "$g" = guest-shared-page ]; then
		want="shared-page-ok"
	fi
	out=$(scripts/android/run-probe.sh librungv.so run -platform=systrap -net=none -bin "@FILES@/guests/$g" | tr -d '\r') || true
	if grep -qF "$want" <<<"$out" && grep -qF "exit code 0" <<<"$out"; then
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
	adb logcat -d -s 'gvx:*' AndroidRuntime:E | tail -40 || true
	failed=1
fi

exit $failed
