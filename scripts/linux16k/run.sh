#!/usr/bin/env bash
# Boots a Linux arm64 kernel with 16 KB pages in QEMU and runs the host
# facility report, the synthetic ELF guest probes, the systrap, hostfs, and
# ext4lite package tests, and the offline e2e test suite in it (GVXIP-006 P5).
# It builds rungv, the test binaries, the prebuilt guest probes, and the init
# program of scripts/linux16k/init.go for linux/arm64, packs them into an
# initramfs, and fails unless init prints VMSMOKE-OK.
#
# KERNEL is the path of the kernel image. Without it, the script needs Docker
# on an arm64 host, and it extracts the arm64-16k kernel of Debian trixie.
# QEMU emulates the CPU (TCG), because a KVM host CPU can lack 16 KB pages.
#
# Usage: scripts/linux16k/run.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$root"

build() { GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath "$@"; }
testbuild() { GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -trimpath -ldflags="-s -w" "$@"; }
mkdir -p "$work/root/guests"
build -ldflags="-s -w" -o "$work/root/init" scripts/linux16k/init.go
build -ldflags="-s -w" -o "$work/root/rungv" ./cmd/rungv
build -ldflags="-s -w" -o "$work/root/androidprobe" ./tools/androidprobe
build -ldflags="-s -w" -o "$work/root/guests/lockdownprobe" ./internal/lockdownprobe/cmd/lockdownprobe
ln -s /rungv "$work/root/guests/rungv"
ln -s /rungv "$work/root/guests/rungv-static"
testbuild -o "$work/root/systrap.test" ./pkg/sentry/platform/systrap
testbuild -o "$work/root/hostfs.test" ./pkg/sentry/fsimpl/hostfs
testbuild -o "$work/root/ext4lite.test" ./pkg/sentry/fsimpl/ext4lite
testbuild -o "$work/root/e2e.test" ./e2e
for g in gostatic regprobe sigframeprobe forkprobe cowprobe codewrite spareprobe membarrierprobe eintrprobe fsfeatures voltree compatprobe microbench parityprobe nodeprobe cpumaxprobe ptracegs brkgrow; do
	build -ldflags=-linkmode=internal -o "$work/root/guests/$g" "./internal/acceptprog/$g"
done
build -ldflags="-linkmode=internal -T 0x1001000" -o "$work/root/guests/brkgrow-0x1001000" ./internal/acceptprog/brkgrow
(cd "$work/root" && find . | cpio -o -H newc --quiet) | gzip -1 > "$work/initramfs.gz"

kernel=${KERNEL:-}
if [ -z "$kernel" ]; then
	# The metapackage linux-image-arm64-16k depends on the current kernel.
	docker run --rm -v "$work:/out" debian:trixie-slim sh -ec '
		apt-get -qq update
		cd /tmp
		apt-get -qq download "$(apt-cache depends linux-image-arm64-16k | sed -n "s/.*Depends: //p")"
		dpkg-deb -x linux-image-*.deb x
		cp x/boot/vmlinuz-* /out/vmlinuz'
	kernel=$work/vmlinuz
fi

# Without lpa2=off, the kernel gives user space 52 address bits. The Sentry
# then places guest memory above 48 bits, which Linux does only on request and
# which the guest Go runtime does not accept. Android devices with 16 KB pages
# have 39 or 47 bits.
timeout 3900 qemu-system-aarch64 -machine virt -accel tcg -cpu max,lpa2=off -smp 4 -m 4096 -nographic -no-reboot \
	-kernel "$kernel" -initrd "$work/initramfs.gz" \
	-append "console=ttyAMA0 rdinit=/init panic=-1 quiet" | tee "$work/console.log" | tr -d '\r'
grep -q VMSMOKE-OK "$work/console.log"
