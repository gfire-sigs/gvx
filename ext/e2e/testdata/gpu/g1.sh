#!/bin/bash
# gvx gate G1: guest Vulkan on the virtual GPU. The script runs as root in a
# Debian trixie guest with NAT networking. It installs pinned Debian packages
# from snapshot.debian.org, builds the compute probe, and runs vulkaninfo and
# the probe against one Vulkan driver file.
#
# Environment:
#   GVX_G1_SNAPSHOT  snapshot.debian.org time stamp, such as 20261115T000000Z
#   GVX_G1_ICD       Vulkan driver file (default: the venus driver)
#   GVX_G1_DEVICE    substring of the device name for the probe (default: Venus)
#   GVX_G1_OUT       directory for raw tool output (default /out)
#   GVX_G1_EXEC_PROBE  1 replaces the shell with the probe in the last step
#
# Each result line starts with "GVX-G1 " or "GVX-VK ". The last line is
# "GVX-G1 done".
set -u
out=${GVX_G1_OUT:-/out}
mkdir -p "$out"
step() { echo "GVX-G1 step=$1"; }

step apt
snapshot=${GVX_G1_SNAPSHOT:?GVX_G1_SNAPSHOT is not set}
rm -f /etc/apt/sources.list.d/*
cat >/etc/apt/sources.list.d/debian.sources <<EOF
Types: deb
URIs: http://snapshot.debian.org/archive/debian/${snapshot}/
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no
EOF
export DEBIAN_FRONTEND=noninteractive
if ! apt-get -o Acquire::Retries=3 update >"$out/apt-update.txt" 2>&1; then
	echo "GVX-G1 error=apt-get update failed"
	tail -n 5 "$out/apt-update.txt"
	echo "GVX-G1 done"
	exit 1
fi
if ! apt-get install -y --no-install-recommends \
	mesa-vulkan-drivers vulkan-tools libvulkan-dev glslang-tools gcc libc6-dev \
	>"$out/apt-install.txt" 2>&1; then
	echo "GVX-G1 error=apt-get install failed"
	tail -n 5 "$out/apt-install.txt"
	echo "GVX-G1 done"
	exit 1
fi
dpkg-query -W -f='GVX-G1 package_${Package}=${Version}\n' mesa-vulkan-drivers vulkan-tools libvulkan1 glslang-tools gcc

step build
cd /workspace/gpu || exit 1
glslangValidator -V vkcompute.comp -o /tmp/vkcompute.spv >"$out/glslang.txt" 2>&1 || {
	echo "GVX-G1 error=glslangValidator failed"
	cat "$out/glslang.txt"
	echo "GVX-G1 done"
	exit 1
}
gcc -O2 -Wall -Werror -o /tmp/vkcompute vkcompute.c -lvulkan >"$out/gcc.txt" 2>&1 || {
	echo "GVX-G1 error=gcc failed"
	cat "$out/gcc.txt"
	echo "GVX-G1 done"
	exit 1
}

step node
icd=${GVX_G1_ICD:-/usr/share/vulkan/icd.d/virtio_icd.json}
echo "GVX-G1 icd=$icd"
echo "GVX-G1 render_node=$(stat -c '%F %t:%T %a' /dev/dri/renderD128 2>&1)"
echo "GVX-G1 sysfs_device=$(readlink -f /sys/dev/char/226:128/device 2>&1)"
echo "GVX-G1 pci_id=$(cat /sys/bus/pci/devices/0000:00:01.0/vendor /sys/bus/pci/devices/0000:00:01.0/device 2>&1 | tr '\n' ' ')"

step vulkaninfo
VK_DRIVER_FILES=$icd vulkaninfo --summary >"$out/vulkaninfo.txt" 2>&1
echo "GVX-G1 vulkaninfo_exit=$?"
grep -E '^\s*(deviceName|driverName|driverInfo|apiVersion|deviceType)\s*=' "$out/vulkaninfo.txt" \
	| sed -E 's/^\s*([a-zA-Z]+)\s*=\s*/GVX-G1 vulkaninfo_\1=/'

step probe
if [ "${GVX_G1_EXEC_PROBE:-0}" = 1 ]; then
	# The sandbox exit code is then the exit code of the probe
	# (TestE2EGPURendererKill). Probe errors go to standard output.
	echo "GVX-G1 exec_probe=1"
	VK_DRIVER_FILES=$icd GVX_VK_DEVICE=${GVX_G1_DEVICE-Venus} exec /tmp/vkcompute /tmp/vkcompute.spv 2>&1
fi
VK_DRIVER_FILES=$icd GVX_VK_DEVICE=${GVX_G1_DEVICE-Venus} /tmp/vkcompute /tmp/vkcompute.spv 2>"$out/vkcompute-stderr.txt"
echo "GVX-G1 probe_exit=$?"
echo "GVX-G1 done"
