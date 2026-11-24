#!/bin/bash
# gvx venus guard gate: create info that the host renderer must survive. The
# script runs as root in a Debian trixie guest with NAT networking. It
# installs pinned Debian packages from snapshot.debian.org, builds vkguard,
# and runs each case of vkguard in its own process (one venus context for
# each case).
#
# Environment:
#   GVX_G1_SNAPSHOT  snapshot.debian.org time stamp, such as 20261115T000000Z
#   GVX_G1_ICD       Vulkan driver file (default: the venus driver)
#   GVX_G1_OUT       directory for raw tool output (default /out)
#
# Each result line starts with "GVX-GUARD ". Each case gives the line of
# vkguard and then "GVX-GUARD case=<case> exit=<code>". The last line is
# "GVX-GUARD done".
set -u
out=${GVX_G1_OUT:-/out}
mkdir -p "$out"
step() { echo "GVX-GUARD step=$1"; }

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
	echo "GVX-GUARD error=apt-get update failed"
	tail -n 5 "$out/apt-update.txt"
	echo "GVX-GUARD done"
	exit 1
fi
if ! apt-get install -y --no-install-recommends \
	mesa-vulkan-drivers libvulkan-dev gcc libc6-dev \
	>"$out/apt-install.txt" 2>&1; then
	echo "GVX-GUARD error=apt-get install failed"
	tail -n 5 "$out/apt-install.txt"
	echo "GVX-GUARD done"
	exit 1
fi
dpkg-query -W -f='GVX-GUARD package_${Package}=${Version}\n' mesa-vulkan-drivers libvulkan1 gcc

step build
cd /workspace/gpu || exit 1
gcc -O2 -Wall -Werror -o /tmp/vkguard vkguard.c -lvulkan >"$out/gcc.txt" 2>&1 || {
	echo "GVX-GUARD error=gcc failed"
	cat "$out/gcc.txt"
	echo "GVX-GUARD done"
	exit 1
}

step cases
export VK_DRIVER_FILES=${GVX_G1_ICD:-/usr/share/vulkan/icd.d/virtio_icd.json}
for c in $(/tmp/vkguard list); do
	# A case whose context stopped can wait for a reply that does not come.
	timeout -k 5 60 /tmp/vkguard "$c" 2>"$out/vkguard-$c-stderr.txt"
	echo "GVX-GUARD case=$c exit=$?"
done
echo "GVX-GUARD done"
