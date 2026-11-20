#!/bin/bash
# gvx gate G3: guest OpenGL ES 3.0 on the virtual GPU (-gpu=virgl). The script
# runs as root in a Debian trixie guest with NAT networking. It installs pinned
# Debian packages from snapshot.debian.org, builds glesprobe, and runs eglinfo
# and glesprobe without setting any Mesa override variable.
#
# Environment:
#   GVX_G3_SNAPSHOT    snapshot.debian.org time stamp, such as 20261115T000000Z
#   GVX_G3_OUT         directory for raw tool output (default /out)
#   GVX_G3_EXEC_PROBE  1 replaces the shell with glesprobe in the last step
#   GVX_GL_ROUNDS      alternating clear-and-readback rounds (optional)
#   GVX_GL_EXPECT      informational label printed by glesprobe (optional)
#
# Each result line starts with "GVX-G3 " or "GVX-GL ". The last line is
# "GVX-G3 done" unless GVX_G3_EXEC_PROBE=1.
set -u
out=${GVX_G3_OUT:-/out}
mkdir -p "$out"
step() { echo "GVX-G3 step=$1"; }

step apt
snapshot=${GVX_G3_SNAPSHOT:?GVX_G3_SNAPSHOT is not set}
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
	echo "GVX-G3 error=apt-get update failed"
	tail -n 5 "$out/apt-update.txt"
	echo "GVX-G3 done"
	exit 1
fi
if ! apt-get install -y --no-install-recommends \
	libegl-mesa0 libgl1-mesa-dri libegl-dev libgles-dev mesa-utils gcc libc6-dev \
	>"$out/apt-install.txt" 2>&1; then
	echo "GVX-G3 error=apt-get install failed"
	tail -n 5 "$out/apt-install.txt"
	echo "GVX-G3 done"
	exit 1
fi
dpkg-query -W -f='GVX-G3 package_${Package}=${Version}\n' \
	libegl-mesa0 libgl1-mesa-dri mesa-libgallium libegl1 libgles2 mesa-utils gcc

step build
cd /workspace/gpu || exit 1
gcc -O2 -Wall -Werror -o /tmp/glesprobe glesprobe.c -lEGL -lGLESv2 >"$out/gcc.txt" 2>&1 || {
	echo "GVX-G3 error=gcc failed"
	cat "$out/gcc.txt"
	echo "GVX-G3 done"
	exit 1
}

step node
echo "GVX-G3 render_node=$(stat -c '%F %t:%T %a' /dev/dri/renderD128 2>&1)"
echo "GVX-G3 sysfs_device=$(readlink -f /sys/dev/char/226:128/device 2>&1)"
echo "GVX-G3 pci_id=$(cat /sys/bus/pci/devices/0000:00:01.0/vendor /sys/bus/pci/devices/0000:00:01.0/device 2>&1 | tr '\n' ' ')"

step eglinfo
if ! command -v eglinfo >/dev/null 2>&1; then
	echo "GVX-G3 error=eglinfo missing (package $(dpkg -S bin/eglinfo 2>&1))"
	echo "GVX-G3 done"
	exit 1
fi
# Restrict to surfaceless: without -p, eglinfo exits with the count of
# unavailable platforms (Wayland and X11 fail in the headless guest).
eglinfo -B -p surfaceless >"$out/eglinfo.txt" 2>&1
echo "GVX-G3 eglinfo_exit=$?"

step probe
if [ "${GVX_G3_EXEC_PROBE:-0}" = 1 ]; then
	# The sandbox exit code is then the exit code of glesprobe
	# (TestE2EGPURendererKill/virgl). Probe errors go to standard output.
	echo "GVX-G3 exec_probe=1"
	exec /tmp/glesprobe 2>&1
fi
/tmp/glesprobe 2>"$out/glesprobe-stderr.txt"
echo "GVX-G3 probe_exit=$?"
echo "GVX-G3 done"
