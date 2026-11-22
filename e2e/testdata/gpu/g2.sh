#!/bin/bash
# gvx gate G2 guest script. It runs as root in the Phase 0 Playwright image
# with no network.
#
# Environment:
#   GVX_G2_MODE  "gpu" installs the pinned Mesa Vulkan packages from
#                /opt/gpu-debs, pins the venus driver, and checks it with
#                vulkaninfo first. "virgl" uses the Mesa EGL and gallium
#                packages already installed in the browser image
#                (mesa-libgallium, libegl-mesa0, libegl1, libgl1-mesa-dri),
#                installing any optional .deb files in /opt/gpu-debs if present.
#                "swiftshader" runs the reference pass.
#   GVX_G2_ARGS  Chromium flags (passed to gpu-webgl.js)
#   GVX_G2_OUT   output directory (passed to gpu-webgl.js)
#
# Each result line starts with "GVX-G2 ", "GVX-WEBGL ", or "GVX-VK". The
# last line is "GVX-G2 done" (printed by gpu-webgl.js) or an error line.
set -u
mode=${GVX_G2_MODE:?GVX_G2_MODE is not set}
out=${GVX_G2_OUT:?GVX_G2_OUT is not set}
mkdir -p "$out"
echo "GVX-G2 mode=$mode"

# shellcheck source=gpu-browser-setup.sh
source /workspace/gpu/gpu-browser-setup.sh "$mode" "$out" "GVX-G2"

if [ "$mode" = gpu ]; then
	vulkaninfo --summary >"$out/vulkaninfo.txt" 2>&1
	echo "GVX-G2 vulkaninfo_exit=$?"
	grep -E '^\s*(deviceName|driverInfo|apiVersion)\s*=' "$out/vulkaninfo.txt" \
		| sed -E 's/^\s*([a-zA-Z]+)\s*=\s*/GVX-G2 vulkaninfo_\1=/'
fi

exec node /workspace/gpu/gpu-webgl.js
