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

if [ "$mode" = gpu ]; then
	if ! dpkg -i /opt/gpu-debs/*.deb >"$out/dpkg.txt" 2>&1; then
		echo "GVX-G2 error=dpkg failed"
		tail -n 5 "$out/dpkg.txt"
		exit 1
	fi
	dpkg-query -W -f='GVX-G2 package_${Package}=${Version}\n' mesa-vulkan-drivers mesa-libgallium vulkan-tools
	# The Vulkan loader that Chromium bundles can be older than the variable
	# VK_DRIVER_FILES, so set the older VK_ICD_FILENAMES too.
	export VK_DRIVER_FILES=/usr/share/vulkan/icd.d/virtio_icd.json
	export VK_ICD_FILENAMES=$VK_DRIVER_FILES
	echo "GVX-G2 render_node=$(stat -c '%F %t:%T %a' /dev/dri/renderD128 2>&1)"
	vulkaninfo --summary >"$out/vulkaninfo.txt" 2>&1
	echo "GVX-G2 vulkaninfo_exit=$?"
	grep -E '^\s*(deviceName|driverInfo|apiVersion)\s*=' "$out/vulkaninfo.txt" \
		| sed -E 's/^\s*([a-zA-Z]+)\s*=\s*/GVX-G2 vulkaninfo_\1=/'
elif [ "$mode" = virgl ]; then
	# playwright:v1.65.1-noble already ships libegl1, libegl-mesa0,
	# libgl1-mesa-dri, and mesa-libgallium (25.2.8-0ubuntu0.24.04.4), so no
	# extra virgl .deb files are needed. Install any mounted files if present.
	if compgen -G "/opt/gpu-debs/*.deb" >/dev/null; then
		if ! dpkg -i /opt/gpu-debs/*.deb >"$out/dpkg.txt" 2>&1; then
			echo "GVX-G2 error=dpkg failed"
			tail -n 5 "$out/dpkg.txt"
			exit 1
		fi
	fi
	dpkg-query -W -f='GVX-G2 package_${Package}=${Version}\n' mesa-libgallium libegl-mesa0 libegl1 libgl1-mesa-dri
	echo "GVX-G2 render_node=$(stat -c '%F %t:%T %a' /dev/dri/renderD128 2>&1)"
fi

exec node /workspace/gpu/gpu-webgl.js
