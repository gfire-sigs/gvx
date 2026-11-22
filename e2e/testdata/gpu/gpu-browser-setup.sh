#!/bin/bash
# Shared GPU mode setup sourced by g2.sh and webgl-cts.sh.
# Usage: source /workspace/gpu/gpu-browser-setup.sh <mode> <out> <prefix>
_gvx_setup_mode=$1
_gvx_setup_out=$2
_gvx_setup_prefix=$3

if [ "$_gvx_setup_mode" = gpu ] || [ "$_gvx_setup_mode" = venus ]; then
	if ! dpkg -i /opt/gpu-debs/*.deb >"$_gvx_setup_out/dpkg.txt" 2>&1; then
		echo "$_gvx_setup_prefix error=dpkg failed"
		tail -n 5 "$_gvx_setup_out/dpkg.txt"
		exit 1
	fi
	dpkg-query -W -f="${_gvx_setup_prefix} package_\${Package}=\${Version}\n" mesa-vulkan-drivers mesa-libgallium vulkan-tools
	# The Vulkan loader that Chromium bundles can be older than the variable
	# VK_DRIVER_FILES, so set the older VK_ICD_FILENAMES too.
	export VK_DRIVER_FILES=/usr/share/vulkan/icd.d/virtio_icd.json
	export VK_ICD_FILENAMES=$VK_DRIVER_FILES
	echo "$_gvx_setup_prefix render_node=$(stat -c '%F %t:%T %a' /dev/dri/renderD128 2>&1)"
elif [ "$_gvx_setup_mode" = virgl ]; then
	# playwright:v1.65.1-noble already ships libegl1, libegl-mesa0,
	# libgl1-mesa-dri, and mesa-libgallium (25.2.8-0ubuntu0.24.04.4), so no
	# extra virgl .deb files are needed. Install any mounted files if present.
	if compgen -G "/opt/gpu-debs/*.deb" >/dev/null; then
		if ! dpkg -i /opt/gpu-debs/*.deb >"$_gvx_setup_out/dpkg.txt" 2>&1; then
			echo "$_gvx_setup_prefix error=dpkg failed"
			tail -n 5 "$_gvx_setup_out/dpkg.txt"
			exit 1
		fi
	fi
	dpkg-query -W -f="${_gvx_setup_prefix} package_\${Package}=\${Version}\n" mesa-libgallium libegl-mesa0 libegl1 libgl1-mesa-dri
	echo "$_gvx_setup_prefix render_node=$(stat -c '%F %t:%T %a' /dev/dri/renderD128 2>&1)"
fi
