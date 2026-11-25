#!/bin/bash
# gvx WebGL CTS guest script. It runs as root in the Playwright image with no
# network.
set -u
mode=${GVX_CTS_MODE:?GVX_CTS_MODE is not set}
out=${GVX_CTS_OUT:-/out}
mkdir -p "$out"
echo "GVX-CTS mode=$mode"

# shellcheck source=gpu-browser-setup.sh
source /workspace/gpu/gpu-browser-setup.sh "$mode" "$out" "GVX-CTS"

exec node /workspace/gpu/webgl-cts.js
