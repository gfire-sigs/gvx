#!/usr/bin/env bash
# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

readonly script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly repo_root=$(cd -- "$script_dir/../.." && pwd -P)

probe_dir=""
cleanup() {
	if [[ -n $probe_dir && -e $probe_dir ]]; then
		rm -rf -- "$probe_dir" || true
	fi
}
trap cleanup EXIT

sw_vers || true
sysctl -n machdep.cpu.brand_string || true
system_profiler SPDisplaysDataType || true

probe_dir=$(mktemp -d "${TMPDIR:-/tmp}/gvx-metal-probe.XXXXXX")
probe_swift="$probe_dir/probe.swift"

cat >"$probe_swift" <<'EOF'
import Metal
if let d = MTLCreateSystemDefaultDevice() {
    print("metal device:", d.name, "apple7:", d.supportsFamily(.apple7))
} else {
    print("metal device: none")
}
EOF

if ! xcrun swift "$probe_swift"; then
	printf 'ci-metal-probe: xcrun swift Metal probe failed\n' >&2
fi

brew install meson ninja

out_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/gpu"
"$repo_root/scripts/gpu/build-renderer.sh" --out "$out_root"

time "$out_root/gvx-gpu-renderer/bin/gvx-gpu-renderer" --selftest
