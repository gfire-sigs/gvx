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

usage() {
	cat >&2 <<'EOF'
usage: scripts/gpu/package-renderer.sh BUNDLE_DIR OUTPUT.tar.gz
EOF
}

die() {
	printf 'package-renderer: %s\n' "$1" >&2
	exit 1
}

if [[ $# -ne 2 ]]; then
	usage
	exit 2
fi

raw_bundle=$1
out_archive=$2

if [[ ! -d $raw_bundle ]]; then
	die "bundle directory does not exist: $raw_bundle"
fi

bundle_dir=$(cd -- "$raw_bundle" && pwd -P)
bundle_name=$(basename -- "$bundle_dir")
if [[ $bundle_name != "gvx-gpu-renderer" ]]; then
	die "bundle directory base name is $bundle_name, want gvx-gpu-renderer"
fi

for req in \
	"bin/gvx-gpu-renderer" \
	"lib/libvulkan.dylib" \
	"lib/libvulkan_kosmickrisp.dylib" \
	"LICENSES/INDEX.txt" \
	"BUILDINFO"; do
	if [[ ! -f "$bundle_dir/$req" ]]; then
		die "missing required bundle file: $bundle_dir/$req"
	fi
done

buildinfo="$bundle_dir/BUILDINFO"
if grep -qx 'SOURCE=homebrew unpinned' "$buildinfo"; then
	die "refusing to package an unpinned homebrew bundle ($buildinfo)"
fi
if ! grep -Eq '^SOURCE=(pinned|mesa-source)$' "$buildinfo"; then
	die "BUILDINFO must declare SOURCE=pinned or SOURCE=mesa-source ($buildinfo)"
fi

bin_count=0
while IFS= read -r -d '' f; do
	if [[ -L $f ]]; then
		die "refusing symlink in bin/: $f"
	fi
	if [[ -d $f ]]; then
		die "refusing subdirectory in bin/: $f"
	fi
	if [[ ! -f $f ]]; then
		die "refusing non-regular file in bin/: $f"
	fi
	if ! codesign --verify --strict "$f" >/dev/null 2>&1; then
		die "codesign verification failed: $f"
	fi
	bin_count=$((bin_count + 1))
done < <(find "$bundle_dir/bin" -mindepth 1 -print0)

if ((bin_count == 0)); then
	die "no files found in $bundle_dir/bin"
fi

lib_count=0
while IFS= read -r -d '' f; do
	base=$(basename -- "$f")
	if [[ $base == libX* || $base == libxcb* ]]; then
		die "refusing to package bundle with X11 library: $base"
	fi
	if [[ -L $f ]]; then
		die "refusing symlink in lib/: $f"
	fi
	if [[ -d $f ]]; then
		die "refusing subdirectory in lib/: $f"
	fi
	if [[ ! -f $f ]]; then
		die "refusing non-regular file in lib/: $f"
	fi
	if ! codesign --verify --strict "$f" >/dev/null 2>&1; then
		die "codesign verification failed: $f"
	fi
	lib_count=$((lib_count + 1))
done < <(find "$bundle_dir/lib" -mindepth 1 -print0)

if ((lib_count == 0)); then
	die "no files found in $bundle_dir/lib"
fi

cat >"$bundle_dir/README.txt" <<'EOF'
gvx-gpu-renderer: the GPU renderer process of rungv -gpu=venus (macOS 26 or later, Apple silicon).
Extract this archive in the directory that holds rungv, so that rungv finds gvx-gpu-renderer/bin/gvx-gpu-renderer.
To use another location, set GVX_GPU_RENDERER or the rungv flag -gpu-renderer to the path of bin/gvx-gpu-renderer.
EOF

find "$bundle_dir" -exec touch -h -t 202601010000.00 {} +

out_dir=$(dirname -- "$out_archive")
mkdir -p -- "$out_dir"
out_abs="$(cd -- "$out_dir" && pwd -P)/$(basename -- "$out_archive")"
parent_dir=$(dirname -- "$bundle_dir")

tmp_list=$(mktemp)
trap 'rm -f -- "$tmp_list"' EXIT
(
	cd -- "$parent_dir"
	LC_ALL=C find gvx-gpu-renderer | LC_ALL=C sort
) >"$tmp_list"

COPYFILE_DISABLE=1 tar \
	--uid 0 --gid 0 --uname root --gname wheel \
	--options gzip:!timestamp \
	--no-recursion \
	-C "$parent_dir" \
	-czf "$out_abs" \
	-T "$tmp_list"

sha=$(shasum -a 256 "$out_abs" | awk '{print $1}')
printf '%s  %s\n' "$sha" "$out_archive"
