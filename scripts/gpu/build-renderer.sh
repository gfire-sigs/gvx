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

out_dir="$repo_root/build/gpu"
offline=0
driver_source="${GVX_GPU_DRIVER_SOURCE:-pinned}"
bottle_tag=""

VIRGLRENDERER_URL=""
VIRGLRENDERER_COMMIT=""
VENUS_PROTOCOL_URL=""
VENUS_PROTOCOL_COMMIT=""
LIBEPOXY_URL=""
LIBEPOXY_COMMIT=""
PYTHON_REQUIREMENTS=""
MESA_VERSION=""
MESA_BOTTLE_SHA256=""
DRIVER_SOURCE_VERSION=""
DRIVER_SOURCE_SHA256=""
DRIVER_SOURCE_PYTHON_REQUIREMENTS=""
TOOLCHAIN_LLVM_VERSION=""
TOOLCHAIN_LIBCLC_VERSION=""
TOOLCHAIN_SPIRV_LLVM_TRANSLATOR_VERSION=""
TOOLCHAIN_SPIRV_TOOLS_VERSION=""

readonly DRIVER_STAGE_MANIFEST=".gvx-stage.sha256"

DRIVER_STAGE_DIR=""
DRIVER_LIB=""
VK_INCLUDE=""

cache_dir=""
work_dir=""
meson_dir=""
epoxy_build=""
epoxy_prefix=""
bundle_dir=""
venv_python=""
tmp_paths=()

cleanup() {
	local status=$?
	trap - EXIT
	local p
	for p in "${tmp_paths[@]+"${tmp_paths[@]}"}"; do
		if [[ -e $p ]]; then
			rm -rf -- "$p" || true
		fi
	done
	exit "$status"
}
trap cleanup EXIT

usage() {
	cat >&2 <<'EOF'
usage: scripts/gpu/build-renderer.sh [--out DIR] [--offline] [--driver-source pinned|homebrew|mesa-source]
  --out DIR                                    output directory (default: build/gpu under the repository root)
  --offline                                    fail instead of starting a download
  --driver-source pinned|homebrew|mesa-source  driver source (default: pinned, or GVX_GPU_DRIVER_SOURCE)
EOF
}

die() {
	printf 'build-renderer: %s\n' "$1" >&2
	exit 1
}

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		die "required command not found: $1"
	fi
}

version_ge() {
	local have=$1 want=$2
	local h1 h2 h3 w1 w2 w3
	IFS=. read -r h1 h2 h3 _ <<<"${have%%-*}"
	IFS=. read -r w1 w2 w3 _ <<<"$want"
	h2=${h2:-0}
	h3=${h3:-0}
	w2=${w2:-0}
	w3=${w3:-0}
	if [[ ! $h1 =~ ^[0-9]+$ || ! $h2 =~ ^[0-9]+$ || ! $h3 =~ ^[0-9]+$ ]]; then
		return 1
	fi
	if ((h1 != w1)); then
		((h1 > w1))
		return
	fi
	if ((h2 != w2)); then
		((h2 > w2))
		return
	fi
	((h3 >= w3))
}

step_args_and_host() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--out)
			if [[ $# -lt 2 ]]; then
				usage
				exit 2
			fi
			out_dir=$2
			shift 2
			;;
		--driver-source)
			if [[ $# -lt 2 ]]; then
				usage
				exit 2
			fi
			driver_source=$2
			shift 2
			;;
		--offline)
			offline=1
			shift
			;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			usage
			exit 2
			;;
		esac
	done

	case "$driver_source" in
	pinned | homebrew | mesa-source) ;;
	*) die "invalid --driver-source: $driver_source (want pinned, homebrew, or mesa-source)" ;;
	esac

	if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
		die "gvx-gpu-renderer builds only on darwin/arm64"
	fi

	if [[ $driver_source == "pinned" ]]; then
		local macos_ver macos_major
		macos_ver=$(sw_vers -productVersion)
		macos_major=${macos_ver%%.*}
		case "$macos_major" in
		26) bottle_tag="arm64_tahoe" ;;
		27) bottle_tag="arm64_golden_gate" ;;
		*) die "no pinned KosmicKrisp bottles for macOS $macos_ver (need 26 or 27)" ;;
		esac
	elif [[ $driver_source == "mesa-source" ]]; then
		bottle_tag="mesa-source"
	else
		bottle_tag="homebrew"
		printf 'build-renderer: driver from the local Homebrew installation; not pinned, for local builds only\n' >&2
	fi

	local cmd
	for cmd in git curl shasum tar meson ninja cc install_name_tool codesign otool rsync pkg-config; do
		require_cmd "$cmd"
	done
	if [[ $driver_source == "homebrew" ]]; then
		require_cmd brew
	elif [[ $driver_source == "mesa-source" ]]; then
		for cmd in cmake brew; do
			require_cmd "$cmd"
		done
		local llvm_prefix
		if llvm_prefix=$(brew --prefix llvm 2>/dev/null) && [[ -d "$llvm_prefix/bin" ]]; then
			export PATH="$llvm_prefix/bin:$PATH"
		fi
		require_cmd llvm-config
	fi

	local meson_ver
	meson_ver=$(meson --version)
	if [[ $driver_source == "mesa-source" ]]; then
		if ! version_ge "$meson_ver" "1.9.1"; then
			die "meson >= 1.9.1 required for mesa-source, found $meson_ver"
		fi
		local llvm_ver
		llvm_ver=$(llvm-config --version)
		if ! version_ge "$llvm_ver" "20.1.8"; then
			die "llvm-config >= 20.1.8 required for mesa-source, found $llvm_ver"
		fi
	else
		if ! version_ge "$meson_ver" "1.3.0"; then
			die "meson >= 1.3.0 required, found $meson_ver"
		fi
	fi

	mkdir -p -- "$out_dir"
	out_dir=$(cd -- "$out_dir" && pwd -P)
	cache_dir="$out_dir/cache"
	work_dir="$out_dir/work/gpurenderer"
	meson_dir="$out_dir/meson"
	bundle_dir="$out_dir/gvx-gpu-renderer"
	mkdir -p -- "$cache_dir"
}

step_lock_file() {
	local lock_file="$repo_root/ext/workers/gpu-renderer/third_party.lock"
	if [[ ! -f $lock_file ]]; then
		die "missing lock file: $lock_file"
	fi

	local mesa_hash_key="BOTTLE.mesa.${bottle_tag}"
	local line key val
	while IFS= read -r line || [[ -n $line ]]; do
		if [[ -z $line || $line == \#* ]]; then
			continue
		fi
		if [[ $line != *=* ]]; then
			die "malformed line in $lock_file: $line"
		fi
		key=${line%%=*}
		val=${line#*=}
		case "$key" in
		VIRGLRENDERER_URL)
			[[ -z $VIRGLRENDERER_URL ]] || die "duplicate key in $lock_file: $key"
			VIRGLRENDERER_URL=$val
			;;
		VIRGLRENDERER_COMMIT)
			[[ -z $VIRGLRENDERER_COMMIT ]] || die "duplicate key in $lock_file: $key"
			VIRGLRENDERER_COMMIT=$val
			;;
		VENUS_PROTOCOL_URL)
			[[ -z $VENUS_PROTOCOL_URL ]] || die "duplicate key in $lock_file: $key"
			VENUS_PROTOCOL_URL=$val
			;;
		VENUS_PROTOCOL_COMMIT)
			[[ -z $VENUS_PROTOCOL_COMMIT ]] || die "duplicate key in $lock_file: $key"
			VENUS_PROTOCOL_COMMIT=$val
			;;
		LIBEPOXY_URL)
			[[ -z $LIBEPOXY_URL ]] || die "duplicate key in $lock_file: $key"
			LIBEPOXY_URL=$val
			;;
		LIBEPOXY_COMMIT)
			[[ -z $LIBEPOXY_COMMIT ]] || die "duplicate key in $lock_file: $key"
			LIBEPOXY_COMMIT=$val
			;;
		PYTHON_REQUIREMENTS)
			[[ -z $PYTHON_REQUIREMENTS ]] || die "duplicate key in $lock_file: $key"
			PYTHON_REQUIREMENTS=$val
			;;
		BOTTLE.mesa.version)
			[[ -z $MESA_VERSION ]] || die "duplicate key in $lock_file: $key"
			MESA_VERSION=$val
			;;
		"$mesa_hash_key")
			[[ -z $MESA_BOTTLE_SHA256 ]] || die "duplicate key in $lock_file: $key"
			MESA_BOTTLE_SHA256=$val
			;;
		DRIVER_SOURCE_VERSION)
			[[ -z $DRIVER_SOURCE_VERSION ]] || die "duplicate key in $lock_file: $key"
			DRIVER_SOURCE_VERSION=$val
			;;
		DRIVER_SOURCE_SHA256)
			[[ -z $DRIVER_SOURCE_SHA256 ]] || die "duplicate key in $lock_file: $key"
			DRIVER_SOURCE_SHA256=$val
			;;
		DRIVER_SOURCE_PYTHON_REQUIREMENTS)
			[[ -z $DRIVER_SOURCE_PYTHON_REQUIREMENTS ]] || die "duplicate key in $lock_file: $key"
			DRIVER_SOURCE_PYTHON_REQUIREMENTS=$val
			;;
		TOOLCHAIN.llvm.version)
			[[ -z $TOOLCHAIN_LLVM_VERSION ]] || die "duplicate key in $lock_file: $key"
			TOOLCHAIN_LLVM_VERSION=$val
			;;
		TOOLCHAIN.libclc.version)
			[[ -z $TOOLCHAIN_LIBCLC_VERSION ]] || die "duplicate key in $lock_file: $key"
			TOOLCHAIN_LIBCLC_VERSION=$val
			;;
		TOOLCHAIN.spirv-llvm-translator.version)
			[[ -z $TOOLCHAIN_SPIRV_LLVM_TRANSLATOR_VERSION ]] || die "duplicate key in $lock_file: $key"
			TOOLCHAIN_SPIRV_LLVM_TRANSLATOR_VERSION=$val
			;;
		TOOLCHAIN.spirv-tools.version)
			[[ -z $TOOLCHAIN_SPIRV_TOOLS_VERSION ]] || die "duplicate key in $lock_file: $key"
			TOOLCHAIN_SPIRV_TOOLS_VERSION=$val
			;;
		BOTTLE.* | DRIVER_*)
			;;
		*)
			die "unknown key in $lock_file: $key"
			;;
		esac
	done <"$lock_file"

	local required_keys=(
		VIRGLRENDERER_URL
		VIRGLRENDERER_COMMIT
		VENUS_PROTOCOL_URL
		VENUS_PROTOCOL_COMMIT
		LIBEPOXY_URL
		LIBEPOXY_COMMIT
		PYTHON_REQUIREMENTS
	)
	if [[ $driver_source == "pinned" ]]; then
		required_keys+=(MESA_VERSION MESA_BOTTLE_SHA256)
	elif [[ $driver_source == "mesa-source" ]]; then
		required_keys+=(
			DRIVER_SOURCE_VERSION
			DRIVER_SOURCE_SHA256
			DRIVER_SOURCE_PYTHON_REQUIREMENTS
			TOOLCHAIN_LLVM_VERSION
			TOOLCHAIN_LIBCLC_VERSION
			TOOLCHAIN_SPIRV_LLVM_TRANSLATOR_VERSION
			TOOLCHAIN_SPIRV_TOOLS_VERSION
		)
	fi
	for key in "${required_keys[@]}"; do
		if [[ -z ${!key} ]]; then
			die "missing key in $lock_file: $key"
		fi
	done
}

verify_brew_formula_version() {
	local formula=$1 want=$2
	local ver_line
	ver_line=$(brew list --versions "$formula" 2>/dev/null || true)
	if [[ -z $ver_line ]]; then
		die "homebrew formula $formula is not installed (want $want from ext/workers/gpu-renderer/third_party.lock)"
	fi
	local parts=()
	read -r -a parts <<<"$ver_line"
	local actual=""
	if [[ ${parts[0]} != "$formula" ]]; then
		die "unexpected brew list --versions output for $formula: $ver_line"
	fi
	if ((${#parts[@]} == 2)); then
		actual=${parts[1]}
	elif ((${#parts[@]} > 2)); then
		local keg_dir
		keg_dir=$(brew --prefix "$formula" 2>/dev/null || true)
		if [[ -n $keg_dir && -d $keg_dir ]]; then
			actual=$(basename -- "$(cd -- "$keg_dir" && pwd -P)")
		fi
	fi
	if [[ $actual != "$want" ]]; then
		die "homebrew formula $formula version is ${actual:-unknown} (brew list --versions: $ver_line), want $want from ext/workers/gpu-renderer/third_party.lock"
	fi
}

step_verify_toolchain() {
	if [[ $driver_source != "mesa-source" ]]; then
		return 0
	fi
	verify_brew_formula_version llvm "$TOOLCHAIN_LLVM_VERSION"
	verify_brew_formula_version libclc "$TOOLCHAIN_LIBCLC_VERSION"
	verify_brew_formula_version spirv-llvm-translator "$TOOLCHAIN_SPIRV_LLVM_TRANSLATOR_VERSION"
	verify_brew_formula_version spirv-tools "$TOOLCHAIN_SPIRV_TOOLS_VERSION"
}

fetch_git_source() {
	local name=$1
	local url=$2
	local commit=$3
	local dir="$cache_dir/${name}-${commit}"

	if [[ ! -d "$dir/.git" ]]; then
		if ((offline)); then
			die "offline mode: missing cached $name checkout at $dir"
		fi
		local tmp
		tmp=$(mktemp -d "$cache_dir/.tmp-${name}.XXXXXX")
		tmp_paths+=("$tmp")
		git -C "$tmp" init -q
		git -C "$tmp" fetch -q --depth 1 -- "$url" "$commit"
		git -C "$tmp" checkout -q --detach FETCH_HEAD
		mv -- "$tmp" "$dir"
	fi

	local head
	head=$(git -C "$dir" rev-parse HEAD)
	if [[ $head != "$commit" ]]; then
		die "$dir HEAD is $head, expected $commit"
	fi
	if [[ -n "$(git -C "$dir" status --porcelain)" ]]; then
		die "$dir has uncommitted modifications"
	fi
}

step_sources() {
	fetch_git_source virglrenderer "$VIRGLRENDERER_URL" "$VIRGLRENDERER_COMMIT"
	fetch_git_source venus-protocol "$VENUS_PROTOCOL_URL" "$VENUS_PROTOCOL_COMMIT"
	fetch_git_source libepoxy "$LIBEPOXY_URL" "$LIBEPOXY_COMMIT"
	VK_INCLUDE="$cache_dir/venus-protocol-${VENUS_PROTOCOL_COMMIT}/include"
	if [[ ! -f "$VK_INCLUDE/vulkan/vulkan.h" ]]; then
		die "missing Vulkan headers in $VK_INCLUDE"
	fi
}

find_python() {
	local cand
	if [[ -n ${GVX_GPU_PYTHON:-} ]]; then
		if command -v "$GVX_GPU_PYTHON" >/dev/null 2>&1 &&
			"$GVX_GPU_PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
			printf '%s\n' "$GVX_GPU_PYTHON"
			return 0
		fi
		die "need Python 3.10 or later (set GVX_GPU_PYTHON)"
	fi

	for cand in python3 python3.14 python3.13 python3.12 python3.11 python3.10; do
		if command -v "$cand" >/dev/null 2>&1 &&
			"$cand" -c 'import sys; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
			printf '%s\n' "$cand"
			return 0
		fi
	done

	die "need Python 3.10 or later (set GVX_GPU_PYTHON)"
}

step_python() {
	local py py_ver reqs expected_marker
	py=$(find_python)
	py_ver=$("$py" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
	reqs=$PYTHON_REQUIREMENTS
	if [[ $driver_source == "mesa-source" ]]; then
		reqs="${PYTHON_REQUIREMENTS} ${DRIVER_SOURCE_PYTHON_REQUIREMENTS}"
	fi
	expected_marker="python=${py_ver} ${reqs}"

	local venv_dir="$cache_dir/venv"
	local marker="$venv_dir/.gvx-requirements"

	local py_probe='import mako, yaml'
	if [[ $driver_source == "mesa-source" ]]; then
		py_probe='import mako, yaml, packaging'
	fi

	local need_venv=1
	if [[ -f $marker && -x "$venv_dir/bin/python3" ]]; then
		if [[ "$(cat -- "$marker")" == "$expected_marker" ]] &&
			"$venv_dir/bin/python3" -Ic "$py_probe" >/dev/null 2>&1; then
			need_venv=0
		fi
	fi

	if ((need_venv)); then
		if ((offline)); then
			die "offline mode: missing Python venv at $venv_dir"
		fi
		rm -rf -- "$venv_dir"
		"$py" -m venv -- "$venv_dir"
		local py_reqs=()
		# reqs is a space-separated list of pinned pip specs.
		read -r -a py_reqs <<<"$reqs"
		"$venv_dir/bin/pip" install --isolated --disable-pip-version-check --no-input "${py_reqs[@]}"
		printf '%s\n' "$expected_marker" >"$marker"
	fi

	export PYTHONNOUSERSITE=1
	export PATH="$venv_dir/bin:$PATH"
	venv_python="$venv_dir/bin/python"
}

step_epoxy() {
	local src="$cache_dir/libepoxy-${LIBEPOXY_COMMIT}"
	epoxy_build="$out_dir/epoxy-build"
	epoxy_prefix="$out_dir/epoxy-prefix"
	rm -rf -- "$epoxy_build" "$epoxy_prefix"
	meson setup "$epoxy_build" "$src" --wrap-mode=nodownload \
		--prefix="$epoxy_prefix" --libdir=lib --buildtype=release \
		-Ddefault_library=static -Degl=no -Dglx=no -Dx11=false -Dtests=false -Ddocs=false \
		-Dc_args=-mmacosx-version-min=26.0 -Dc_link_args=-mmacosx-version-min=26.0
	ninja -C "$epoxy_build" install
	[[ -f "$epoxy_prefix/lib/libepoxy.a" ]] || die "libepoxy.a missing in $epoxy_prefix/lib"
	if compgen -G "$epoxy_prefix/lib/libepoxy*.dylib" >/dev/null; then
		die "libepoxy must be static only"
	fi
	export PKG_CONFIG_PATH="$epoxy_prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
}

compute_driver_stage_manifest() {
	local stage_dir=$1
	(
		# The caller runs this function on the left side of ||, so set -e is off.
		# Each command that can fail exits the subshell explicitly.
		cd -- "$stage_dir" || exit 1
		LC_ALL=C find . -mindepth 1 \( -type f -o -type l \) ! -name "$DRIVER_STAGE_MANIFEST" |
			sed 's|^\./||' |
			LC_ALL=C sort |
			while IFS= read -r rel; do
				if [[ -L $rel ]]; then
					exit 1
				fi
				shasum -a 256 -- "$rel" || exit 1
			done
	)
}

write_driver_stage_manifest() {
	local stage_dir=$1
	local manifest="$stage_dir/$DRIVER_STAGE_MANIFEST"
	local content
	content=$(compute_driver_stage_manifest "$stage_dir") || die "failed to hash staged driver outputs in $stage_dir"
	if [[ -z $content ]]; then
		die "staged driver directory has no files: $stage_dir"
	fi
	printf '%s\n' "$content" >"$manifest"
}

verify_driver_stage_manifest() {
	local stage_dir=$1
	local manifest="$stage_dir/$DRIVER_STAGE_MANIFEST"
	if [[ ! -f $manifest || -L $manifest || ! -s $manifest ]]; then
		return 1
	fi
	if [[ ! -f "$stage_dir/driver.txt" || ! -f "$stage_dir/lib/libvulkan_kosmickrisp.dylib" ]]; then
		return 1
	fi
	local actual expected
	actual=$(compute_driver_stage_manifest "$stage_dir") || return 1
	expected=$(cat -- "$manifest") || return 1
	[[ -n $actual && $actual == "$expected" ]]
}

step_driver() {
	if [[ $driver_source == "pinned" ]]; then
		local lock_digest
		lock_digest=$(
			shasum -a 256 \
				"$repo_root/ext/workers/gpu-renderer/third_party.lock" \
				"$repo_root/scripts/gpu/stage_driver.py" |
				shasum -a 256 |
				awk '{print substr($1, 1, 16)}'
		)
		DRIVER_STAGE_DIR="$cache_dir/driver-${bottle_tag}-${lock_digest}"
		local reuse_stage=0
		if [[ -d $DRIVER_STAGE_DIR ]]; then
			if verify_driver_stage_manifest "$DRIVER_STAGE_DIR"; then
				reuse_stage=1
			else
				printf 'build-renderer: staged driver manifest missing or mismatched in %s; rebuilding\n' "$DRIVER_STAGE_DIR" >&2
				rm -rf -- "$DRIVER_STAGE_DIR"
			fi
		fi
		if ((reuse_stage)); then
			"$venv_python" -I "$repo_root/scripts/gpu/stage_driver.py" \
				--lock "$repo_root/ext/workers/gpu-renderer/third_party.lock" \
				--cache "$cache_dir" \
				--tag "$bottle_tag" \
				--verify-cache-only
		else
			local tmp_stage
			tmp_stage=$(mktemp -d "$cache_dir/.tmp-driver.XXXXXX")
			rmdir -- "$tmp_stage"
			tmp_paths+=("$tmp_stage")

			local stage_args=(
				--lock "$repo_root/ext/workers/gpu-renderer/third_party.lock"
				--cache "$cache_dir"
				--tag "$bottle_tag"
				--out "$tmp_stage"
			)
			if ((offline)); then
				stage_args+=(--offline)
			fi
			"$venv_python" -I "$repo_root/scripts/gpu/stage_driver.py" "${stage_args[@]}"
			write_driver_stage_manifest "$tmp_stage"
			rm -rf -- "$DRIVER_STAGE_DIR"
			mv -- "$tmp_stage" "$DRIVER_STAGE_DIR"
		fi
	elif [[ $driver_source == "mesa-source" ]]; then
		local mesa_patch_dir="$repo_root/ext/workers/gpu-renderer/patches/mesa"
		local mesa_key
		mesa_key=$(
			{
				shasum -a 256 \
					"$repo_root/ext/workers/gpu-renderer/third_party.lock" \
					"$repo_root/scripts/gpu/stage_driver.py"
				if [[ -d $mesa_patch_dir ]]; then
					local pf
					shopt -s nullglob
					for pf in "$mesa_patch_dir"/*.patch; do
						printf '%s %s\n' "$(basename -- "$pf")" "$(shasum -a 256 -- "$pf" | awk '{print $1}')"
					done | LC_ALL=C sort
					shopt -u nullglob
				fi
			} | shasum -a 256 | awk '{print substr($1, 1, 16)}'
		)
		DRIVER_STAGE_DIR="$cache_dir/driver-mesa-source-${mesa_key}"
		local reuse_stage=0
		if [[ -d $DRIVER_STAGE_DIR ]]; then
			if verify_driver_stage_manifest "$DRIVER_STAGE_DIR"; then
				reuse_stage=1
			else
				printf 'build-renderer: staged driver manifest missing or mismatched in %s; rebuilding\n' "$DRIVER_STAGE_DIR" >&2
				rm -rf -- "$DRIVER_STAGE_DIR"
			fi
		fi
		if ((reuse_stage)); then
			"$venv_python" -I "$repo_root/scripts/gpu/stage_driver.py" \
				--lock "$repo_root/ext/workers/gpu-renderer/third_party.lock" \
				--source mesa-source \
				--cache "$cache_dir" \
				--verify-cache-only
		else
			local tmp_stage
			tmp_stage=$(mktemp -d "$cache_dir/.tmp-driver.XXXXXX")
			rmdir -- "$tmp_stage"
			tmp_paths+=("$tmp_stage")

			local stage_args=(
				--lock "$repo_root/ext/workers/gpu-renderer/third_party.lock"
				--source mesa-source
				--cache "$cache_dir"
				--out "$tmp_stage"
			)
			if [[ -d $mesa_patch_dir ]]; then
				stage_args+=(--patches-dir "$mesa_patch_dir")
			fi
			if ((offline)); then
				stage_args+=(--offline)
			fi
			"$venv_python" -I "$repo_root/scripts/gpu/stage_driver.py" "${stage_args[@]}"
			write_driver_stage_manifest "$tmp_stage"
			rm -rf -- "$DRIVER_STAGE_DIR"
			mv -- "$tmp_stage" "$DRIVER_STAGE_DIR"
		fi
	else
		DRIVER_STAGE_DIR="$cache_dir/driver-homebrew"
		local tmp_stage
		tmp_stage=$(mktemp -d "$cache_dir/.tmp-driver.XXXXXX")
		rmdir -- "$tmp_stage"
		tmp_paths+=("$tmp_stage")

		"$venv_python" -I "$repo_root/scripts/gpu/stage_driver.py" \
			--lock "$repo_root/ext/workers/gpu-renderer/third_party.lock" \
			--source homebrew \
			--out "$tmp_stage"
		rm -rf -- "$DRIVER_STAGE_DIR"
		mv -- "$tmp_stage" "$DRIVER_STAGE_DIR"
	fi

	DRIVER_LIB="$DRIVER_STAGE_DIR/lib/libvulkan_kosmickrisp.dylib"
	if [[ ! -f $DRIVER_LIB ]]; then
		die "staged driver missing: $DRIVER_LIB"
	fi
}

step_work_tree() {
	mkdir -p -- "$work_dir/subprojects/virglrenderer"
	rsync -a --delete --exclude subprojects -- "$repo_root/ext/workers/gpu-renderer/" "$work_dir/"
	rsync -a --delete --exclude .git -- \
		"$cache_dir/virglrenderer-${VIRGLRENDERER_COMMIT}/" \
		"$work_dir/subprojects/virglrenderer/"

	local wrap_file="$work_dir/subprojects/virglrenderer/subprojects/venus-protocol.wrap"
	if [[ ! -f $wrap_file ]]; then
		die "missing wrap file: $wrap_file"
	fi
	local venus_dir
	venus_dir=$(sed -n 's/^directory[[:space:]]*=[[:space:]]*//p' "$wrap_file" | head -n 1)
	if [[ -z $venus_dir || $venus_dir == */* ]]; then
		die "invalid venus-protocol wrap directory: $venus_dir"
	fi

	mkdir -p -- "$work_dir/subprojects/virglrenderer/subprojects/$venus_dir"
	rsync -a --delete --exclude .git -- \
		"$cache_dir/venus-protocol-${VENUS_PROTOCOL_COMMIT}/" \
		"$work_dir/subprojects/virglrenderer/subprojects/$venus_dir/"

	local patch_dir="$repo_root/ext/workers/gpu-renderer/patches/virglrenderer"
	if [[ -d $patch_dir ]]; then
		local patch_file
		shopt -s nullglob
		for patch_file in "$patch_dir"/*.patch; do
			GIT_CEILING_DIRECTORIES="$work_dir" \
				GIT_CONFIG_GLOBAL=/dev/null \
				GIT_CONFIG_NOSYSTEM=1 \
				git -C "$work_dir/subprojects/virglrenderer" \
				apply --check -- "$patch_file" ||
				die "virglrenderer patch failed check: $patch_file"
			GIT_CEILING_DIRECTORIES="$work_dir" \
				GIT_CONFIG_GLOBAL=/dev/null \
				GIT_CONFIG_NOSYSTEM=1 \
				git -C "$work_dir/subprojects/virglrenderer" \
				apply -- "$patch_file" ||
				die "virglrenderer patch failed to apply: $patch_file"
		done
		shopt -u nullglob
	fi
}

step_build() {
	local short_commit=${VIRGLRENDERER_COMMIT:0:8}
	local build_info
	if [[ $driver_source == "pinned" ]]; then
		build_info="virglrenderer ${short_commit} KosmicKrisp ${MESA_VERSION}"
	elif [[ $driver_source == "mesa-source" ]]; then
		build_info="virglrenderer ${short_commit} KosmicKrisp ${DRIVER_SOURCE_VERSION}"
	else
		build_info="virglrenderer ${short_commit} KosmicKrisp homebrew"
	fi

	local min_macos
	min_macos=$(sed -n 's/^MIN_MACOS=//p' "$DRIVER_STAGE_DIR/driver.txt" | head -n 1)
	if [[ -z $min_macos ]]; then
		die "missing MIN_MACOS in $DRIVER_STAGE_DIR/driver.txt"
	fi

	local opts=(
		"-Dvulkan_include_dir=$VK_INCLUDE"
		"-Ddriver_lib=$DRIVER_LIB"
		"-Dmin_macos=$min_macos"
		"-Dbuild_info=$build_info"
	)
	if [[ ! -f "$meson_dir/build.ninja" ]]; then
		rm -rf -- "$meson_dir"
		meson setup "$meson_dir" "$work_dir" --wrap-mode=nodownload "${opts[@]}"
	else
		meson configure "$meson_dir" "${opts[@]}"
	fi
	ninja -C "$meson_dir" gvx-gpu-renderer libvulkan.dylib
}

step_stage() {
	rm -rf -- "$bundle_dir"
	mkdir -p -- "$bundle_dir/bin" "$bundle_dir/lib" "$bundle_dir/LICENSES"

	install -m 0755 -- "$meson_dir/gvx-gpu-renderer" "$bundle_dir/bin/gvx-gpu-renderer"

	local f
	for f in "$DRIVER_STAGE_DIR"/lib/*.dylib; do
		install -m 0755 -- "$f" "$bundle_dir/lib/$(basename -- "$f")"
	done

	local shim="$bundle_dir/lib/libvulkan.dylib"
	install -m 0755 -- "$meson_dir/libvulkan.dylib" "$shim"
	install_name_tool -id "@loader_path/libvulkan.dylib" "$shim"

	local rpath
	while IFS= read -r rpath; do
		if [[ -n $rpath ]]; then
			install_name_tool -delete_rpath "$rpath" "$shim"
		fi
	done < <(otool -l "$shim" | awk '
		$1 == "cmd" && $2 == "LC_RPATH" { in_rpath = 1; next }
		in_rpath && $1 == "path" { print $2; in_rpath = 0 }
		$1 == "Load" { in_rpath = 0 }
	')

	cp -- "$cache_dir/virglrenderer-${VIRGLRENDERER_COMMIT}/COPYING" "$bundle_dir/LICENSES/virglrenderer.txt"
	cp -- "$repo_root/ext/workers/gpu-renderer/licenses/venus-protocol.txt" "$bundle_dir/LICENSES/venus-protocol.txt"
	cp -- "$cache_dir/libepoxy-${LIBEPOXY_COMMIT}/COPYING" "$bundle_dir/LICENSES/libepoxy.txt"
	for f in "$DRIVER_STAGE_DIR"/licenses/*.txt; do
		cp -- "$f" "$bundle_dir/LICENSES/$(basename -- "$f")"
	done

	write_license_index
}

write_license_index() {
	local manifest="$repo_root/ext/workers/gpu-renderer/licenses/components.txt"
	if [[ ! -f $manifest ]]; then
		die "missing license manifest: $manifest"
	fi
	local driver_report="$DRIVER_STAGE_DIR/driver.txt"
	if [[ ! -f $driver_report ]]; then
		die "missing $driver_report"
	fi

	local bundle_kind=$driver_source
	if [[ $bundle_kind == "homebrew" ]]; then
		bundle_kind="pinned"
	fi

	local index_file="$bundle_dir/LICENSES/INDEX.txt"
	: >"$index_file"

	local indexed_files="|"
	local raw_line comp spdx lic_file kinds kind_matched ver
	while IFS= read -r raw_line || [[ -n $raw_line ]]; do
		if [[ -z $raw_line || $raw_line == \#* ]]; then
			continue
		fi
		IFS='|' read -r comp spdx lic_file kinds <<<"$raw_line"
		if [[ -z $comp || -z $spdx || -z $lic_file || -z $kinds ]]; then
			die "malformed line in $manifest: $raw_line"
		fi
		kind_matched=0
		if [[ ",$kinds," == *",$bundle_kind,"* ]]; then
			kind_matched=1
		fi
		if ((kind_matched == 0)); then
			continue
		fi
		if [[ ! -f "$bundle_dir/LICENSES/$lic_file" ]]; then
			die "missing license file $bundle_dir/LICENSES/$lic_file required by $manifest for $comp"
		fi

		case "$comp" in
		virglrenderer)
			ver=${VIRGLRENDERER_COMMIT:0:12}
			;;
		venus-protocol)
			ver=${VENUS_PROTOCOL_COMMIT:0:12}
			;;
		libepoxy)
			ver=${LIBEPOXY_COMMIT:0:12}
			;;
		mesa)
			ver=$(awk '
				/^MESA=/ { sub(/^MESA=/, "", $1); print $1; exit }
				$1 == "mesa" { print $2; exit }
			' "$driver_report")
			;;
		*)
			ver=$(awk -v c="$comp" '$1 == c { print $2; exit }' "$driver_report")
			;;
		esac
		if [[ -z $ver ]]; then
			die "cannot resolve version for license component $comp from $driver_report"
		fi
		printf '%s %s %s\n' "$comp" "$ver" "$spdx" >>"$index_file"
		indexed_files="${indexed_files}${lic_file}|"
	done <"$manifest"

	local f base
	shopt -s nullglob
	for f in "$bundle_dir"/LICENSES/*.txt; do
		base=$(basename -- "$f")
		if [[ $base == "INDEX.txt" ]]; then
			continue
		fi
		if [[ $indexed_files != *"|$base|"* ]]; then
			shopt -u nullglob
			die "unindexed license file in $bundle_dir/LICENSES: $base"
		fi
	done
	shopt -u nullglob
}

step_buildinfo() {
	if [[ ! -f "$DRIVER_STAGE_DIR/driver.txt" ]]; then
		die "missing $DRIVER_STAGE_DIR/driver.txt"
	fi

	{
		printf 'RENDERER_VERSION=0.1.0\n'
		printf 'VIRGLRENDERER_COMMIT=%s\n' "$VIRGLRENDERER_COMMIT"
		local patch_dir="$repo_root/ext/workers/gpu-renderer/patches/virglrenderer"
		if [[ -d $patch_dir ]]; then
			local patch_file patch_sha
			shopt -s nullglob
			for patch_file in "$patch_dir"/*.patch; do
				patch_sha=$(shasum -a 256 -- "$patch_file" | awk '{print $1}')
				printf 'VIRGLRENDERER_PATCH=%s %s\n' "$(basename -- "$patch_file")" "$patch_sha"
			done
			shopt -u nullglob
		fi
		printf 'VENUS_PROTOCOL_COMMIT=%s\n' "$VENUS_PROTOCOL_COMMIT"
		printf 'LIBEPOXY_COMMIT=%s\n' "$LIBEPOXY_COMMIT"
		printf 'DRIVER=KosmicKrisp\n'
		printf 'BOTTLE_TAG=%s\n' "$bottle_tag"
		cat -- "$DRIVER_STAGE_DIR/driver.txt"
	} >"$bundle_dir/BUILDINFO"
}

step_sign() {
	local f
	for f in "$bundle_dir"/lib/*.dylib; do
		codesign --force --sign - "$f"
	done
	codesign --force --sign - "$bundle_dir/bin/gvx-gpu-renderer"
}

step_check() {
	local bin="$bundle_dir/bin/gvx-gpu-renderer"

	local line
	while IFS= read -r line; do
		line=${line#"${line%%[![:space:]]*}"}
		if [[ $line != /usr/lib/* && $line != /System/Library/* ]]; then
			die "unexpected linked library in $bin: $line"
		fi
	done < <(otool -L "$bin" | tail -n +2)

	if ! otool -l "$bin" | awk '
		$1 == "cmd" && $2 == "LC_RPATH" { in_rpath = 1; next }
		in_rpath && $1 == "path" {
			if ($2 == "@executable_path/../lib") { count++ } else { bad = 1 }
			in_rpath = 0
		}
		$1 == "Load" { in_rpath = 0 }
		END { exit (count == 1 && !bad) ? 0 : 1 }
	'; then
		die "expected sole LC_RPATH @executable_path/../lib in $bin"
	fi
	codesign --verify --strict "$bin"

	if [[ -e "$bundle_dir/lib/libMoltenVK.dylib" ]]; then
		die "unexpected libMoltenVK.dylib in $bundle_dir/lib"
	fi

	local dylib base got_id dep dep_name shim_has_driver
	for dylib in "$bundle_dir"/lib/*.dylib; do
		base=$(basename -- "$dylib")
		got_id=$(otool -D "$dylib" | sed -n '2p' | sed 's/^[[:space:]]*//')
		if [[ $got_id != "@loader_path/$base" ]]; then
			die "unexpected install name in $dylib: $got_id"
		fi

		shim_has_driver=0
		while IFS= read -r line; do
			line=${line#"${line%%[![:space:]]*}"}
			dep=${line%% (*}
			if [[ $dep == /usr/lib/* || $dep == /System/Library/* ]]; then
				continue
			fi
			if [[ $dep == @loader_path/* ]]; then
				dep_name=${dep#@loader_path/}
				if [[ $base == "libvulkan.dylib" ]]; then
					if [[ $dep_name == "libvulkan.dylib" ]]; then
						continue
					fi
					if [[ $dep_name == "libvulkan_kosmickrisp.dylib" ]]; then
						shim_has_driver=1
						continue
					fi
					die "unexpected dependency in shim $dylib: $dep"
				fi
				if [[ -f "$bundle_dir/lib/$dep_name" ]]; then
					continue
				fi
			fi
			die "unexpected dependency in $dylib: $dep"
		done < <(otool -L "$dylib" | tail -n +2)

		if [[ $base == "libvulkan.dylib" && $shim_has_driver -eq 0 ]]; then
			die "shim $dylib does not link @loader_path/libvulkan_kosmickrisp.dylib"
		fi
		if otool -l "$dylib" | grep -q 'cmd LC_RPATH'; then
			die "unexpected LC_RPATH in $dylib"
		fi
		codesign --verify --strict "$dylib"
	done
}

step_args_and_host "$@"
step_lock_file
step_verify_toolchain
step_sources
step_python
step_epoxy
step_driver
step_work_tree
step_build
step_stage
step_buildinfo
step_sign
step_check

printf '%s\n' "$bundle_dir"
