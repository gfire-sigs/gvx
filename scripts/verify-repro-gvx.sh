#!/usr/bin/env bash
# Builds rungv on the host and inside a Go OCI image running on gvx, then
# verifies that both binaries produce the exact same SHA-256 digest.
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
target_os=${GVX_REPRO_GOOS:-linux}
target_arch=${GVX_REPRO_GOARCH:-amd64}
pkg=${GVX_REPRO_PKG:-./cmd/rungv}
go_ver=$(awk '$1 == "go" { print $2; exit }' "$repo_root/go.mod")
image=${GVX_REPRO_IMAGE:-golang:${go_ver}-bookworm}
platform=${GVX_REPRO_PLATFORM:-auto}
cache_args=()
if [ -n "${GVX_REPRO_CACHE_DIR:-}" ]; then
	cache_args=(-cache-dir="$GVX_REPRO_CACHE_DIR")
fi

host_os=$(go env GOHOSTOS)
host_arch=$(go env GOHOSTARCH)
gomodcache=$(go env GOMODCACHE)

work=$(mktemp -d "${TMPDIR:-/tmp}/gvx-repro.XXXXXX")
cleanup() {
	status=$?
	trap - EXIT
	rm -rf -- "$work" || true
	exit "$status"
}
trap cleanup EXIT

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum -- "$1" | awk '{ print $1 }'
	else
		shasum -a 256 -- "$1" | awk '{ print $1 }'
	fi
}

go -C "$repo_root" mod download

host_out="$work/host/rungv"
GOOS="$target_os" GOARCH="$target_arch" "$repo_root/scripts/repro-build.sh" "$host_out" "$pkg"
host_sha=$(sha256_file "$host_out")

runner_bin="$host_out"
if [ "$host_os/$host_arch" != "$target_os/$target_arch" ] || [ "$pkg" != "./cmd/rungv" ]; then
	runner_bin="$work/runner/rungv"
	GOOS="$host_os" GOARCH="$host_arch" "$repo_root/scripts/repro-build.sh" "$runner_bin" ./cmd/rungv
elif [ "$host_os" = "darwin" ]; then
	mkdir -p -- "$work/runner"
	runner_bin="$work/runner/rungv"
	cp -- "$host_out" "$runner_bin"
fi
if [ "$host_os" = "darwin" ]; then
	codesign --sign - --entitlements "$repo_root/entitlements.plist" --force "$runner_bin"
fi

if ! "$runner_bin" inspect ${cache_args[@]+"${cache_args[@]}"} "$image" >/dev/null 2>&1; then
	"$runner_bin" pull ${cache_args[@]+"${cache_args[@]}"} "$image"
fi

mkdir -p -- "$work/guest"
"$runner_bin" run \
	${cache_args[@]+"${cache_args[@]}"} \
	-platform="$platform" \
	-v "$repo_root":/src:ro \
	-v "$gomodcache":/gomodcache:ro \
	-v "$work/guest":/out \
	"$image" \
	sh -ceu '
		git config --global --add safe.directory /src
		GOOS="$1" GOARCH="$2" GOMODCACHE=/gomodcache GOCACHE=/tmp/gocache \
			/src/scripts/repro-build.sh /out/rungv "$3"
	' sh "$target_os" "$target_arch" "$pkg"

guest_out="$work/guest/rungv"
guest_sha=$(sha256_file "$guest_out")

printf 'target: %s/%s (%s)\n' "$target_os" "$target_arch" "$pkg"
printf 'image:  %s\n' "$image"
printf 'host:   %s\n' "$host_sha"
printf 'gvx:    %s\n' "$guest_sha"

if [ "$host_sha" != "$guest_sha" ]; then
	printf 'reproducible build mismatch between host and gvx guest\n' >&2
	go version -m "$host_out" >&2 || true
	go version -m "$guest_out" >&2 || true
	exit 1
fi

if [ "$host_os/$host_arch" = "$target_os/$target_arch" ] && [ "$pkg" = "./cmd/rungv" ]; then
	"$guest_out" version
fi
