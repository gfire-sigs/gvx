#!/bin/sh
# Builds a deterministic, dead-method-eliminated Go executable using
# tools/slimlink (an overlay-patched cmd/link built from the active GOROOT)
# while preserving full stack traces and runtime metadata.
#
# Usage: scripts/slim-build.sh OUTPUT [PACKAGE]
# Accepts the same environment variables as scripts/repro-build.sh plus:
#   GVX_SLIM_FIX_REFLECT_METHODS=true|false (default: true)
#   GVX_SLIM_CACHE_DIR=DIR                  (optional patched-linker cache dir)
set -eu

out=${1:?usage: slim-build.sh OUTPUT [PACKAGE]}
pkg=${2:-./cmd/rungvx}
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

build_dir="$repo_root"
build_pkg="$pkg"
gowork="off"
case "$pkg" in
./ext/*)
	build_dir="$repo_root/ext"
	build_pkg="./${pkg#./ext/}"
	gowork="$repo_root/ext/go.work"
	;;
ext/*)
	build_dir="$repo_root/ext"
	build_pkg="./${pkg#ext/}"
	gowork="$repo_root/ext/go.work"
	;;
esac

go_bin=${GO:-go}
go_path=$(command -v "$go_bin")
gobin_dir=$(dirname -- "$go_path")
go_name=$(basename -- "$go_path")
host_goos=$("$go_bin" env GOHOSTOS)
host_goarch=$("$go_bin" env GOHOSTARCH)
goos=${GOOS:-$host_goos}
goarch=${GOARCH:-$host_goarch}
toolchain="go$(awk '$1 == "go" { print $2; exit }' "$repo_root/go.mod")"
gomodcache=${GOMODCACHE:-$("$go_bin" env GOMODCACHE)}
gocache=${GOCACHE:-$("$go_bin" env GOCACHE)}
home_dir=${HOME:-/tmp}
tmp_dir=${TMPDIR:-/tmp}
goproxy=${GVX_GOPROXY:-https://proxy.golang.org/}
gosumdb=${GVX_GOSUMDB:-sum.golang.org}
buildvcs=${GVX_BUILDVCS:-true}
buildtags=${GVX_BUILD_TAGS:-}
fix_reflect=${GVX_SLIM_FIX_REFLECT_METHODS:-true}
slim_cache=${GVX_SLIM_CACHE_DIR:-}

buildmode=exe
if [ "$goos" = "android" ]; then
	buildmode=pie
fi
case "$goos" in
linux|windows)
	default_goamd64=v2
	;;
*)
	default_goamd64=v1
	;;
esac
case "$goos" in
darwin)
	default_goarm64=v8.4
	;;
windows)
	default_goarm64=v8.1
	;;
*)
	default_goarm64=v8.0
	;;
esac
goamd64=${GOAMD64:-$default_goamd64}
goarm64=${GOARM64:-$default_goarm64}

mkdir -p -- "$(dirname -- "$out")"
out_abs="$(CDPATH= cd -- "$(dirname -- "$out")" && pwd)/$(basename -- "$out")"

# Build tools/slimlink for the host first so -toolexec runs natively.
slim_tmp=$(mktemp -d "${tmp_dir%/}/gvx-slimlink-bin.XXXXXX")
cleanup() {
	rm -rf -- "$slim_tmp" || true
}
trap cleanup EXIT
trap 'cleanup; trap - HUP; kill -HUP $$' HUP
trap 'cleanup; trap - INT; kill -INT $$' INT
trap 'cleanup; trap - TERM; kill -TERM $$' TERM

slim_bin="$slim_tmp/slimlink"
if [ "$host_goos" = "windows" ]; then
	slim_bin="${slim_bin}.exe"
fi
(
	cd "$repo_root"
	GOOS="$host_goos" \
	GOARCH="$host_goarch" \
	GOAMD64= \
	GOARM64= \
	GO386= \
	GOARM= \
	GOEXPERIMENT= \
	GOFLAGS= \
	GOENV=off \
	GOWORK=off \
	GOTOOLCHAIN="$toolchain" \
	CGO_ENABLED=0 \
	"$go_bin" build -mod=readonly -buildvcs=false -o "$slim_bin" ./tools/slimlink
)

set -- \
	PATH="$gobin_dir:${PATH:-/usr/local/bin:/usr/bin:/bin}" \
	HOME="$home_dir" \
	TMPDIR="$tmp_dir" \
	LC_ALL=C \
	TZ=UTC \
	GOMODCACHE="$gomodcache" \
	GOCACHE="$gocache" \
	GOENV=off \
	GOWORK="$gowork" \
	GO111MODULE=on \
	GOPROXY="$goproxy" \
	GOSUMDB="$gosumdb" \
	GOTOOLCHAIN="$toolchain" \
	GOTELEMETRY=off \
	GOFIPS140=off \
	GOEXPERIMENT= \
	GODEBUG= \
	GOFLAGS= \
	CGO_ENABLED=0 \
	GOOS="$goos" \
	GOARCH="$goarch" \
	GOAMD64="$goamd64" \
	GOARM64="$goarm64" \
	GO386=sse2 \
	GOARM=7
if [ -n "${SYSTEMROOT:-}" ]; then
	set -- "$@" SYSTEMROOT="$SYSTEMROOT"
fi
if [ -n "${USERPROFILE:-}" ]; then
	set -- "$@" USERPROFILE="$USERPROFILE"
fi
if [ -n "${LOCALAPPDATA:-}" ]; then
	set -- "$@" LOCALAPPDATA="$LOCALAPPDATA"
fi
if [ -n "${TEMP:-}" ]; then
	set -- "$@" TEMP="$TEMP"
fi
if [ -n "${TMP:-}" ]; then
	set -- "$@" TMP="$TMP"
fi

set -- "$@" \
	"$slim_bin" \
	"-go=$go_name" \
	"-fix-reflect-methods=$fix_reflect"
if [ -n "$slim_cache" ]; then
	set -- "$@" -cache-dir "$slim_cache"
fi
set -- "$@" \
	-- \
	-C "$build_dir" \
	-mod=readonly \
	-pgo=off \
	-trimpath \
	"-buildmode=$buildmode" \
	-compiler=gc \
	"-buildvcs=$buildvcs"
if [ -n "$buildtags" ]; then
	set -- "$@" "-tags=$buildtags"
fi
set -- "$@" \
	-ldflags="-s -w -buildid=" \
	-o "$out_abs" \
	"$build_pkg"

env -i "$@"
