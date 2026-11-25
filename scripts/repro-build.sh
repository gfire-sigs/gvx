#!/bin/sh
# Builds a deterministic Go executable from this repository.
#
# Usage: scripts/repro-build.sh OUTPUT [PACKAGE]
# Reads GOOS, GOARCH, GOAMD64, GOARM64, and GVX_BUILD_TAGS from the environment
# and selects per-OS defaults when unset. Scrubs ambient environment variables
# and pins the toolchain, module proxy, architecture level, and linker flags.
#
# Building ./cmd/rungvx runs with GOWORK=off and CGO_ENABLED=0 from the root
# module. Building a package under ./ext/... (for example ./ext/cmd/rungvx)
# runs from ext/ using ext/go.work and applies GVX_BUILD_TAGS when set.
set -eu

out=${1:?usage: repro-build.sh OUTPUT [PACKAGE]}
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
goos=${GOOS:-$("$go_bin" env GOHOSTOS)}
goarch=${GOARCH:-$("$go_bin" env GOHOSTARCH)}
toolchain="go$(awk '$1 == "go" { print $2; exit }' "$repo_root/go.mod")"
gomodcache=${GOMODCACHE:-$("$go_bin" env GOMODCACHE)}
gocache=${GOCACHE:-$("$go_bin" env GOCACHE)}
home_dir=${HOME:-/tmp}
tmp_dir=${TMPDIR:-/tmp}
goproxy=${GVX_GOPROXY:-https://proxy.golang.org/}
gosumdb=${GVX_GOSUMDB:-sum.golang.org}
buildvcs=${GVX_BUILDVCS:-true}
buildtags=${GVX_BUILD_TAGS:-}
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

if [ -n "$buildtags" ]; then
	exec env -i "$@" "$go_bin" build \
		-C "$build_dir" \
		-mod=readonly \
		-pgo=off \
		-trimpath \
		"-buildmode=$buildmode" \
		-compiler=gc \
		"-buildvcs=$buildvcs" \
		"-tags=$buildtags" \
		-ldflags="-s -w -buildid=" \
		-o "$out_abs" \
		"$build_pkg"
fi

exec env -i "$@" "$go_bin" build \
	-C "$build_dir" \
	-mod=readonly \
	-pgo=off \
	-trimpath \
	"-buildmode=$buildmode" \
	-compiler=gc \
	"-buildvcs=$buildvcs" \
	-ldflags="-s -w -buildid=" \
	-o "$out_abs" \
	"$build_pkg"
