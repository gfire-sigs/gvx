#!/bin/sh
# Builds a deterministic Go executable from this repository.
#
# Usage: scripts/repro-build.sh OUTPUT [PACKAGE]
# Reads GOOS and GOARCH from the environment and defaults to GOHOSTOS and
# GOHOSTARCH. Scrubs ambient environment variables and pins the toolchain,
# module proxy, architecture level, and linker flags.
set -eu

out=${1:?usage: repro-build.sh OUTPUT [PACKAGE]}
pkg=${2:-./cmd/rungv}
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

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
buildmode=exe
if [ "$goos" = "android" ]; then
	buildmode=pie
fi

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
	GOWORK=off \
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
	GOAMD64=v1 \
	GOARM64=v8.0 \
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

exec env -i "$@" "$go_bin" build \
	-C "$repo_root" \
	-mod=readonly \
	-pgo=off \
	-trimpath \
	"-buildmode=$buildmode" \
	-compiler=gc \
	"-buildvcs=$buildvcs" \
	-ldflags="-s -w -buildid=" \
	-o "$out_abs" \
	"$pkg"
