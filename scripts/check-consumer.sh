#!/usr/bin/env bash
# Build a module outside this repository that imports pkg/gvx, for every target.
#
# A `replace` directive of this module does not apply to a module that imports
# it. This check fails when a package of pkg/gvx needs such a directive.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
readonly script_dir repo_root

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

go_version=$(awk '$1 == "go" { print $2; exit }' "$repo_root/go.mod")
cat >"$tmp/go.mod" <<MOD
module example.com/consumer

go $go_version

require z.gfire.dev/gvx v0.0.0

replace z.gfire.dev/gvx => $repo_root
MOD
cat >"$tmp/main.go" <<'SRC'
package main

import (
	"fmt"

	"z.gfire.dev/gvx/pkg/gvx"
)

func main() {
	fmt.Println(gvx.Config{}.Platform)
}
SRC

cd -- "$tmp"
for target in darwin/arm64 windows/amd64 windows/arm64 linux/amd64 linux/arm64; do
  printf 'consumer build %s\n' "$target"
  GOFLAGS=-mod=mod GOOS=${target%/*} GOARCH=${target#*/} CGO_ENABLED=0 go build -o /dev/null .
done
