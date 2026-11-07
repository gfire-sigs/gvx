#!/usr/bin/env bash
# Run the gVisor analyzers (checklocks, checkconst, checklinkname) on every package.
#
# Usage: scripts/gvisorlint.sh [os/arch ...]
# Without arguments, the script checks the five supported targets. Build files
# differ between targets, so each target runs on its own. The Go build cache
# keeps the results of a target until a source file changes.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
readonly script_dir repo_root

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
	targets=(linux/amd64 linux/arm64 darwin/arm64 windows/amd64 windows/arm64)
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cd "$repo_root"
go build -o "$tmp/gvisorlint" ./tools/gvisorlint

status=0
for target in "${targets[@]}"; do
	echo "::group::gvisorlint $target"
	if ! GOOS=${target%/*} GOARCH=${target#*/} go vet -vettool="$tmp/gvisorlint" ./... 2>&1 | awk '!seen[$0]++'; then
		status=1
	fi
	echo "::endgroup::"
done
exit "$status"
