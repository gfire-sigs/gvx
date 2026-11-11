#!/usr/bin/env bash
# Synchronize the fork with google/gvisor (docs/architecture.md section 2.3).
#
# `tools/upstream -mode=sync` runs steps 1 to 7. It uses `git merge --no-commit upstream/go`
# when the repository is a git fork that shares history with upstream. Otherwise it prints a
# notice and overlays the pinned upstream archive. Extra arguments go to the tool, for example
# `-ref=<sha>`, `-strategy=archive`, `-offline`, or `-dest=<dir>`.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
readonly script_dir repo_root

if ! command -v go >/dev/null 2>&1; then
  printf 'required command not found: go\n' >&2
  exit 127
fi

cd -- "$repo_root"
go run ./tools/upstream -mode=sync -root=. -max-ratio=0.05 "$@"

# Step 7: verify all five host targets, Android arm64, and gVisor static analyzers.
targets=(linux/amd64 linux/arm64 darwin/arm64 windows/amd64 windows/arm64)
for target in "${targets[@]}"; do
  printf 'building %s\n' "$target"
  GOOS=${target%/*} GOARCH=${target#*/} go build ./...
done

printf 'building android/arm64\n'
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build ./...

"$script_dir/gvisorlint.sh"
