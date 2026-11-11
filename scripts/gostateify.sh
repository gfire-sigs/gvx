#!/usr/bin/env bash
# Regenerate or verify pkg/state autogen files for registered packages.
#
# Usage:
#   ./scripts/gostateify.sh          # regenerate tools/gostateify/packages.txt
#   ./scripts/gostateify.sh -check   # verify zero drift on registered packages
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
readonly script_dir repo_root

if ! command -v go >/dev/null 2>&1; then
  printf 'required command not found: go\n' >&2
  exit 127
fi

use_default_list=1
for arg in "$@"; do
  case "$arg" in
    -pkg|-pkg=*|--pkg|--pkg=*|-packages-file|-packages-file=*|--packages-file|--packages-file=*)
      use_default_list=0
      ;;
  esac
done

cd -- "$repo_root"
if [ "$use_default_list" -eq 1 ]; then
  exec go run ./tools/gostateify -root=. -packages-file=tools/gostateify/packages.txt "$@"
else
  exec go run ./tools/gostateify -root=. "$@"
fi
