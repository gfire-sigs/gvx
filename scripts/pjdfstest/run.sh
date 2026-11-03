#!/usr/bin/env bash
# Run the pjdfstest suites in four parallel rungv guests on one file system
# driver, and write the guest output of each worker to OUT_DIR/worker_N.log.
# Compare the logs with internal/pjdfsreport afterwards.
set -euo pipefail

readonly usage='usage: run.sh RUNGV CACHE_DIR BUNDLE_DIR ext4lite|hostfs vol|tmp OUT_DIR'
readonly rungv=${1:?$usage} cache=${2:?$usage} bundle=${3:?$usage}
readonly fs=${4:?$usage} binmode=${5:?$usage} outdir=${6:?$usage}
readonly platform=${PJDFS_PLATFORM:-systrap}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly script_dir

if [[ $fs != ext4lite && $fs != hostfs ]]; then
  printf '%s\n' "$usage" >&2
  exit 2
fi

# Git Bash on Windows rewrites arguments that start with "/" into Windows
# paths. The guest paths must reach rungv unchanged.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
mkdir -p -- "$outdir" "$cache"
"$rungv" pull -cache-dir="$cache" alpine:3.20 >/dev/null

run_worker() {
  local w=$1
  shift
  local wdir="$outdir/bundle_$w"
  rm -rf -- "$wdir"
  cp -R -- "$bundle" "$wdir"
  cp -- "$script_dir/guest-run.sh" "$wdir/guest-run.sh"
  local mount=(-v "pjdfs_vol_$w:/mnt/vol")
  if [[ $fs == hostfs ]]; then
    mount=(--mount "type=volume,src=pjdfs_host_$w,dst=/mnt/vol,driver=hostfs")
  fi
  "$rungv" run -platform="$platform" -cache-dir="$cache" -workspace="$wdir" -ro "${mount[@]}" \
    alpine:3.20 sh /workspace/guest-run.sh "$binmode" "$@" >"$outdir/worker_$w.log" 2>&1
}

pids=()
run_worker 1 chown &
pids+=("$!")
run_worker 2 rename &
pids+=("$!")
run_worker 3 chmod link mknod open ftruncate &
pids+=("$!")
run_worker 4 chflags mkdir mkfifo posix_fallocate rmdir symlink truncate unlink utimensat &
pids+=("$!")

status=0
for i in "${!pids[@]}"; do
  if ! wait "${pids[$i]}"; then
    printf 'worker %d failed; last lines of its log:\n' "$((i + 1))" >&2
    tail -n 20 -- "$outdir/worker_$((i + 1)).log" >&2
    status=1
  fi
done
exit "$status"
