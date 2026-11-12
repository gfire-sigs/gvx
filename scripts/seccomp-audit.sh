#!/usr/bin/env bash
# Run go tests in a diagnostic build and list the system calls that the Linux
# seccomp allowlist lacks. The build uses the tag gvx_seccomp_log, so a call
# outside the allowlist runs and the kernel logs it. Use this script when a
# change adds a host call and the normal build kills the process.
#
# Usage: scripts/seccomp-audit.sh <package patterns> [go test -run value]
set -eo pipefail

pkgs=${1:?usage: seccomp-audit.sh <package patterns> [run pattern]}
run=${2:-}

export CGO_ENABLED=0
export GOFLAGS="${GOFLAGS:-} -tags=gvx_seccomp_log"

log=$(mktemp)
trap 'rm -f "$log"' EXIT

sudo dmesg -C >/dev/null 2>&1 || true
args=(-count=1 -v)
if [ -n "$run" ]; then args+=(-run "$run"); fi
rc=0
# shellcheck disable=SC2086 # the patterns split on spaces on purpose
go test "${args[@]}" $pkgs || rc=$?

{ sudo dmesg 2>/dev/null || sudo journalctl -k --no-pager 2>/dev/null; } | grep -E 'type=1326|SECCOMP' >"$log" || true
echo
echo "== system calls outside the allowlist ($(wc -l <"$log") log lines, test exit code $rc)"
sysdir=$(go list -m -f '{{.Dir}}' golang.org/x/sys)
python3 - "$log" "$sysdir/unix/zsysnum_linux_$(go env GOARCH).go" <<'PY'
import collections, re, sys

names = {}
for line in open(sys.argv[2]):
    m = re.match(r"\s*SYS_(\w+)\s*=\s*(\d+)", line)
    if m:
        names[int(m.group(2))] = m.group(1).lower()

counts = collections.Counter()
for line in open(sys.argv[1]):
    comm = re.search(r'comm="([^"]*)"', line)
    nr = re.search(r"syscall=(\d+)", line)
    if comm and nr:
        counts[(comm.group(1), names.get(int(nr.group(1)), nr.group(1)))] += 1
for (comm, name), n in sorted(counts.items()):
    print(f"{n:6d}  {comm:20s} {name}")
PY
exit $rc
