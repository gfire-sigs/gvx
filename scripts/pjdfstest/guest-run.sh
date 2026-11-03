#!/bin/sh
# Run pjdfstest suites inside the guest. The test directory is /mnt/vol. The
# script brackets the TAP output of each test file with BEGIN and END markers
# for internal/pjdfsreport, and it exits nonzero only when the harness fails.
set -eu

usage='usage: guest-run.sh vol|tmp SUITE...'
mode=${1:?$usage}
shift
case "$mode" in
vol) base=/mnt/vol/pjdfstest ;;
tmp) base=/tmp/pjdfstest ;;
*)
	printf '%s\n' "$usage" >&2
	exit 2
	;;
esac

rm -rf "$base"
cp -r /workspace "$base"
chmod +x "$base/pjdfstest"
for suite in "$@"; do
	[ -d "$base/tests/$suite" ] || continue
	mkdir -p "/mnt/vol/work/$suite"
	cd "/mnt/vol/work/$suite"
	for t in "$base/tests/$suite"/*.t; do
		name="$suite/${t##*/}"
		echo "@@ BEGIN $name"
		rc=0
		sh "$t" 2>&1 || rc=$?
		echo "@@ END $name rc=$rc"
	done
done
