#!/usr/bin/env bash
# Build the pjdfstest bundle inside an Alpine guest and adapt its shell
# helpers to busybox. The bundle holds the pjdfstest binary and tests/.
set -euo pipefail

readonly usage='usage: build-bundle.sh RUNGV CACHE_DIR BUNDLE_DIR'
readonly rungv=${1:?$usage} cache=${2:?$usage} bundle=${3:?$usage}
readonly platform=${PJDFS_PLATFORM:-systrap}
# The pinned commit keeps test numbers stable for known-failures.txt.
readonly pjdfstest_commit=85a8aea9e685999ef0540392fd80535f873d7ff7
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly script_dir

mkdir -p -- "$bundle" "$cache"
"$rungv" run -platform="$platform" -cache-dir="$cache" -workspace="$bundle" \
  -v pjdfs_build:/mnt/vol alpine:3.20 sh -c '
    set -e
    apk add --no-cache git build-base autoconf automake perl perl-utils >/dev/null
    git clone --quiet https://github.com/pjd/pjdfstest.git /mnt/vol/pjdfstest
    cd /mnt/vol/pjdfstest
    git checkout --quiet "$1"
    autoreconf -ifs
    CFLAGS="-O2 -Wl,-z,max-page-size=65536" ./configure >/dev/null
    make pjdfstest >/dev/null
    cp -r /mnt/vol/pjdfstest/* /workspace/
  ' sh "$pjdfstest_commit"

cat >"$bundle/tests/conf" <<'EOF'
os="Linux"
GREP="grep"
fs="EXT4"
EOF
# Shell expansions replace external commands, because each process start
# in the guest costs more than on a host.
sed -i.orig 's/dir=`dirname \$0`/dir=${0%\/*}/g' "$bundle"/tests/*/*.t
sed -i.orig '/^confdir=/,/^fstest=/c\
confdir="${dir}/.."\
maindir="${dir}/../.."\
fstest="${maindir}/pjdfstest"' "$bundle/tests/misc.sh"
find "$bundle/tests" -name '*.orig' -delete
cat "$script_dir/misc-overrides.sh" >>"$bundle/tests/misc.sh"
