// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build darwin || windows || linux

package e2e

import (
	"strings"
	"testing"
)

// bpffsScript repeats the steps of the Calico init container mount-bpffs. It
// tests the mountpoint, mounts bpffs, and reads the file system type that
// calico-node reads from /proc/mounts and from statfs.
const bpffsScript = `ok() { echo "$1"; }
bad() { echo "FAIL $*"; }
test -d /sys/fs/bpf && ok MOUNTPOINT-OK || bad "no /sys/fs/bpf"
[ "$(stat -c '%a %u' /sys/fs/bpf)" = "755 0" ] && ok MOUNTPOINT-MODE-OK || bad "mountpoint mode $(stat -c '%a %u' /sys/fs/bpf)"
[ -z "$(ls -A /sys/fs/bpf)" ] && ok EMPTY-OK || bad "mountpoint not empty"
mkdir -p /sys/fs/bpf && ok MKDIR-P-OK || bad "mkdir -p /sys/fs/bpf"
grep -q '^nodev[[:space:]]bpf$' /proc/filesystems && ok LISTED-OK || bad "bpf missing in /proc/filesystems"
[ "$(stat -f -c %t /sys/fs/bpf)" = "62656572" ] && ok SYSFS-MAGIC-OK || bad "magic before mount $(stat -f -c %t /sys/fs/bpf)"
mount --make-rshared / && ok RSHARED-OK || bad "make-rshared"
mount -t bpf bpffs /sys/fs/bpf && ok MOUNT-OK || bad "mount -t bpf"
[ "$(stat -f -c %t /sys/fs/bpf)" = "cafe4a11" ] && ok BPF-MAGIC-OK || bad "magic after mount $(stat -f -c %t /sys/fs/bpf)"
grep -q '^[a-z]* /sys/fs/bpf bpf rw' /proc/mounts && ok PROC-MOUNTS-OK || { bad "no bpf line in /proc/mounts"; grep bpf /proc/mounts; }
mkdir /sys/fs/bpf/tc && mkdir /sys/fs/bpf/tc/globals && ok BPF-MKDIR-OK || bad "mkdir in bpffs"
if touch /sys/fs/bpf/file 2>/dev/null; then bad "regular file in bpffs"; else ok BPF-NOFILE-OK; fi
rmdir /sys/fs/bpf/tc/globals /sys/fs/bpf/tc && ok BPF-RMDIR-OK || bad "rmdir in bpffs"
umount /sys/fs/bpf && ok UMOUNT-OK || bad umount
[ "$(stat -f -c %t /sys/fs/bpf)" = "62656572" ] && ok UMOUNT-MAGIC-OK || bad "magic after umount"
echo BPFFS-DONE
`

// TestE2ESysFsBpf checks that /sys/fs/bpf exists as in Linux and that bpffs
// mounts on it with the type and the magic number that Calico expects.
func TestE2ESysFsBpf(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat:  b.plat,
				image: "alpine:3.20",
				argv:  []string{"sh", "-c", bpffsScript},
			})
			requireContains(t, "guest output", out,
				"MOUNTPOINT-OK\n", "MOUNTPOINT-MODE-OK\n", "EMPTY-OK\n", "MKDIR-P-OK\n", "LISTED-OK\n",
				"SYSFS-MAGIC-OK\n", "RSHARED-OK\n", "MOUNT-OK\n", "BPF-MAGIC-OK\n", "PROC-MOUNTS-OK\n",
				"BPF-MKDIR-OK\n", "BPF-NOFILE-OK\n", "BPF-RMDIR-OK\n", "UMOUNT-OK\n", "UMOUNT-MAGIC-OK\n", "BPFFS-DONE\n")
			if strings.Contains(out, "FAIL ") {
				t.Errorf("guest reported failures:\n%s", out)
			}
		})
	}
}
