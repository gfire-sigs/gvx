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

package ext4lite

import (
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// The per-call flags of preadv2 and pwritev2 that pkg/abi/linux does not name.
const (
	rwfNoWait   = 0x8
	rwfAppend   = 0x10
	rwfNoAppend = 0x20
)

// checkRWFlags validates the flags of one read or write call as the Linux
// function kiocb_set_rw_flags does. A flag that ext4 does not serve, such as
// RWF_ATOMIC, fails with EOPNOTSUPP. RWF_APPEND with RWF_NOAPPEND fails with
// EINVAL.
//
// RWF_NOWAIT needs no check of its own. Linux returns EAGAIN when a read finds
// a page outside the page cache or when a write needs a lock that is busy. This
// driver has no page cache between a call and the engine, and the engine holds
// every lock for the length of one in-memory change and its host write. A call
// therefore never has a reason to refuse, and the flag only has to pass.
func checkRWFlags(flags uint32) error {
	const supported = linux.RWF_HIPRI | linux.RWF_DSYNC | linux.RWF_SYNC | rwfNoWait | rwfAppend | rwfNoAppend
	if flags&^supported != 0 {
		return linuxerr.EOPNOTSUPP
	}
	if flags&rwfAppend != 0 && flags&rwfNoAppend != 0 {
		return linuxerr.EINVAL
	}
	return nil
}

// appendsWrite reports whether a write goes to the end of the file. The flag
// O_APPEND of the description selects it, RWF_APPEND selects it for one call,
// and RWF_NOAPPEND removes O_APPEND for one call.
func appendsWrite(statusFlags, rwf uint32) bool {
	if rwf&rwfAppend != 0 {
		return true
	}
	return statusFlags&linux.O_APPEND != 0 && rwf&rwfNoAppend == 0
}
