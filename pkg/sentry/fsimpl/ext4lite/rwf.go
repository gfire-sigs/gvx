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
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/fsutilx"
)

// The per-call flags of preadv2 and pwritev2 that pkg/abi/linux does not name.
const (
	rwfNoWait   = fsutilx.RWFNoWait
	rwfAppend   = fsutilx.RWFAppend
	rwfNoAppend = fsutilx.RWFNoAppend
)

// checkRWFlags validates the flags of one read or write call as the Linux
// function kiocb_set_rw_flags does. A flag that ext4 does not serve, such as
// RWF_ATOMIC, fails with EOPNOTSUPP. RWF_APPEND with RWF_NOAPPEND fails with
// EINVAL.
func checkRWFlags(flags uint32) error {
	return fsutilx.CheckRWFlags(flags)
}

// appendsWrite reports whether a write goes to the end of the file. The flag
// O_APPEND of the description selects it, RWF_APPEND selects it for one call,
// and RWF_NOAPPEND removes O_APPEND for one call.
func appendsWrite(statusFlags, rwf uint32) bool {
	return fsutilx.AppendsWrite(statusFlags, rwf)
}
