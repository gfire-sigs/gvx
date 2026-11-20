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

package virtgpu

import (
	"unsafe"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

// MapInternal implements memmap.File.MapInternal. The block is unsafe for
// plain loads and stores: the renderer process shares the memory, so Sentry
// copies go through safecopy.
func (b *blob) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	if fr.Start >= fr.End || fr.End > b.guestSize {
		return safemem.BlockSeq{}, linuxerr.EINVAL
	}
	return safemem.BlockSeqOf(safemem.BlockFromUnsafePointer(unsafe.Add(b.base, fr.Start), int(fr.Length()))), nil
}
