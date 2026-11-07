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

package mm

import (
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
)

// WithPinnedMappings calls f with the internal mappings of the length bytes at
// addr. The mappings stay valid, and keep backing addr, until f returns: a
// call that unmaps or replaces the range, such as munmap(2), mmap(2) with
// MAP_FIXED, or mprotect(2), waits for f. A caller that needs several writes to
// reach one set of frames makes them all in f, because each CopyOut call looks
// up the frames again.
//
// f writes through the mappings and ignores the permissions of the range. It
// must run synchronously, and it must not retain the mappings after it
// returns. It must not call into mm, because mm.activeMu is locked.
//
// WithPinnedMappings returns EFAULT, and does not call f, if a part of the
// range has no mapping.
//
// +checklocksexclude:mm.mappingMu
// +checklocksexclude:mm.activeMu
func (mm *MemoryManager) WithPinnedMappings(ctx context.Context, addr hostarch.Addr, length int, f func(safemem.BlockSeq) error) error {
	ar, ok := mm.CheckIORange(addr, int64(length))
	if !ok || length == 0 {
		return linuxerr.EFAULT
	}
	_, err := mm.withInternalMappings(ctx, ar, hostarch.Write, true /* ignorePermissions */, func(ims safemem.BlockSeq) (uint64, error) {
		if ims.NumBytes() < uint64(length) {
			return 0, linuxerr.EFAULT
		}
		if err := f(ims); err != nil {
			return 0, err
		}
		return uint64(length), nil
	})
	return err
}
