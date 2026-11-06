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
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

// TestUnalignedFixedMMapChecksTheRangeFirst verifies the error order of
// mmap(2) with an unaligned MAP_FIXED address. Linux returns ENOMEM when the
// mapping ends above the task size, and EINVAL otherwise. A nested Sentry
// sizes its host address space with this probe, so a wrong error order gives
// it a task size that the outer guest does not have.
func TestUnalignedFixedMMapChecksTheRangeFirst(t *testing.T) {
	mm := newHoleMM(plainPlatform{}, 0, holeMin, holeMax)
	for _, tc := range []struct {
		name string
		addr hostarch.Addr
		len  uint64
		want error
	}{
		{"ends above the range", holeMax - holePage/2, 512, linuxerr.ENOMEM},
		{"starts above the range", holeMax + holePage + 1, 512, linuxerr.ENOMEM},
		{"address wraps", ^hostarch.Addr(0) - 1, 512, linuxerr.ENOMEM},
		{"ends inside the range", holeMax - holePage - 1, 512, linuxerr.EINVAL},
		{"ends one byte above the range", holeMax - holePage + 1, 512, linuxerr.ENOMEM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mm.MMap(nil, memmap.MMapOpts{
				Addr:     tc.addr,
				Fixed:    true,
				Length:   tc.len,
				Private:  true,
				MaxPerms: hostarch.AnyAccess,
			})
			if err != tc.want {
				t.Errorf("MMap(%#x, %d) = %v, want %v", uint64(tc.addr), tc.len, err, tc.want)
			}
		})
	}
}
