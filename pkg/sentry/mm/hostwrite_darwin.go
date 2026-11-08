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

//go:build darwin

package mm

import (
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

// The macOS platforms map the same pages that the Sentry writes, so these
// functions return f unchanged and cost nothing.

func (mm *MemoryManager) hostWriteWrap(_ hostarch.AddrRange, f func(safemem.BlockSeq) (uint64, error)) func(safemem.BlockSeq) (uint64, error) {
	return f
}

func (mm *MemoryManager) hostWriteWrapVec(_ hostarch.AddrRangeSeq, f func(safemem.BlockSeq) (uint64, error)) func(safemem.BlockSeq) (uint64, error) {
	return f
}

func mapInternalOf(file memmap.File, fr memmap.FileRange, perms hostarch.AccessType) (safemem.BlockSeq, error) {
	return file.MapInternal(fr, perms)
}
