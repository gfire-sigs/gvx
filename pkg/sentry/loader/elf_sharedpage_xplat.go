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

package loader

import (
	"debug/elf"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/mm"
)

// mergeSharedPagePerms grants the union of permissions to any host page that
// holds parts of two or more PT_LOAD segments. On 16KB-page hosts, 4KB-aligned
// segments can place the tail of code and the head of data in one page.
// Mapping the later segment overwrites the earlier permissions and strips
// execute access from the shared code bytes. Ordered PT_LOAD segments can
// share only their first or last host page.
func mergeSharedPagePerms(ctx context.Context, m *mm.MemoryManager, phdrs []elf.ProgHeader, offset hostarch.Addr) error {
	type pageUse struct {
		perms hostarch.AccessType
		segs  int
	}
	pages := make(map[hostarch.Addr]*pageUse)
	touch := func(page hostarch.Addr, perms hostarch.AccessType) {
		u, ok := pages[page]
		if !ok {
			u = &pageUse{}
			pages[page] = u
		}
		u.segs++
		u.perms = u.perms.Union(perms)
	}
	for i := range phdrs {
		phdr := &phdrs[i]
		if phdr.Type != elf.PT_LOAD || phdr.Memsz == 0 {
			continue
		}
		start, ok := offset.AddLength(phdr.Vaddr)
		if !ok {
			return linuxerr.ENOEXEC
		}
		end, ok := start.AddLength(phdr.Memsz)
		if !ok {
			return linuxerr.ENOEXEC
		}
		limit, ok := end.RoundUp()
		if !ok {
			return linuxerr.ENOEXEC
		}
		perms := progFlagsAsPerms(phdr.Flags)
		first, last := start.RoundDown(), limit-hostarch.PageSize
		touch(first, perms)
		if last != first {
			touch(last, perms)
		}
	}
	for page, u := range pages {
		if u.segs < 2 {
			continue
		}
		if err := m.MProtect(page, hostarch.PageSize, u.perms, false); err != nil {
			ctx.Infof("Error merging permissions of the shared page at %#x: %v", page, err)
			return err
		}
	}
	return nil
}
