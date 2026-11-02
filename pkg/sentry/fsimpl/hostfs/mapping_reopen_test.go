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

package hostfs

import (
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

// TestAddMappingWithoutConfigureMMapAfterLastUnmap replays the calls of the
// overlay filesystem. It keeps the Mappable of a layer file and calls
// AddMapping for each later mmap, without ConfigureMMap and after the file
// description that configured the first mapping has closed.
func TestAddMappingWithoutConfigureMMapAfterLastUnmap(t *testing.T) {
	for _, tc := range []struct {
		name     string
		flags    uint32
		writable bool
		at       hostarch.AccessType
	}{
		{"read-only", linux.O_RDONLY, false, hostarch.Read},
		{"shared-writable", linux.O_RDWR, true, hostarch.ReadWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forEachChunkMode(t, func(t *testing.T, e *env) {
				content := []byte("twenty-six bytes of data.")
				e.writeFile("layer-file", content)
				fd := e.mustOpen("layer-file", tc.flags)
				const length = hostarch.PageSize
				m, ms, ar := e.mapFile(fd, length, tc.writable)
				m.RemoveMapping(e.ctx, ms, ar, 0, tc.writable)
				fd.DecRef(e.ctx)
				data := m.(*fileData)
				data.DataMu.Lock()
				held := data.mh != nil || data.pending != nil
				data.DataMu.Unlock()
				if held {
					t.Fatal("the file data holds a handle after the last unmap")
				}

				ms2 := &recordingSpace{}
				ar2 := hostarch.AddrRange{Start: 0x50000, End: 0x50000 + length}
				if err := m.AddMapping(e.ctx, ms2, ar2, 0, tc.writable); err != nil {
					t.Fatalf("AddMapping after the last unmap: %v", err)
				}
				required := memmap.MappableRange{Start: 0, End: hostarch.PageSize}
				ts, err := m.Translate(e.ctx, required, required, tc.at)
				if err != nil || len(ts) == 0 {
					t.Fatalf("Translate after AddMapping = (%v, %v), want a translation", ts, err)
				}
				bs, err := ts[0].File.MapInternal(memmap.FileRange{Start: ts[0].Offset, End: ts[0].Offset + uint64(len(content))}, hostarch.Read)
				if err != nil {
					t.Fatalf("MapInternal: %v", err)
				}
				if bs.NumBlocks() != 1 {
					t.Fatalf("MapInternal returned %d blocks, want 1", bs.NumBlocks())
				}
				if got := bs.Head().ToSlice(); string(got) != string(content) {
					t.Errorf("mapped bytes = %q, want %q", bs.Head().ToSlice(), content)
				}

				m.RemoveMapping(e.ctx, ms2, ar2, 0, tc.writable)
				data.DataMu.Lock()
				held = data.mh != nil || data.pending != nil
				data.DataMu.Unlock()
				if held {
					t.Error("the file data holds a handle after the second last unmap")
				}
			})
		})
	}
}
