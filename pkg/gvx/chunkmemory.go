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

package gvx

import (
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

// memoryFileChunks lets hostfs keep the chunks of mapped files in the kernel
// memory file.
type memoryFileChunks struct{ *pgalloc.MemoryFile }

// AllocateChunk implements hostfs.ChunkMemory.
func (m memoryFileChunks) AllocateChunk(length uint64) (memmap.FileRange, error) {
	return m.Allocate(length, pgalloc.AllocOpts{Kind: usage.Anonymous})
}

// attachChunkMemory moves the chunks of mapped host directory files into the
// kernel memory file when the platform needs it. It covers every bind and
// volume mount. It must run before the first mapping.
func (s *Sandbox) attachChunkMemory() {
	if !sharedChunkMemory || s.memFile == nil {
		return
	}
	for _, ws := range s.workspaces {
		ws.SetChunkMemory(memoryFileChunks{s.memFile})
	}
}
