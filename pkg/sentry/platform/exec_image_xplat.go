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

package platform

import (
	"io"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
)

// MappingKind says what backs the virtual memory area that holds an address.
type MappingKind int

const (
	// MappingUnmapped means that no virtual memory area holds the address.
	MappingUnmapped MappingKind = iota
	// MappingAnonymous means that no file backs the area.
	MappingAnonymous
	// MappingSpecial means that the Sentry itself provides the area, as it does
	// for the vDSO.
	MappingSpecial
	// MappingFile means that a file backs the area.
	MappingFile
)

// ExecImage describes the mapping behind one address. A platform that
// rewrites executable pages uses it to tell code from data in a page that
// holds both.
type ExecImage struct {
	Kind MappingKind

	// The remaining fields are set for MappingFile only.

	// Device and Inode identify the file.
	Device, Inode uint64
	// Offset is the file offset that the address maps.
	Offset uint64
	// File reads the file at absolute offsets. The caller calls Release when
	// it no longer needs File.
	File    io.ReaderAt
	Release func()
}

// ExecImageProvider is implemented by a MemoryManager that can report the
// mapping behind an address. A platform that needs the information asserts
// its MemoryManager to this interface.
type ExecImageProvider interface {
	// ExecImageAt reports what backs addr. For a file mapping it returns a
	// reader of the whole file, not only of the mapped part, because section
	// headers sit beyond the last mapped segment.
	ExecImageAt(ctx context.Context, addr hostarch.Addr) ExecImage
}

// SubBlockPopulator is implemented by a MemoryManager that can populate a 4KB
// sub-block inside a larger host page.
type SubBlockPopulator interface {
	// PopulateSubBlock ensures that a readable virtual memory area at addr is
	// mapped into the active AddressSpace.
	PopulateSubBlock(ctx context.Context, addr hostarch.Addr) bool
}
