// Copyright 2021 The gVisor Authors.
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

package stack

import "unsafe"

// PacketBufferStructSize is the per-packet overhead charged to checkpointed
// queues. It excludes auxiliary storage that exists only on pooled packets.
const PacketBufferStructSize = int(unsafe.Sizeof(PacketBuffer{}))

// The pool allocates the saved packet layout and its unsaved metadata together.
// packet must be first so a marked *PacketBuffer points to the same allocation.
type pooledPacketBuffer struct {
	packet  PacketBuffer
	policy  PacketPolicyMetadata
	release func()
}

func (pk *PacketBuffer) pooled() *pooledPacketBuffer {
	if pk.onRelease == nil {
		return nil
	}
	return (*pooledPacketBuffer)(unsafe.Pointer(pk))
}

// PacketPolicy returns the metadata belonging to a live packet, or nil for a
// packet decoded from a checkpoint. The metadata is borrowed with the packet.
func (pk *PacketBuffer) PacketPolicy() *PacketPolicyMetadata {
	if storage := pk.pooled(); storage != nil {
		return &storage.policy
	}
	return nil
}

func (pk *PacketBuffer) policyIngress() PacketPolicyIngress {
	if policy := pk.PacketPolicy(); policy != nil {
		return policy.Ingress
	}
	return PacketPolicyIngress{}
}

// ID returns a unique ID for the underlying storage of the packet.
//
// Two *PacketBuffers have the same IDs if and only if they point to the same
// location in memory.
func (pk *PacketBuffer) ID() uintptr {
	return uintptr(unsafe.Pointer(pk))
}
