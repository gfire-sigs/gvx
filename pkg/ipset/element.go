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

package ipset

// Present is a bit set of the attributes that an Element or a CreateParams
// carries.
type Present uint32

// The attributes of an Element.
const (
	HasIP Present = 1 << iota
	HasIPTo
	HasCIDR
	HasPort
	HasPortTo
	HasProto
	HasIP2
	HasIP2To
	HasCIDR2
	HasName
	HasNameRef
	HasCadtFlags
	HasTimeout
	HasPackets
	HasBytes
	HasComment
	HasSkbMark
	HasSkbPrio
	HasSkbQueue
)

// Element is one element of a set in the form of the attributes of the ADD,
// DEL, and TEST commands. The netlink layer fills it from a request, and a
// listing fills it from a stored element. A field is valid when its bit is
// in Has.
type Element struct {
	Has Present

	IP, IPTo   Addr
	IP2, IP2To Addr
	CIDR       uint8
	CIDR2      uint8
	Port       uint16
	PortTo     uint16
	Proto      uint8

	// Name and NameRef name the member and the reference member of a
	// list:set element.
	Name    string
	NameRef string

	CadtFlags uint32
	// Timeout is the timeout in seconds. In a listing it is the remaining
	// time, or zero for an element with no timeout.
	Timeout uint32
	Packets uint64
	Bytes   uint64
	Comment string

	// SkbMark has the mark in its upper half and the mask in its lower half.
	SkbMark  uint64
	SkbPrio  uint32
	SkbQueue uint16
}

func (e *Element) has(p Present) bool { return e.Has&p != 0 }

// SkbInfo is the packet information that an element stores.
//
// +stateify savable
type SkbInfo struct {
	Mark     uint32
	MarkMask uint32
	Prio     uint32
	Queue    uint16
}

// ext is the extension data that an add operation stores in an element. It
// is struct ip_set_ext of Linux.
type ext struct {
	timeout uint32
	// packets and bytes are ^uint64(0) when the request gives no value.
	packets, bytes uint64
	comment        string
	skbinfo        SkbInfo
	// target is true when the data comes from a packet.
	target bool
}
