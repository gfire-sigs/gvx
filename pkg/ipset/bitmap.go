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

import "time"

// createBitmapPort fills the bitmap:port part of a set.
func (s *Set) createBitmapPort(p *CreateParams) int {
	if !p.given(GivenPortFrom) || !p.given(GivenPortTo) {
		return -ErrProtocol
	}
	s.portFrom, s.portTo = p.PortFrom, p.PortTo
	if s.portFrom > s.portTo {
		s.portFrom, s.portTo = s.portTo, s.portFrom
	}
	// The count of elements never reaches the limit of a hash set.
	s.maxElem = 1 << 17
	return 0
}

// bitmapUadt runs an operation of a request on a bitmap:port set.
func (s *Set) bitmapUadt(adt Adt, e *Element, flags uint32) int {
	if !e.has(HasPort) {
		return -ErrProtocol
	}
	port := uint32(e.Port)
	if port < uint32(s.portFrom) || port > uint32(s.portTo) {
		return -ErrBitmapRange
	}
	x, ret := s.getExtensions(e)
	if ret != 0 {
		return ret
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if adt == AdtTest {
		return s.hashApply(adt, hashKey{port: uint16(port)}, false, &x, flags, now)
	}
	portTo := port
	if e.has(HasPortTo) {
		portTo = uint32(e.PortTo)
		if port > portTo {
			port, portTo = portTo, port
			if port < uint32(s.portFrom) {
				return -ErrBitmapRange
			}
		}
	}
	if portTo > uint32(s.portTo) {
		return -ErrBitmapRange
	}
	for ; port <= portTo; port++ {
		ret = s.hashApply(adt, hashKey{port: uint16(port)}, false, &x, flags, now)
		if ret != 0 && !(ret == -ErrExist && flags&FlagExist != 0) {
			return ret
		}
	}
	return 0
}

// bitmapKadt runs an operation on the port of a packet.
func (s *Set) bitmapKadt(adt Adt, pkt *Packet, o *KOpt) int {
	if !pkt.PortsOK {
		return -errnoEINVAL
	}
	port := pkt.DstPort
	if o.Flags&KDimOneSrc != 0 {
		port = pkt.SrcPort
	}
	if port < s.portFrom || port > s.portTo {
		return -ErrBitmapRange
	}
	x := ext{timeout: o.timeoutOr(s.defTimeout), packets: 1, bytes: uint64(pkt.Len), target: true}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	k := hashKey{port: port}
	if adt == AdtTest {
		return s.hashTest(k, &x, o, o.CmdFlags, now)
	}
	return s.hashApply(adt, k, false, &x, o.CmdFlags, now)
}

// bitmapElement builds the listed form of a stored element.
func (s *Set) bitmapElement(e *entry, now time.Duration) Element {
	out := Element{Has: HasPort, Port: e.key.port}
	s.outputExtensions(&out, &e.extensionData, now)
	return out
}
