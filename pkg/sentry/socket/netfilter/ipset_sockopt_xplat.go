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

package netfilter

import (
	"bytes"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/ipset"
	"z.gfire.dev/gvx/pkg/marshal"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// SO_IP_SET is the socket option at level SOL_IP with which iptables resolves
// the names of sets to indexes.
const SO_IP_SET = 83

// The operations of SO_IP_SET (include/uapi/linux/netfilter/ipset/ip_set.h).
const (
	ipSetOpGetByName  = 0x00000006
	ipSetOpGetByIndex = 0x00000007
	ipSetOpGetFName   = 0x00000008
	ipSetOpVersion    = 0x00000100
)

// The layouts of the request structs. Each starts with the operation and the
// version, both 32 bits wide. ip_set_req_get_set has the union ip_set_name_index
// next, and ip_set_req_get_set_family has the family before the union.
const (
	ipSetReqOpSize        = 4
	ipSetReqVersionSize   = 8
	ipSetReqOffVersion    = 4
	ipSetNameIndexSize    = ipset.MaxNameLen
	ipSetReqGetSetSize    = 8 + ipSetNameIndexSize
	ipSetReqGetFamilySize = 12 + ipSetNameIndexSize
	ipSetReqOffFamily     = 8
	ipSetReqOffSet        = 8
	ipSetReqFamilyOffSet  = 12
)

// IPSetSockOpt implements getsockopt(SOL_IP, SO_IP_SET) of Linux
// (ip_set_sockfn_get). It reads the request at outPtr and returns the reply
// with the length of the request.
func IPSetSockOpt(t *kernel.Task, stk *stack.Stack, outPtr hostarch.Addr, outLen int) (marshal.Marshallable, *syserr.Error) {
	if outLen < ipSetReqOpSize {
		return nil, syserr.ErrInvalidArgument
	}
	data := make([]byte, outLen)
	if _, err := t.CopyInBytes(outPtr, data); err != nil {
		return nil, syserr.FromError(err)
	}
	reply, err := ipSetGet(ipset.ExistingForStack(stk), data)
	if err != nil {
		return nil, err
	}
	out := primitive.ByteSlice(reply)
	return &out, nil
}

// ipSetGet answers the request in data. reg is nil when the network stack
// never had a set. The reply has the length of the request.
func ipSetGet(reg *ipset.Registry, data []byte) ([]byte, *syserr.Error) {
	order := hostarch.ByteOrder
	outLen := len(data)
	op := order.Uint32(data)
	if op < ipSetOpVersion {
		// Linux checks the version at the beginning of the operations.
		if outLen < ipSetReqVersionSize {
			return nil, syserr.ErrInvalidArgument
		}
		if order.Uint32(data[ipSetReqOffVersion:]) < ipset.ProtocolVersionMin {
			return nil, syserr.ErrProtocol
		}
	}

	switch op {
	case ipSetOpVersion:
		if outLen != ipSetReqVersionSize {
			return nil, syserr.ErrInvalidArgument
		}
		order.PutUint32(data[ipSetReqOffVersion:], ipset.ProtocolVersion)
	case ipSetOpGetByName:
		if outLen != ipSetReqGetSetSize {
			return nil, syserr.ErrInvalidArgument
		}
		id, _ := lookupSetByName(reg, data[ipSetReqOffSet:ipSetReqOffSet+ipSetNameIndexSize])
		order.PutUint16(data[ipSetReqOffSet:], uint16(id))
	case ipSetOpGetFName:
		if outLen != ipSetReqGetFamilySize {
			return nil, syserr.ErrInvalidArgument
		}
		id, family := lookupSetByName(reg, data[ipSetReqFamilyOffSet:ipSetReqFamilyOffSet+ipSetNameIndexSize])
		order.PutUint16(data[ipSetReqFamilyOffSet:], uint16(id))
		if id != ipset.InvalidID {
			order.PutUint32(data[ipSetReqOffFamily:], uint32(family))
		}
	case ipSetOpGetByIndex:
		if outLen != ipSetReqGetSetSize {
			return nil, syserr.ErrInvalidArgument
		}
		index := order.Uint16(data[ipSetReqOffSet:])
		limit := ipset.DefaultMaxSets
		if reg != nil {
			limit = reg.Len()
		}
		if int(index) >= limit {
			return nil, syserr.ErrInvalidArgument
		}
		var name string
		if reg != nil {
			name, _ = reg.NameByIndex(ipset.ID(index))
		}
		// Linux copies the name and its zero byte, and keeps the other
		// bytes of the field.
		n := copy(data[ipSetReqOffSet:ipSetReqOffSet+ipSetNameIndexSize], name)
		data[ipSetReqOffSet+n] = 0
	default:
		return nil, syserr.ErrInvalidDataMessage
	}
	return data, nil
}

// lookupSetByName returns the index and the family of the set that the name
// field of a request names. The name ends at the first zero byte, or at the
// last byte of the field. An unknown set gives ipset.InvalidID.
func lookupSetByName(reg *ipset.Registry, field []byte) (ipset.ID, uint8) {
	name := field[:len(field)-1]
	if end := bytes.IndexByte(name, 0); end >= 0 {
		name = name[:end]
	}
	if reg == nil {
		return ipset.InvalidID, 0
	}
	id, family, ok := reg.Lookup(string(name))
	if !ok {
		return ipset.InvalidID, 0
	}
	return id, family
}
