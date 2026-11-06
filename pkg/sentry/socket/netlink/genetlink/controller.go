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

package genetlink

import (
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
)

// Commands and attributes of the controller, from
// include/uapi/linux/genetlink.h.
const (
	ctrlCmdNewFamily = 1
	ctrlCmdGetFamily = 3

	ctrlAttrFamilyID   = 1
	ctrlAttrFamilyName = 2
	ctrlAttrVersion    = 3
	ctrlAttrHdrSize    = 4
	ctrlAttrMaxAttr    = 5
	ctrlAttrOps        = 6

	ctrlAttrOpID    = 1
	ctrlAttrOpFlags = 2

	ctrlAttrMax = 10
)

// registerController adds the family "nlctrl" with its fixed ID.
func registerController() {
	c := &Family{
		Name:    "nlctrl",
		Version: 2,
		MaxAttr: ctrlAttrMax,
		Ops: []Op{{
			Cmd:  ctrlCmdGetFamily,
			Do:   ctrlGetFamily,
			Dump: ctrlDumpFamilies,
		}},
		id: ControllerID,
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	byID[c.id] = c
	byName[c.Name] = c
}

// ParseAttrs returns the attributes of the request by type. It clears the
// NLA_F_NESTED and NLA_F_NET_BYTEORDER flags of each type.
func (r *Request) ParseAttrs() (map[uint16]nlmsg.BytesView, bool) {
	return ParseAttrs(r.Attrs)
}

// ParseAttrs returns the attributes in view by type, without the
// NLA_F_NESTED and NLA_F_NET_BYTEORDER flags of the types. A later attribute
// replaces an earlier one of the same type, as in the policy parser of Linux.
func ParseAttrs(view nlmsg.AttrsView) (map[uint16]nlmsg.BytesView, bool) {
	attrs := make(map[uint16]nlmsg.BytesView)
	for !view.Empty() {
		hdr, value, rest, ok := view.ParseFirst()
		if !ok {
			return nil, false
		}
		view = rest
		attrs[hdr.Type&linux.NLA_TYPE_MASK] = nlmsg.BytesView(value)
	}
	return attrs, true
}

// ctrlGetFamily answers CTRL_CMD_GETFAMILY for one family, selected by its
// ID or its name. From net/netlink/genetlink.c:ctrl_getfamily.
func ctrlGetFamily(_ context.Context, req *Request, reply *Reply) *syserr.Error {
	attrs, ok := req.ParseAttrs()
	if !ok {
		return syserr.ErrInvalidArgument
	}
	var f *Family
	if v, ok := attrs[ctrlAttrFamilyID]; ok {
		id, ok := v.Uint16()
		if !ok {
			return syserr.ErrInvalidArgument
		}
		f = lookupID(id)
	} else if v, ok := attrs[ctrlAttrFamilyName]; ok {
		name := v.String()
		if len(name) >= maxNameLen {
			return syserr.ErrInvalidArgument
		}
		f = lookupName(name)
	} else {
		return syserr.ErrInvalidArgument
	}
	if f == nil {
		return syserr.ErrNoFileOrDir
	}
	fillFamily(reply.Message(ctrlCmdNewFamily), f)
	return nil
}

// ctrlDumpFamilies answers CTRL_CMD_GETFAMILY with NLM_F_DUMP. It sends one
// message for each registered family.
func ctrlDumpFamilies(context.Context, *Request) (Dumper, *syserr.Error) {
	return &familyDump{families: families()}, nil
}

// familyDump sends the registered families, as many as each chunk holds.
type familyDump struct {
	families []*Family
}

// DumpChunk implements Dumper.DumpChunk.
func (d *familyDump) DumpChunk(_ context.Context, chunk *Chunk) (bool, *syserr.Error) {
	for len(d.families) > 0 {
		fillFamily(chunk.Message(ctrlCmdNewFamily), d.families[0])
		if chunk.Size() > chunk.Limit() && chunk.Count() > 1 {
			chunk.Discard()
			return true, nil
		}
		d.families = d.families[1:]
	}
	return false, nil
}

// DumpDone implements Dumper.DumpDone.
func (d *familyDump) DumpDone() { d.families = nil }

// fillFamily adds the attributes of ctrl_fill_info to m. The family has no
// multicast groups, so the message has no CTRL_ATTR_MCAST_GROUPS.
func fillFamily(m *nlmsg.Message, f *Family) {
	m.PutAttr(ctrlAttrFamilyID, primitive.AllocateUint16(f.id))
	m.PutAttrString(ctrlAttrFamilyName, f.Name)
	m.PutAttr(ctrlAttrVersion, primitive.AllocateUint32(uint32(f.Version)))
	m.PutAttr(ctrlAttrHdrSize, primitive.AllocateUint32(f.HdrSize))
	m.PutAttr(ctrlAttrMaxAttr, primitive.AllocateUint32(f.MaxAttr))
	if len(f.Ops) == 0 {
		return
	}
	var ops nlmsg.NestedAttr
	for i := range f.Ops {
		op := &f.Ops[i]
		flags := op.Flags
		if op.Do != nil {
			flags |= opCapDo
		}
		if op.Dump != nil {
			flags |= opCapDump
		}
		var entry nlmsg.NestedAttr
		entry.PutAttr(ctrlAttrOpID, primitive.AllocateUint32(uint32(op.Cmd)))
		entry.PutAttr(ctrlAttrOpFlags, primitive.AllocateUint32(uint32(flags)))
		// The type of each entry is its 1-based position.
		ops.PutAttr(uint16(i+1), primitive.AsByteSlice(entry))
	}
	m.PutAttr(ctrlAttrOps, primitive.AsByteSlice(ops))
}
