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

// Package genetlink provides a NETLINK_GENERIC socket protocol.
//
// The package implements the dispatcher of net/netlink/genetlink.c and the
// controller family "nlctrl" of CTRL_CMD_GETFAMILY. Other packages add a
// family with RegisterFamily from an init function. The wireguard package
// does this for the WireGuard family.
package genetlink

import (
	"fmt"
	"sync"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
)

const (
	// ControllerID is GENL_ID_CTRL, the family ID of the controller.
	ControllerID = 0x10

	// firstDynamicID is the first family ID that RegisterFamily assigns.
	// It is GENL_MIN_ID + 1 of include/uapi/linux/genetlink.h.
	firstDynamicID = ControllerID + 1

	// maxFamilyID is the largest family ID. It is GENL_MAX_ID.
	maxFamilyID = 1023

	// headerSize is GENL_HDRLEN, the size of struct genlmsghdr.
	headerSize = 4

	// maxNameLen is GENL_NAMSIZ, the size of a family name with its NUL byte.
	maxNameLen = 16

	// dumpMessageLimit is the size above which Dump.Message sends the
	// previous message in its own datagram. It is the size of one socket
	// buffer page of libmnl, less room for the header of the next message.
	dumpMessageLimit = 3584

	// dumpByteLimit is the size of all messages of one dump. A netlink socket
	// buffers 208 KiB of answers, and it drops a datagram when the buffer is
	// full. The Sentry builds a dump at once and has no way to wait for the
	// reader, so a dump that would pass the limit fails with ENOBUFS. A dump
	// then never ends with NLMSG_DONE after a lost message. The limit leaves
	// 16 KiB for the end of the dump.
	dumpByteLimit = 192 << 10
)

// OpFlags are the GENL_* command flags of include/uapi/linux/genetlink.h.
type OpFlags uint32

const (
	// OpNetAdmin is GENL_UNS_ADMIN_PERM. The caller needs CAP_NET_ADMIN in
	// the user namespace of its network namespace.
	OpNetAdmin OpFlags = 0x10

	// opCapDo is GENL_CMD_CAP_DO. The controller reports it for a command
	// with a Do function.
	opCapDo OpFlags = 0x02

	// opCapDump is GENL_CMD_CAP_DUMP. The controller reports it for a command
	// with a Dump function.
	opCapDump OpFlags = 0x04
)

// Request is one generic netlink request that the dispatcher accepted.
type Request struct {
	// Socket is the socket that sent the request. Its network namespace is
	// the namespace of the request.
	Socket *netlink.Socket

	// Header is the netlink header of the request.
	Header linux.NetlinkMessageHeader

	// Cmd and Version are the fields of struct genlmsghdr.
	Cmd     uint8
	Version uint8

	// Attrs holds the attributes after the generic and the family header.
	Attrs nlmsg.AttrsView
}

// Reply collects the answer of a command without the NLM_F_DUMP flag.
type Reply struct {
	family *Family
	ms     *nlmsg.MessageSet
}

// Message starts a reply message for the command cmd. The caller adds the
// attributes to the returned message.
func (r *Reply) Message(cmd uint8) *nlmsg.Message {
	return newMessage(r.ms, r.family, cmd)
}

// Dump sends the messages of a command with the NLM_F_DUMP flag. Each message
// leaves in its own datagram, so a reader with a 4,096-byte buffer does not
// truncate it.
type Dump struct {
	family *Family
	socket *netlink.Socket
	ctx    context.Context
	ms     *nlmsg.MessageSet
	// sent is the size of the messages that the dump already sent.
	sent int
}

// Message starts a dump message for the command cmd. The previous message of
// the dump is complete at this point, and Message sends it. A message must
// stay below MessageLimit bytes.
func (d *Dump) Message(cmd uint8) (*nlmsg.Message, *syserr.Error) {
	if err := d.flush(); err != nil {
		return nil, err
	}
	return newMessage(d.ms, d.family, cmd), nil
}

// MessageLimit returns the largest size of one dump message.
func (d *Dump) MessageLimit() int {
	return dumpMessageLimit
}

// flush sends the messages that the dump holds, except the last message of
// the whole dump, which the netlink socket sends before NLMSG_DONE.
func (d *Dump) flush() *syserr.Error {
	if len(d.ms.Messages) == 0 {
		return nil
	}
	if err := d.account(); err != nil {
		return err
	}
	d.sent += d.pending()
	part := &nlmsg.MessageSet{PortID: d.ms.PortID, Seq: d.ms.Seq, Messages: d.ms.Messages}
	d.ms.Clear()
	return d.socket.SendResponse(d.ctx, part)
}

// pending returns the size of the messages that the dump holds, with the
// alignment that the socket adds.
func (d *Dump) pending() int {
	n := 0
	for _, m := range d.ms.Messages {
		n += (len(m.Buffer()) + linux.NLMSG_ALIGNTO - 1) &^ (linux.NLMSG_ALIGNTO - 1)
	}
	return n
}

// account fails with ENOBUFS when the held messages would take the dump past
// dumpByteLimit.
func (d *Dump) account() *syserr.Error {
	if d.sent+d.pending() > dumpByteLimit {
		return syserr.ErrNoBufferSpace
	}
	return nil
}

// newMessage adds a message with the generic netlink header to ms.
func newMessage(ms *nlmsg.MessageSet, f *Family, cmd uint8) *nlmsg.Message {
	m := ms.AddMessage(linux.NetlinkMessageHeader{Type: f.id})
	hdr := primitive.ByteSlice{cmd, f.Version, 0, 0}
	m.Put(&hdr)
	return m
}

// Op is one command of a family.
type Op struct {
	// Cmd is the command number in the field cmd of struct genlmsghdr.
	Cmd uint8

	// Flags adds permission requirements to the command.
	Flags OpFlags

	// Do answers a request without the NLM_F_DUMP flag. It is nil when the
	// command has no such form.
	Do func(ctx context.Context, req *Request, reply *Reply) *syserr.Error

	// Dump answers a request with the NLM_F_DUMP flag. It is nil when the
	// command has no such form.
	Dump func(ctx context.Context, req *Request, dump *Dump) *syserr.Error
}

// Family is one generic netlink family. A registered family never changes.
type Family struct {
	// Name is the family name. It has at most 15 bytes.
	Name string

	// Version is the version of the family.
	Version uint8

	// HdrSize is the size of the family header after struct genlmsghdr.
	HdrSize uint32

	// MaxAttr is the largest attribute type that the family accepts.
	MaxAttr uint32

	// Ops lists the commands of the family.
	Ops []Op

	// id is the family ID that RegisterFamily assigned.
	id uint16
}

// ID returns the family ID that RegisterFamily assigned.
func (f *Family) ID() uint16 {
	return f.id
}

var (
	registryMu sync.RWMutex
	byID       = map[uint16]*Family{}
	byName     = map[string]*Family{}
	nextID     = uint16(firstDynamicID)
)

// RegisterFamily adds f to NETLINK_GENERIC and assigns its family ID. The ID
// is stable for the life of the process, but it depends on the order of the
// registrations, as it does on Linux.
//
// Preconditions: The name is unique and has 1 to 15 bytes. Each command has a
// Do function or a Dump function.
func RegisterFamily(f *Family) {
	if f.Name == "" || len(f.Name) >= maxNameLen {
		panic(fmt.Sprintf("genetlink: invalid family name %q", f.Name))
	}
	for i := range f.Ops {
		if f.Ops[i].Do == nil && f.Ops[i].Dump == nil {
			panic(fmt.Sprintf("genetlink: command %d of %q has no handler", f.Ops[i].Cmd, f.Name))
		}
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, ok := byName[f.Name]; ok {
		panic(fmt.Sprintf("genetlink: family %q is already registered", f.Name))
	}
	if nextID > maxFamilyID {
		panic("genetlink: no free family ID")
	}
	f.id = nextID
	nextID++
	byID[f.id] = f
	byName[f.Name] = f
}

// lookupID returns the family with the given ID, or nil.
func lookupID(id uint16) *Family {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return byID[id]
}

// lookupName returns the family with the given name, or nil.
func lookupName(name string) *Family {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return byName[name]
}

// families returns every family in the order of the family IDs.
func families() []*Family {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]*Family, 0, len(byID))
	for id := uint16(ControllerID); id < nextID; id++ {
		if f, ok := byID[id]; ok {
			out = append(out, f)
		}
	}
	return out
}

// Protocol implements netlink.Protocol for NETLINK_GENERIC.
type Protocol struct{}

var _ netlink.Protocol = (*Protocol)(nil)

// NewProtocol creates a NETLINK_GENERIC netlink.Protocol.
func NewProtocol(t *kernel.Task) (netlink.Protocol, *syserr.Error) {
	return &Protocol{}, nil
}

// Protocol implements netlink.Protocol.Protocol.
func (p *Protocol) Protocol() int {
	return linux.NETLINK_GENERIC
}

// CanSend implements netlink.Protocol.CanSend.
func (p *Protocol) CanSend() bool {
	return true
}

// Receive implements netlink.Protocol.Receive.
func (p *Protocol) Receive(ctx context.Context, s *netlink.Socket, buf []byte) *syserr.Error {
	return s.ProcessMessages(ctx, buf)
}

// ProcessMessage implements netlink.Protocol.ProcessMessage.
//
// From net/netlink/genetlink.c:genl_rcv_msg. The netlink message type is the
// family ID.
func (p *Protocol) ProcessMessage(ctx context.Context, s *netlink.Socket, msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	hdr := msg.Header()
	f := lookupID(hdr.Type)
	if f == nil {
		return syserr.ErrNoFileOrDir
	}

	gh := make(primitive.ByteSlice, headerSize)
	attrs, ok := msg.GetData(&gh)
	if !ok {
		return syserr.ErrInvalidArgument
	}
	// The family header follows the generic header, padded to 4 bytes.
	if skip := int((f.HdrSize + 3) &^ 3); skip > 0 {
		if len(attrs) < skip {
			return syserr.ErrInvalidArgument
		}
		attrs = attrs[skip:]
	}
	req := &Request{Socket: s, Header: hdr, Cmd: gh[0], Version: gh[1], Attrs: attrs}

	var op *Op
	for i := range f.Ops {
		if f.Ops[i].Cmd == req.Cmd {
			op = &f.Ops[i]
			break
		}
	}
	if op == nil {
		return syserr.ErrNotSupported
	}
	if op.Flags&OpNetAdmin != 0 && !s.NetworkNamespace().HasCapability(ctx, linux.CAP_NET_ADMIN) {
		return syserr.ErrNotPermitted
	}

	if hdr.Flags&linux.NLM_F_DUMP == linux.NLM_F_DUMP {
		if op.Dump == nil {
			return syserr.ErrNotSupported
		}
		ms.Multi = true
		d := &Dump{family: f, socket: s, ctx: ctx, ms: ms}
		err := op.Dump(ctx, req, d)
		if err == nil {
			err = d.account()
		}
		if err != nil {
			// Drop the unfinished message. The socket then sends only the error.
			ms.Clear()
			ms.Multi = false
			return err
		}
		return nil
	}
	if op.Do == nil {
		return syserr.ErrNotSupported
	}
	return op.Do(ctx, req, &Reply{family: f, ms: ms})
}

func init() {
	netlink.RegisterProvider(linux.NETLINK_GENERIC, NewProtocol)
	registerController()
}
