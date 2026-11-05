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
	"encoding/binary"
	"errors"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/ipset"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/syserr"
)

// This file implements the subsystem NFNL_SUBSYS_IPSET of NETLINK_NETFILTER.
// The ipset tool, kube-router, and Calico use it to create sets and to list
// and change their elements. The commands and the error codes follow
// net/netfilter/ipset/ip_set_core.c. The sets themselves live in package
// ipset.

// Commands of the subsystem (enum ipset_cmd).
const (
	ipsetCmdNone = iota
	ipsetCmdProtocol
	ipsetCmdCreate
	ipsetCmdDestroy
	ipsetCmdFlush
	ipsetCmdRename
	ipsetCmdSwap
	ipsetCmdList
	ipsetCmdSave
	ipsetCmdAdd
	ipsetCmdDel
	ipsetCmdTest
	ipsetCmdHeader
	ipsetCmdType
	ipsetCmdGetByName
	ipsetCmdGetByIndex
	ipsetMsgMax
)

// Attributes at command level.
const (
	ipsetAttrProtocol  = 1
	ipsetAttrSetname   = 2
	ipsetAttrTypename  = 3
	ipsetAttrSetname2  = 3
	ipsetAttrRevision  = 4
	ipsetAttrFamily    = 5
	ipsetAttrFlags     = 6
	ipsetAttrData      = 7
	ipsetAttrADT       = 8
	ipsetAttrLineno    = 9
	ipsetAttrRevMin    = 10
	ipsetAttrIndex     = 11
	ipsetAttrCmdMax    = 11
	ipsetAttrProtoMin  = 10
	ipsetAttrIPAddrV4  = 1
	ipsetAttrIPAddrV6  = 2
	ipsetAttrIPAddrMax = 2
)

// Attributes of the elements and of the create request.
const (
	ipsetAttrIP         = 1
	ipsetAttrIPTo       = 2
	ipsetAttrCIDR       = 3
	ipsetAttrPort       = 4
	ipsetAttrPortTo     = 5
	ipsetAttrTimeout    = 6
	ipsetAttrProto      = 7
	ipsetAttrCadtFlags  = 8
	ipsetAttrMark       = 10
	ipsetAttrMarkmask   = 11
	ipsetAttrBitmask    = 12
	ipsetAttrCadtMax    = 16
	ipsetAttrInitval    = 17
	ipsetAttrHashsize   = 18
	ipsetAttrMaxelem    = 19
	ipsetAttrNetmask    = 20
	ipsetAttrBucketsize = 21
	ipsetAttrResize     = 22
	ipsetAttrSize       = 23
	ipsetAttrElements   = 24
	ipsetAttrReferences = 25
	ipsetAttrMemsize    = 26
	ipsetAttrCreateMax  = 26

	ipsetAttrEther    = 17
	ipsetAttrName     = 18
	ipsetAttrNameRef  = 19
	ipsetAttrIP2      = 20
	ipsetAttrCIDR2    = 21
	ipsetAttrIP2To    = 22
	ipsetAttrIface    = 23
	ipsetAttrBytes    = 24
	ipsetAttrPackets  = 25
	ipsetAttrComment  = 26
	ipsetAttrSkbMark  = 27
	ipsetAttrSkbPrio  = 28
	ipsetAttrSkbQueue = 29
	ipsetAttrPad      = 30
	ipsetAttrADTMax   = 30
)

const (
	nlaFNested       = 1 << 15
	nlaFNetByteorder = 1 << 14

	// ipsetMaxNameLen is IPSET_MAXNAMELEN.
	ipsetMaxNameLen = 32
)

// attrKind is the policy type of an attribute.
type attrKind uint8

const (
	kindUnspec attrKind = iota
	kindU8
	kindU16
	kindU32
	kindU64
	kindString
	kindNested
	kindBinary
)

// attrPolicy describes the size rule of one attribute: the minimum size of a
// number, or the longest string without its NUL byte.
type attrPolicy struct {
	kind   attrKind
	maxLen int
}

var cmdPolicy = map[uint16]attrPolicy{
	ipsetAttrProtocol: {kind: kindU8},
	ipsetAttrSetname:  {kind: kindString, maxLen: ipsetMaxNameLen - 1},
	ipsetAttrTypename: {kind: kindString, maxLen: ipsetMaxNameLen - 1},
	ipsetAttrRevision: {kind: kindU8},
	ipsetAttrFamily:   {kind: kindU8},
	ipsetAttrFlags:    {kind: kindU32},
	ipsetAttrData:     {kind: kindNested},
	ipsetAttrADT:      {kind: kindNested},
	ipsetAttrLineno:   {kind: kindU32},
	ipsetAttrIndex:    {kind: kindU16},
}

var createPolicy = map[uint16]attrPolicy{
	ipsetAttrPort:       {kind: kindU16},
	ipsetAttrPortTo:     {kind: kindU16},
	ipsetAttrTimeout:    {kind: kindU32},
	ipsetAttrCadtFlags:  {kind: kindU32},
	ipsetAttrMarkmask:   {kind: kindU32},
	ipsetAttrBitmask:    {kind: kindNested},
	ipsetAttrInitval:    {kind: kindU32},
	ipsetAttrHashsize:   {kind: kindU32},
	ipsetAttrMaxelem:    {kind: kindU32},
	ipsetAttrNetmask:    {kind: kindU8},
	ipsetAttrBucketsize: {kind: kindU8},
	ipsetAttrResize:     {kind: kindU8},
	ipsetAttrSize:       {kind: kindU32},
}

var adtPolicy = map[uint16]attrPolicy{
	ipsetAttrIP:        {kind: kindNested},
	ipsetAttrIPTo:      {kind: kindNested},
	ipsetAttrCIDR:      {kind: kindU8},
	ipsetAttrPort:      {kind: kindU16},
	ipsetAttrPortTo:    {kind: kindU16},
	ipsetAttrTimeout:   {kind: kindU32},
	ipsetAttrProto:     {kind: kindU8},
	ipsetAttrCadtFlags: {kind: kindU32},
	ipsetAttrLineno:    {kind: kindU32},
	ipsetAttrMark:      {kind: kindU32},
	ipsetAttrEther:     {kind: kindBinary},
	ipsetAttrName:      {kind: kindString, maxLen: ipsetMaxNameLen},
	ipsetAttrNameRef:   {kind: kindString, maxLen: ipsetMaxNameLen},
	ipsetAttrIP2:       {kind: kindNested},
	ipsetAttrCIDR2:     {kind: kindU8},
	ipsetAttrIP2To:     {kind: kindNested},
	ipsetAttrIface:     {kind: kindString, maxLen: 15},
	ipsetAttrBytes:     {kind: kindU64},
	ipsetAttrPackets:   {kind: kindU64},
	ipsetAttrComment:   {kind: kindString, maxLen: ipset.MaxCommentSize},
	ipsetAttrSkbMark:   {kind: kindU64},
	ipsetAttrSkbPrio:   {kind: kindU32},
	ipsetAttrSkbQueue:  {kind: kindU16},
}

var ipAddrPolicy = map[uint16]attrPolicy{
	ipsetAttrIPAddrV4: {kind: kindU32},
	ipsetAttrIPAddrV6: {kind: kindBinary},
}

// ipsetAttr is a parsed attribute.
type ipsetAttr struct {
	value []byte
	flags uint16
	// offset is the position of the value in the message.
	offset int
}

func (a ipsetAttr) netOrder() bool { return a.flags&nlaFNetByteorder != 0 }

func (a ipsetAttr) u8() uint8    { return a.value[0] }
func (a ipsetAttr) be16() uint16 { return binary.BigEndian.Uint16(a.value) }
func (a ipsetAttr) be32() uint32 { return binary.BigEndian.Uint32(a.value) }
func (a ipsetAttr) be64() uint64 { return binary.BigEndian.Uint64(a.value) }

// str returns the string of a NUL terminated attribute.
func (a ipsetAttr) str() string {
	end := bytes.IndexByte(a.value, 0)
	if end < 0 {
		end = len(a.value)
	}
	return string(a.value[:end])
}

type ipsetAttrs map[uint16]ipsetAttr

// parseIPSetAttrs parses a list of attributes, and it validates the attributes
// that policy names. An attribute of a type above maxType is skipped. base is
// the position of b in the message. It reports false for a malformed list.
func parseIPSetAttrs(b []byte, base int, maxType uint16, policy map[uint16]attrPolicy) (ipsetAttrs, bool) {
	attrs := make(ipsetAttrs)
	pos := 0
	for len(b)-pos >= linux.NetlinkAttrHeaderSize {
		l := int(binary.NativeEndian.Uint16(b[pos:]))
		typ := binary.NativeEndian.Uint16(b[pos+2:])
		if l < linux.NetlinkAttrHeaderSize || l > len(b)-pos {
			return nil, false
		}
		flags := typ & (nlaFNested | nlaFNetByteorder)
		typ &^= nlaFNested | nlaFNetByteorder
		value := b[pos+linux.NetlinkAttrHeaderSize : pos+l]
		if typ <= maxType {
			if p, ok := policy[typ]; ok && !validAttr(p, value) {
				return nil, false
			}
			attrs[typ] = ipsetAttr{value: value, flags: flags, offset: base + pos + linux.NetlinkAttrHeaderSize}
		}
		pos += (l + linux.NLA_ALIGNTO - 1) &^ (linux.NLA_ALIGNTO - 1)
	}
	return attrs, true
}

// validAttr applies the policy of one attribute to its value.
func validAttr(p attrPolicy, v []byte) bool {
	switch p.kind {
	case kindU8:
		return len(v) >= 1
	case kindU16:
		return len(v) >= 2
	case kindU32:
		return len(v) >= 4
	case kindU64:
		return len(v) >= 8
	case kindString:
		// A NUL byte must end the string within the length limit.
		window := len(v)
		if p.maxLen > 0 {
			window = min(window, p.maxLen+1)
		}
		return window > 0 && bytes.IndexByte(v[:window], 0) >= 0
	}
	return true
}

// attrBuilder builds the attributes of a reply.
type attrBuilder struct{ b []byte }

func (a *attrBuilder) put(typ uint16, data []byte) {
	a.b = binary.NativeEndian.AppendUint16(a.b, uint16(linux.NetlinkAttrHeaderSize+len(data)))
	a.b = binary.NativeEndian.AppendUint16(a.b, typ)
	a.b = append(a.b, data...)
	for len(a.b)%linux.NLA_ALIGNTO != 0 {
		a.b = append(a.b, 0)
	}
}

func (a *attrBuilder) u8(typ uint16, v uint8) { a.put(typ, []byte{v}) }

func (a *attrBuilder) str(typ uint16, s string) { a.put(typ, append([]byte(s), 0)) }

func (a *attrBuilder) net16(typ uint16, v uint16) {
	a.put(typ|nlaFNetByteorder, binary.BigEndian.AppendUint16(nil, v))
}

func (a *attrBuilder) net32(typ uint16, v uint32) {
	a.put(typ|nlaFNetByteorder, binary.BigEndian.AppendUint32(nil, v))
}

func (a *attrBuilder) net64(typ uint16, v uint64) {
	a.put(typ|nlaFNetByteorder, binary.BigEndian.AppendUint64(nil, v))
}

// nest adds a nested attribute whose content fn writes.
func (a *attrBuilder) nest(typ uint16, fn func()) {
	start := len(a.b)
	a.b = binary.NativeEndian.AppendUint16(a.b, 0)
	a.b = binary.NativeEndian.AppendUint16(a.b, typ|nlaFNested)
	fn()
	binary.NativeEndian.PutUint16(a.b[start:], uint16(len(a.b)-start))
}

// ipaddr adds an address as the nested attribute typ.
func (a *attrBuilder) ipaddr(typ uint16, family uint8, addr ipset.Addr) {
	a.nest(typ, func() {
		if family == ipset.FamilyIPv6 {
			a.put(ipsetAttrIPAddrV6|nlaFNetByteorder, addr[:])
			return
		}
		a.put(ipsetAttrIPAddrV4|nlaFNetByteorder, addr[:4])
	})
}

// processIPSet handles one message of the subsystem NFNL_SUBSYS_IPSET.
func processIPSet(ctx context.Context, s *netlink.Socket, msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	stk := s.Stack().(*netstack.Stack).Stack
	reg := ipset.ForStack(stk, ipset.ModuleFor(kernel.KernelFromContext(ctx)))
	return serveIPSet(reg, s, msg, ms)
}

// ipsetRequest is one message that serveIPSet answers.
type ipsetRequest struct {
	reg   *ipset.Registry
	dumps dumpStarter
	msg   *nlmsg.Message
	ms    *nlmsg.MessageSet
	hdr   linux.NetlinkMessageHeader
	attrs ipsetAttrs
}

// serveIPSet answers one message of the subsystem NFNL_SUBSYS_IPSET. It writes
// an error as an NLMSG_ERROR message that carries the request, as Linux does,
// because the ipset library decodes the request in the answer.
func serveIPSet(reg *ipset.Registry, dumps dumpStarter, msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	hdr := msg.Header()
	r := &ipsetRequest{reg: reg, dumps: dumps, msg: msg, ms: ms, hdr: hdr}
	cmd := int(hdr.NetFilterMsgType())
	if cmd >= ipsetMsgMax {
		return r.fail(errnoInval)
	}
	var gen linux.NetFilterGenMsg
	view, ok := msg.GetData(&gen)
	if !ok {
		return nil
	}
	offset := len(msg.Buffer()) - len(view)
	attrs, ok := parseIPSetAttrs(view, offset, ipsetAttrCmdMax, cmdPolicy)
	if !ok {
		return r.fail(errnoInval)
	}
	r.attrs = attrs
	var code int
	switch cmd {
	case ipsetCmdProtocol:
		code = r.protocol()
	case ipsetCmdCreate:
		code = r.create()
	case ipsetCmdDestroy:
		code = r.destroy()
	case ipsetCmdFlush:
		code = r.flush()
	case ipsetCmdRename:
		code = r.rename()
	case ipsetCmdSwap:
		code = r.swap()
	case ipsetCmdList, ipsetCmdSave:
		code = r.list()
	case ipsetCmdAdd:
		code = r.adt(ipset.AdtAdd)
	case ipsetCmdDel:
		code = r.adt(ipset.AdtDel)
	case ipsetCmdTest:
		code = r.test()
	case ipsetCmdHeader:
		code = r.header()
	case ipsetCmdType:
		code = r.typeInfo()
	case ipsetCmdGetByName:
		code = r.getByName()
	case ipsetCmdGetByIndex:
		code = r.getByIndex()
	default:
		code = -errnoNotSupported
	}
	if code == codeAnswered {
		return nil
	}
	if code != 0 {
		return r.fail(-code)
	}
	return nil
}

// codeAnswered is the result of a command that already wrote its error
// message. It stops a batch, as the error EINTR of call_ad does in Linux.
const codeAnswered = -1 << 20

// errno values of Linux for the errors that this file returns itself.
const (
	errnoInval        = 22
	errnoNotSupported = 95
	errnoNoEnt        = 2
)

// fail answers the request with an error. An error with a failing element in
// a batch carries the line number of that element.
func (r *ipsetRequest) fail(errno int) *syserr.Error {
	r.failWith(errno, r.msg.Buffer())
	return nil
}

// failWith adds the NLMSG_ERROR message that carries request.
func (r *ipsetRequest) failWith(errno int, request []byte) {
	m := r.ms.AddMessage(linux.NetlinkMessageHeader{Type: linux.NLMSG_ERROR})
	m.Put(primitive.AllocateInt32(int32(-errno)))
	m.Put(primitive.AsByteSlice(request))
	r.ms.ContainsError = true
}

// codeOf converts the error of the registry to a negative code.
func codeOf(err error) int {
	if err == nil {
		return 0
	}
	var e *ipset.Error
	if errors.As(err, &e) {
		return -e.Code
	}
	return -errnoInval
}

// protocolFailed is protocol_failed of Linux: the request does not carry the
// protocol version of the kernel.
func (r *ipsetRequest) protocolFailed() bool {
	a, ok := r.attrs[ipsetAttrProtocol]
	return !ok || a.u8() != ipset.ProtocolVersion
}

// protocolMinFailed is protocol_min_failed of Linux: the request carries a
// protocol version that the kernel does not support.
func (r *ipsetRequest) protocolMinFailed() bool {
	a, ok := r.attrs[ipsetAttrProtocol]
	return !ok || a.u8() < ipset.ProtocolVersionMin
}

// existFlag is the exist flag of the request: the request has no NLM_F_EXCL.
func (r *ipsetRequest) existFlag() uint32 {
	if r.hdr.Flags&linux.NLM_F_EXCL != 0 {
		return 0
	}
	return ipset.FlagExist
}

// setName returns the attribute SETNAME.
func (r *ipsetRequest) setName() (string, bool) {
	a, ok := r.attrs[ipsetAttrSetname]
	if !ok {
		return "", false
	}
	return a.str(), true
}

// reply starts the answer message of a command.
func (r *ipsetRequest) reply(cmd int, attrs *attrBuilder) {
	m := r.ms.AddMessage(linux.NetlinkMessageHeader{Type: uint16(linux.NFNL_SUBSYS_IPSET)<<8 | uint16(cmd)})
	m.Put(&linux.NetFilterGenMsg{Family: afInet, Version: linux.NFNETLINK_V0})
	m.Put(primitive.AsByteSlice(attrs.b))
}

func (r *ipsetRequest) protocol() int {
	if _, ok := r.attrs[ipsetAttrProtocol]; !ok {
		return -ipset.ErrProtocol
	}
	var a attrBuilder
	a.u8(ipsetAttrProtocol, ipset.ProtocolVersion)
	a.u8(ipsetAttrProtoMin, ipset.ProtocolVersionMin)
	r.reply(ipsetCmdProtocol, &a)
	return 0
}

func (r *ipsetRequest) destroy() int {
	if r.protocolMinFailed() {
		return -ipset.ErrProtocol
	}
	name, ok := r.setName()
	return codeOf(r.reg.Destroy(name, !ok, r.existFlag() != 0))
}

func (r *ipsetRequest) flush() int {
	if r.protocolMinFailed() {
		return -ipset.ErrProtocol
	}
	name, ok := r.setName()
	return codeOf(r.reg.Flush(name, !ok))
}

// twoNames returns the two names of a RENAME or SWAP request.
func (r *ipsetRequest) twoNames() (string, string, bool) {
	a, aok := r.attrs[ipsetAttrSetname]
	b, bok := r.attrs[ipsetAttrSetname2]
	if r.protocolMinFailed() || !aok || !bok {
		return "", "", false
	}
	return a.str(), b.str(), true
}

func (r *ipsetRequest) rename() int {
	from, to, ok := r.twoNames()
	if !ok {
		return -ipset.ErrProtocol
	}
	return codeOf(r.reg.Rename(from, to))
}

func (r *ipsetRequest) swap() int {
	from, to, ok := r.twoNames()
	if !ok {
		return -ipset.ErrProtocol
	}
	return codeOf(r.reg.Swap(from, to))
}

func (r *ipsetRequest) header() int {
	name, ok := r.setName()
	if r.protocolMinFailed() || !ok {
		return -ipset.ErrProtocol
	}
	info, err := r.reg.Info(name)
	if err != nil {
		return codeOf(err)
	}
	var a attrBuilder
	a.u8(ipsetAttrProtocol, r.attrs[ipsetAttrProtocol].u8())
	a.str(ipsetAttrSetname, info.Name)
	a.str(ipsetAttrTypename, info.TypeName)
	a.u8(ipsetAttrFamily, info.Family)
	a.u8(ipsetAttrRevision, info.Revision)
	r.reply(ipsetCmdHeader, &a)
	return 0
}

func (r *ipsetRequest) typeInfo() int {
	tn, tok := r.attrs[ipsetAttrTypename]
	fam, fok := r.attrs[ipsetAttrFamily]
	if r.protocolMinFailed() || !tok || !fok {
		return -ipset.ErrProtocol
	}
	lo, hi, err := ipset.FindType(tn.str(), fam.u8())
	if err != nil {
		return codeOf(err)
	}
	var a attrBuilder
	a.u8(ipsetAttrProtocol, r.attrs[ipsetAttrProtocol].u8())
	a.str(ipsetAttrTypename, tn.str())
	a.u8(ipsetAttrFamily, fam.u8())
	a.u8(ipsetAttrRevision, hi)
	a.u8(ipsetAttrRevMin, lo)
	r.reply(ipsetCmdType, &a)
	return 0
}

func (r *ipsetRequest) getByName() int {
	name, ok := r.setName()
	if r.protocolFailed() || !ok {
		return -ipset.ErrProtocol
	}
	id, family, found := r.reg.Lookup(name)
	if !found {
		return -errnoNoEnt
	}
	var a attrBuilder
	a.u8(ipsetAttrProtocol, r.attrs[ipsetAttrProtocol].u8())
	a.u8(ipsetAttrFamily, family)
	a.net16(ipsetAttrIndex, uint16(id))
	r.reply(ipsetCmdGetByName, &a)
	return 0
}

func (r *ipsetRequest) getByIndex() int {
	idx, ok := r.attrs[ipsetAttrIndex]
	if r.protocolFailed() || !ok || !idx.netOrder() {
		return -ipset.ErrProtocol
	}
	name, found := r.reg.NameByIndex(ipset.ID(idx.be16()))
	if !found {
		return -errnoNoEnt
	}
	var a attrBuilder
	a.u8(ipsetAttrProtocol, r.attrs[ipsetAttrProtocol].u8())
	a.str(ipsetAttrSetname, name)
	r.reply(ipsetCmdGetByIndex, &a)
	return 0
}

// create handles CREATE.
func (r *ipsetRequest) create() int {
	name, nok := r.setName()
	tn, tok := r.attrs[ipsetAttrTypename]
	rev, rok := r.attrs[ipsetAttrRevision]
	fam, fok := r.attrs[ipsetAttrFamily]
	data, dok := r.attrs[ipsetAttrData]
	if r.protocolMinFailed() || !nok || !tok || !rok || !fok || (dok && data.flags&nlaFNested == 0) {
		return -ipset.ErrProtocol
	}
	p := &ipset.CreateParams{
		Name:     name,
		TypeName: tn.str(),
		Family:   fam.u8(),
		Revision: rev.u8(),
		Exist:    r.existFlag() != 0,
	}
	// A type must exist before the attributes of the request can be read.
	if _, _, err := ipset.FindType(p.TypeName, p.Family); err != nil {
		return codeOf(err)
	}
	if dok {
		attrs, ok := parseIPSetAttrs(data.value, data.offset, ipsetAttrCreateMax, createPolicy)
		if !ok {
			return -ipset.ErrProtocol
		}
		if code := fillCreate(p, attrs); code != 0 {
			return code
		}
	}
	return codeOf(r.reg.Create(p))
}

// fillCreate copies the attributes of the DATA part of a CREATE request into
// the parameters. A number without the flag NLA_F_NET_BYTEORDER fails with the
// protocol error, as in Linux.
func fillCreate(p *ipset.CreateParams, attrs ipsetAttrs) int {
	u32 := func(typ uint16, given ipset.CreateGiven, dst *uint32) bool {
		a, ok := attrs[typ]
		if !ok {
			return true
		}
		if !a.netOrder() {
			return false
		}
		*dst = a.be32()
		p.Given |= given
		return true
	}
	u16 := func(typ uint16, given ipset.CreateGiven, dst *uint16) bool {
		a, ok := attrs[typ]
		if !ok {
			return true
		}
		if !a.netOrder() {
			return false
		}
		*dst = a.be16()
		p.Given |= given
		return true
	}
	ok := u32(ipsetAttrHashsize, ipset.GivenHashSize, &p.HashSize) &&
		u32(ipsetAttrMaxelem, ipset.GivenMaxElem, &p.MaxElem) &&
		u32(ipsetAttrInitval, ipset.GivenInitVal, &p.InitVal) &&
		u32(ipsetAttrTimeout, ipset.GivenTimeout, &p.Timeout) &&
		u32(ipsetAttrCadtFlags, ipset.GivenCadtFlags, &p.CadtFlags) &&
		u32(ipsetAttrSize, ipset.GivenSize, &p.Size) &&
		u16(ipsetAttrPort, ipset.GivenPortFrom, &p.PortFrom) &&
		u16(ipsetAttrPortTo, ipset.GivenPortTo, &p.PortTo)
	if !ok {
		return -ipset.ErrProtocol
	}
	if a, ok := attrs[ipsetAttrNetmask]; ok {
		p.Netmask, p.Given = a.u8(), p.Given|ipset.GivenNetmask
	}
	if a, ok := attrs[ipsetAttrBucketsize]; ok {
		p.BucketSize, p.Given = a.u8(), p.Given|ipset.GivenBucketSize
	}
	if a, ok := attrs[ipsetAttrBitmask]; ok {
		addr, code := parseIPAddr(p.Family, a)
		if code != 0 {
			return -ipset.ErrInvalidNetmask
		}
		p.Bitmask, p.Given = addr, p.Given|ipset.GivenBitmask
	}
	return 0
}

// parseIPAddr reads the nested attribute of an address for the family of the
// set.
func parseIPAddr(family uint8, a ipsetAttr) (ipset.Addr, int) {
	var addr ipset.Addr
	if a.flags&nlaFNested == 0 {
		return addr, -ipset.ErrProtocol
	}
	inner, ok := parseIPSetAttrs(a.value, a.offset, ipsetAttrIPAddrMax, ipAddrPolicy)
	if !ok {
		return addr, -errnoInval
	}
	switch family {
	case ipset.FamilyIPv4:
		v, ok := inner[ipsetAttrIPAddrV4]
		if !ok || !v.netOrder() {
			return addr, -ipset.ErrProtocol
		}
		copy(addr[:4], v.value)
	case ipset.FamilyIPv6:
		v, ok := inner[ipsetAttrIPAddrV6]
		if !ok || !v.netOrder() || len(v.value) < 16 {
			return addr, -ipset.ErrProtocol
		}
		copy(addr[:], v.value)
	default:
		return addr, -ipset.ErrProtocol
	}
	return addr, 0
}

// parseElement reads the attributes of one element of a set of the family. It
// returns the line number that the element carries, if any.
func parseElement(family uint8, data ipsetAttr) (e ipset.Element, lineno []byte, code int) {
	attrs, ok := parseIPSetAttrs(data.value, data.offset, ipsetAttrADTMax, adtPolicy)
	if !ok {
		return e, nil, -ipset.ErrProtocol
	}
	for typ, a := range attrs {
		switch typ {
		case ipsetAttrLineno:
			lineno = a.value[:4]
		case ipsetAttrIP, ipsetAttrIPTo, ipsetAttrIP2, ipsetAttrIP2To:
			if family == ipset.FamilyUnspec {
				continue
			}
			addr, code := parseIPAddr(family, a)
			if code != 0 {
				return e, lineno, code
			}
			switch typ {
			case ipsetAttrIP:
				e.IP, e.Has = addr, e.Has|ipset.HasIP
			case ipsetAttrIPTo:
				e.IPTo, e.Has = addr, e.Has|ipset.HasIPTo
			case ipsetAttrIP2:
				e.IP2, e.Has = addr, e.Has|ipset.HasIP2
			default:
				e.IP2To, e.Has = addr, e.Has|ipset.HasIP2To
			}
		case ipsetAttrCIDR:
			e.CIDR, e.Has = a.u8(), e.Has|ipset.HasCIDR
		case ipsetAttrCIDR2:
			e.CIDR2, e.Has = a.u8(), e.Has|ipset.HasCIDR2
		case ipsetAttrProto:
			e.Proto, e.Has = a.u8(), e.Has|ipset.HasProto
		case ipsetAttrName:
			e.Name, e.Has = a.str(), e.Has|ipset.HasName
		case ipsetAttrNameRef:
			e.NameRef, e.Has = a.str(), e.Has|ipset.HasNameRef
		case ipsetAttrComment:
			e.Comment, e.Has = a.str(), e.Has|ipset.HasComment
		case ipsetAttrPort, ipsetAttrPortTo, ipsetAttrTimeout, ipsetAttrCadtFlags, ipsetAttrSkbPrio, ipsetAttrSkbQueue,
			ipsetAttrBytes, ipsetAttrPackets, ipsetAttrSkbMark:
			if !a.netOrder() {
				return e, lineno, -ipset.ErrProtocol
			}
			switch typ {
			case ipsetAttrPort:
				e.Port, e.Has = a.be16(), e.Has|ipset.HasPort
			case ipsetAttrPortTo:
				e.PortTo, e.Has = a.be16(), e.Has|ipset.HasPortTo
			case ipsetAttrTimeout:
				e.Timeout, e.Has = a.be32(), e.Has|ipset.HasTimeout
			case ipsetAttrCadtFlags:
				e.CadtFlags, e.Has = a.be32(), e.Has|ipset.HasCadtFlags
			case ipsetAttrSkbPrio:
				e.SkbPrio, e.Has = a.be32(), e.Has|ipset.HasSkbPrio
			case ipsetAttrSkbQueue:
				e.SkbQueue, e.Has = a.be16(), e.Has|ipset.HasSkbQueue
			case ipsetAttrBytes:
				e.Bytes, e.Has = a.be64(), e.Has|ipset.HasBytes
			case ipsetAttrPackets:
				e.Packets, e.Has = a.be64(), e.Has|ipset.HasPackets
			default:
				e.SkbMark, e.Has = a.be64(), e.Has|ipset.HasSkbMark
			}
		}
	}
	return e, lineno, 0
}

// dataAttr returns the attribute DATA when it is nested.
func (r *ipsetRequest) dataAttr() (ipsetAttr, bool) {
	a, ok := r.attrs[ipsetAttrData]
	return a, ok && a.flags&nlaFNested != 0
}

// adt handles ADD and DEL, with one element in DATA or many elements in ADT.
func (r *ipsetRequest) adt(adt ipset.Adt) int {
	name, nok := r.setName()
	data, dok := r.attrs[ipsetAttrData]
	batch, bok := r.attrs[ipsetAttrADT]
	_, lok := r.attrs[ipsetAttrLineno]
	if r.protocolMinFailed() || !nok || dok == bok ||
		(dok && data.flags&nlaFNested == 0) ||
		(bok && (batch.flags&nlaFNested == 0 || !lok)) {
		return -ipset.ErrProtocol
	}
	family, found := r.reg.Family(name)
	if !found {
		return -errnoNoEnt
	}
	flags := r.existFlag()
	if dok {
		return r.applyOne(name, family, adt, data, flags)
	}
	pos := 0
	for len(batch.value)-pos >= linux.NetlinkAttrHeaderSize {
		l := int(binary.NativeEndian.Uint16(batch.value[pos:]))
		typ := binary.NativeEndian.Uint16(batch.value[pos+2:])
		if l < linux.NetlinkAttrHeaderSize || l > len(batch.value)-pos {
			return -ipset.ErrProtocol
		}
		if typ&^(nlaFNested|nlaFNetByteorder) != ipsetAttrData || typ&nlaFNested == 0 {
			return -ipset.ErrProtocol
		}
		elem := ipsetAttr{
			value:  batch.value[pos+linux.NetlinkAttrHeaderSize : pos+l],
			flags:  nlaFNested,
			offset: batch.offset + pos + linux.NetlinkAttrHeaderSize,
		}
		if code := r.applyOne(name, family, adt, elem, flags); code != 0 {
			return code
		}
		pos += (l + linux.NLA_ALIGNTO - 1) &^ (linux.NLA_ALIGNTO - 1)
	}
	return 0
}

// applyOne runs ADD or DEL on one element. A failure in a batch answers with
// the line number of the element, as call_ad of Linux does.
func (r *ipsetRequest) applyOne(name string, family uint8, adt ipset.Adt, data ipsetAttr, flags uint32) int {
	e, lineno, code := parseElement(family, data)
	if code == 0 {
		code = r.reg.Uadt(name, adt, &e, flags)
	}
	if code >= 0 || (code == -ipset.ErrExist && flags&ipset.FlagExist != 0) {
		return 0
	}
	if top, ok := r.attrs[ipsetAttrLineno]; ok && lineno != nil && binary.NativeEndian.Uint32(lineno) != 0 {
		request := bytes.Clone(r.msg.Buffer())
		copy(request[top.offset:top.offset+4], lineno)
		r.failWith(-code, request)
		return codeAnswered
	}
	return code
}

// test handles TEST: it succeeds when the element is in the set.
func (r *ipsetRequest) test() int {
	name, nok := r.setName()
	data, dok := r.dataAttr()
	if r.protocolMinFailed() || !nok || !dok {
		return -ipset.ErrProtocol
	}
	family, found := r.reg.Family(name)
	if !found {
		return -errnoNoEnt
	}
	e, _, code := parseElement(family, data)
	if code != 0 {
		return code
	}
	if r.reg.Uadt(name, ipset.AdtTest, &e, 0) > 0 {
		return 0
	}
	return -ipset.ErrExist
}

// list handles LIST and SAVE as a dump.
func (r *ipsetRequest) list() int {
	if r.protocolMinFailed() {
		return -ipset.ErrProtocol
	}
	name, one := r.setName()
	var flags uint32
	if a, ok := r.attrs[ipsetAttrFlags]; ok {
		flags = a.be32()
	}
	d, err := r.reg.NewDump(name, one)
	if err != nil {
		return codeOf(err)
	}
	dump := &ipsetDump{dump: d, proto: r.attrs[ipsetAttrProtocol].u8(), flags: flags}
	if err := r.dumps.StartDump(dump); err != nil {
		d.Close()
		return -int(err.ToLinux())
	}
	return 0
}

// ipsetDump is the state of a listing of sets. Each DumpChunk call writes one
// message: the header of a set with its first elements, or the next elements of
// the set.
type ipsetDump struct {
	dump  *ipset.Dump
	proto uint8
	flags uint32

	// info is the set in progress, and started tells that its header went
	// out. pending is the element that did not fit into the last message.
	info    ipset.SetInfo
	active  bool
	started bool
	cursor  *ipset.Cursor
}

var _ netlink.Dumper = (*ipsetDump)(nil)

// DumpChunk implements netlink.Dumper.DumpChunk.
func (d *ipsetDump) DumpChunk(_ context.Context, chunk *nlmsg.MessageSet, limit int) (bool, *syserr.Error) {
	var a attrBuilder
	a.u8(ipsetAttrProtocol, d.proto)
	if !d.active {
		info, head, ok, err := d.dump.Next()
		if err != nil {
			return false, syserr.ErrNoFileOrDir
		}
		if !ok {
			return false, nil
		}
		d.info, d.active, d.started = info, true, false
		d.cursor = d.dump.Cursor()
		a.str(ipsetAttrSetname, info.Name)
		if d.flags&ipset.FlagListSetname != 0 {
			d.active = false
			d.emit(chunk, &a)
			return true, nil
		}
		a.str(ipsetAttrTypename, info.TypeName)
		a.u8(ipsetAttrFamily, info.Family)
		a.u8(ipsetAttrRevision, info.Revision)
		if d.proto > ipset.ProtocolVersionMin {
			a.net16(ipsetAttrIndex, uint16(info.Index))
		}
		putHead(&a, &head)
		d.started = true
		if d.flags&ipset.FlagListHeader != 0 {
			d.active = false
			d.emit(chunk, &a)
			return true, nil
		}
	} else {
		a.str(ipsetAttrSetname, d.info.Name)
	}
	a.nest(ipsetAttrADT, func() {
		first := true
		for {
			e, ok := d.cursor.Peek()
			if !ok {
				d.active = false
				return
			}
			var el attrBuilder
			el.nest(ipsetAttrData, func() { putElement(&el, d.info.Family, &e) })
			// One message holds at most limit bytes, but it holds one element
			// at least, so that the dump advances.
			if !first && linux.NetlinkMessageHeaderSize+linux.SizeOfNetfilterGenMsg+len(a.b)+len(el.b) > limit {
				return
			}
			a.b = append(a.b, el.b...)
			d.cursor.Advance()
			first = false
		}
	})
	d.emit(chunk, &a)
	return true, nil
}

// emit writes the answer message of a dump.
func (d *ipsetDump) emit(chunk *nlmsg.MessageSet, a *attrBuilder) {
	m := chunk.AddMessage(linux.NetlinkMessageHeader{Type: uint16(linux.NFNL_SUBSYS_IPSET)<<8 | ipsetCmdList})
	m.Put(&linux.NetFilterGenMsg{Family: afInet, Version: linux.NFNETLINK_V0})
	m.Put(primitive.AsByteSlice(a.b))
}

// DumpDone implements netlink.Dumper.DumpDone.
func (d *ipsetDump) DumpDone() { d.dump.Close() }

// putHead adds the nested header of a set.
func putHead(a *attrBuilder, h *ipset.Head) {
	a.nest(ipsetAttrData, func() {
		if h.HasPort {
			a.net16(ipsetAttrPort, h.PortFrom)
			a.net16(ipsetAttrPortTo, h.PortTo)
		}
		if h.HasSize {
			a.net32(ipsetAttrSize, h.Size)
		}
		if h.HasHash {
			a.net32(ipsetAttrHashsize, h.HashSize)
			a.net32(ipsetAttrMaxelem, h.MaxElem)
		}
		if h.HasBitmask {
			a.nest(ipsetAttrBitmask, func() {
				if h.Bitmask[4]|h.Bitmask[5]|h.Bitmask[6]|h.Bitmask[7]|h.Bitmask[8] == 0 && h.Bitmask[15] == 0 && h.Bitmask[9] == 0 {
					a.put(ipsetAttrIPAddrV4|nlaFNetByteorder, h.Bitmask[:4])
					return
				}
				a.put(ipsetAttrIPAddrV6|nlaFNetByteorder, h.Bitmask[:])
			})
		}
		if h.Netmask != 0 {
			a.u8(ipsetAttrNetmask, h.Netmask)
		}
		if h.HasBucket {
			a.u8(ipsetAttrBucketsize, h.BucketSize)
			a.net32(ipsetAttrInitval, h.InitVal)
		}
		a.net32(ipsetAttrReferences, h.References)
		a.net32(ipsetAttrMemsize, h.MemSize)
		a.net32(ipsetAttrElements, h.Elements)
		if h.HasTimeout {
			a.net32(ipsetAttrTimeout, h.Timeout)
		}
		if h.CadtFlags != 0 {
			a.net32(ipsetAttrCadtFlags, h.CadtFlags)
		}
	})
}

// putElement adds the attributes of a listed element.
func putElement(a *attrBuilder, family uint8, e *ipset.Element) {
	has := func(p ipset.Present) bool { return e.Has&p != 0 }
	if has(ipset.HasIP) {
		a.ipaddr(ipsetAttrIP, family, e.IP)
	}
	if has(ipset.HasCIDR) {
		a.u8(ipsetAttrCIDR, e.CIDR)
	}
	if has(ipset.HasPort) {
		a.net16(ipsetAttrPort, e.Port)
	}
	if has(ipset.HasProto) {
		a.u8(ipsetAttrProto, e.Proto)
	}
	if has(ipset.HasIP2) {
		a.ipaddr(ipsetAttrIP2, family, e.IP2)
	}
	if has(ipset.HasCIDR2) {
		a.u8(ipsetAttrCIDR2, e.CIDR2)
	}
	if has(ipset.HasName) {
		a.str(ipsetAttrName, e.Name)
	}
	if has(ipset.HasCadtFlags) {
		a.net32(ipsetAttrCadtFlags, e.CadtFlags)
	}
	if has(ipset.HasTimeout) {
		a.net32(ipsetAttrTimeout, e.Timeout)
	}
	if has(ipset.HasBytes) {
		a.net64(ipsetAttrBytes, e.Bytes)
	}
	if has(ipset.HasPackets) {
		a.net64(ipsetAttrPackets, e.Packets)
	}
	if has(ipset.HasComment) {
		a.str(ipsetAttrComment, e.Comment)
	}
	if has(ipset.HasSkbMark) {
		a.net64(ipsetAttrSkbMark, e.SkbMark)
	}
	if has(ipset.HasSkbPrio) {
		a.net32(ipsetAttrSkbPrio, e.SkbPrio)
	}
	if has(ipset.HasSkbQueue) {
		a.net16(ipsetAttrSkbQueue, e.SkbQueue)
	}
}
