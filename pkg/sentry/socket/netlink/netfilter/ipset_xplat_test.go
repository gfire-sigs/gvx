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
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/ipset"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
)

// reply is one message that the subsystem sends.
type reply struct {
	hdr   linux.NetlinkMessageHeader
	attrs ipsetAttrs
	// errno is the error of an NLMSG_ERROR message. echo is the request that
	// the error message carries.
	errno int32
	echo  []byte
	buf   []byte
}

type fakeClock struct{ now time.Duration }

func (c *fakeClock) read() time.Duration { return c.now + time.Second }

// ipsetClient builds requests the way libipset does and decodes the answers.
type ipsetClient struct {
	t     *testing.T
	reg   *ipset.Registry
	clock *fakeClock
	seq   uint32
	// limit is the size of a chunk of a dump.
	limit int
}

func newIPSetClient(t *testing.T) *ipsetClient {
	t.Helper()
	clock := &fakeClock{}
	return &ipsetClient{t: t, reg: ipset.NewRegistry(ipset.DefaultMaxSets, clock.read), clock: clock, limit: 3776}
}

// request builds a message of the subsystem.
func (c *ipsetClient) request(cmd int, flags uint16, build func(a *attrBuilder)) []byte {
	var a attrBuilder
	build(&a)
	c.seq++
	buf := make([]byte, 0, 20+len(a.b))
	buf = binary.NativeEndian.AppendUint32(buf, uint32(20+len(a.b)))
	buf = binary.NativeEndian.AppendUint16(buf, uint16(linux.NFNL_SUBSYS_IPSET)<<8|uint16(cmd))
	buf = binary.NativeEndian.AppendUint16(buf, flags)
	buf = binary.NativeEndian.AppendUint32(buf, c.seq)
	buf = binary.NativeEndian.AppendUint32(buf, 0)
	buf = append(buf, afInet, 0, 0, 0)
	return append(buf, a.b...)
}

// send serves a request and returns every message that the socket would queue,
// as the loop of netlink.Socket.ProcessMessages does.
func (c *ipsetClient) send(buf []byte) []reply {
	c.t.Helper()
	msg, _, ok := nlmsg.ParseMessage(buf)
	if !ok {
		c.t.Fatal("malformed request")
	}
	hdr := msg.Header()
	ms := nlmsg.NewMessageSet(1, hdr.Seq)
	dumps := &startedDump{}
	if err := serveIPSet(c.reg, dumps, msg, ms); err != nil {
		c.t.Fatalf("serveIPSet returned %v", err)
	}
	var out []reply
	for _, m := range ms.Messages {
		out = append(out, c.decode(m.Finalize()))
	}
	switch {
	case dumps.dump != nil:
		defer dumps.dump.DumpDone()
		for {
			chunk := nlmsg.NewMessageSet(1, hdr.Seq)
			chunk.Multi = true
			more, err := dumps.dump.DumpChunk(context.Background(), chunk, c.limit)
			if err != nil {
				c.t.Fatalf("DumpChunk: %v", err)
			}
			for _, m := range chunk.Messages {
				b := m.Finalize()
				if len(b) > c.limit {
					c.t.Errorf("dump message of %d bytes exceeds the chunk limit %d", len(b), c.limit)
				}
				out = append(out, c.decode(b))
			}
			if !more {
				return out
			}
		}
	case hdr.Flags&linux.NLM_F_ACK != 0 && !ms.ContainsError:
		out = append(out, reply{hdr: linux.NetlinkMessageHeader{Type: linux.NLMSG_ERROR}})
	}
	return out
}

func (c *ipsetClient) decode(b []byte) reply {
	c.t.Helper()
	var r reply
	r.buf = b
	r.hdr.UnmarshalUnsafe(b[:linux.NetlinkMessageHeaderSize])
	if r.hdr.Type == linux.NLMSG_ERROR {
		r.errno = int32(binary.NativeEndian.Uint32(b[16:]))
		r.echo = b[20:r.hdr.Length]
		return r
	}
	attrs, ok := parseIPSetAttrs(b[20:r.hdr.Length], 20, ipsetAttrADTMax, nil)
	if !ok {
		c.t.Fatalf("malformed answer % x", b)
	}
	r.attrs = attrs
	return r
}

// ok sends a request and requires that its answer is an acknowledgement.
func (c *ipsetClient) ok(buf []byte) {
	c.t.Helper()
	out := c.send(buf)
	if len(out) != 1 || out[0].hdr.Type != linux.NLMSG_ERROR || out[0].errno != 0 {
		c.t.Fatalf("answer = %+v, want one acknowledgement", out)
	}
}

// fails sends a request and returns the errno of its error answer.
func (c *ipsetClient) fails(buf []byte) int32 {
	c.t.Helper()
	out := c.send(buf)
	if len(out) != 1 || out[0].hdr.Type != linux.NLMSG_ERROR || out[0].errno == 0 {
		c.t.Fatalf("answer = %+v, want one error", out)
	}
	if want := len(buf); len(out[0].echo) != want {
		c.t.Errorf("error carries %d bytes of the request, want %d", len(out[0].echo), want)
	}
	return -out[0].errno
}

const (
	reqFlags = linux.NLM_F_REQUEST | linux.NLM_F_ACK
)

func createFlags() uint16 { return reqFlags | linux.NLM_F_CREATE | linux.NLM_F_EXCL }

func addFlags() uint16 { return reqFlags | linux.NLM_F_EXCL }

func protocolAttr(a *attrBuilder) { a.u8(ipsetAttrProtocol, ipset.ProtocolVersion) }

// createReq builds a CREATE request. build adds attributes to DATA.
func (c *ipsetClient) createReq(flags uint16, name, typ string, family, revision uint8, data func(a *attrBuilder)) []byte {
	return c.request(ipsetCmdCreate, flags, func(a *attrBuilder) {
		protocolAttr(a)
		a.str(ipsetAttrSetname, name)
		a.str(ipsetAttrTypename, typ)
		a.u8(ipsetAttrRevision, revision)
		a.u8(ipsetAttrFamily, family)
		a.nest(ipsetAttrData, func() {
			if data != nil {
				data(a)
			}
		})
	})
}

// maxRevision returns the highest revision of a type, as the TYPE command
// reports it.
func (c *ipsetClient) maxRevision(typ string, family uint8) uint8 {
	c.t.Helper()
	out := c.send(c.request(ipsetCmdType, linux.NLM_F_REQUEST, func(a *attrBuilder) {
		protocolAttr(a)
		a.str(ipsetAttrTypename, typ)
		a.u8(ipsetAttrFamily, family)
	}))
	if len(out) != 1 || out[0].attrs[ipsetAttrRevision].value == nil {
		c.t.Fatalf("TYPE %s answer = %+v", typ, out)
	}
	return out[0].attrs[ipsetAttrRevision].u8()
}

// createSet creates a set with the highest revision of its type.
func (c *ipsetClient) createSet(name, typ string, family uint8, data func(a *attrBuilder)) {
	c.t.Helper()
	c.ok(c.createReq(createFlags(), name, typ, family, c.maxRevision(typ, family), data))
}

func addrV4(a, b, c, d byte) []byte { return []byte{a, b, c, d} }

func putIP(a *attrBuilder, typ uint16, ip []byte) {
	a.nest(typ, func() { a.put(ipsetAttrIPAddrV4|nlaFNetByteorder, ip) })
}

func (c *ipsetClient) elemReq(cmd int, flags uint16, set string, build func(a *attrBuilder)) []byte {
	return c.request(cmd, flags, func(a *attrBuilder) {
		protocolAttr(a)
		a.str(ipsetAttrSetname, set)
		a.nest(ipsetAttrData, func() { build(a) })
	})
}

func (c *ipsetClient) listReq(set string, flags uint32) []byte {
	return c.request(ipsetCmdList, reqFlags|linux.NLM_F_DUMP, func(a *attrBuilder) {
		protocolAttr(a)
		if set != "" {
			a.str(ipsetAttrSetname, set)
		}
		if flags != 0 {
			a.net32(ipsetAttrFlags, flags)
		}
	})
}

func TestIPSetProtocol(t *testing.T) {
	c := newIPSetClient(t)
	out := c.send(c.request(ipsetCmdProtocol, linux.NLM_F_REQUEST, protocolAttr))
	if len(out) != 1 {
		t.Fatalf("answer = %+v, want one message", out)
	}
	r := out[0]
	if got := r.hdr.Type; got != uint16(linux.NFNL_SUBSYS_IPSET)<<8|ipsetCmdProtocol {
		t.Errorf("message type = %#x", got)
	}
	if r.attrs[ipsetAttrProtocol].u8() != 7 || r.attrs[ipsetAttrProtoMin].u8() != 6 {
		t.Errorf("protocol versions = %d to %d, want 6 to 7", r.attrs[ipsetAttrProtoMin].u8(), r.attrs[ipsetAttrProtocol].u8())
	}
	missing := c.request(ipsetCmdProtocol, linux.NLM_F_REQUEST, func(*attrBuilder) {})
	if out := c.send(missing); len(out) != 1 || out[0].errno != -ipset.ErrProtocol {
		t.Errorf("request without a protocol attribute = %+v, want the protocol error", out)
	}
}

func TestIPSetTypeReportsRevisionRange(t *testing.T) {
	c := newIPSetClient(t)
	for _, typ := range []string{"hash:ip", "hash:net", "hash:ip,port", "hash:net,port", "hash:ip,port,ip", "hash:ip,port,net", "hash:net,net", "list:set", "bitmap:port"} {
		if c.maxRevision(typ, linux.AF_INET) == 0 {
			t.Errorf("type %s reports revision 0", typ)
		}
	}
	unknown := c.request(ipsetCmdType, linux.NLM_F_REQUEST, func(a *attrBuilder) {
		protocolAttr(a)
		a.str(ipsetAttrTypename, "hash:mac")
		a.u8(ipsetAttrFamily, linux.AF_INET)
	})
	if out := c.send(unknown); len(out) != 1 || out[0].errno != -ipset.ErrFindType {
		t.Errorf("unknown type answer = %+v, want the find type error", out)
	}
}

func TestIPSetCreateAddTestListDelete(t *testing.T) {
	c := newIPSetClient(t)
	c.createSet("web", "hash:ip", linux.AF_INET, func(a *attrBuilder) {
		a.net32(ipsetAttrHashsize, 1024)
		a.net32(ipsetAttrMaxelem, 100)
		a.net32(ipsetAttrTimeout, 300)
		a.net32(ipsetAttrCadtFlags, ipset.CadtWithCounters|ipset.CadtWithComment)
	})
	c.ok(c.elemReq(ipsetCmdAdd, addFlags(), "web", func(a *attrBuilder) {
		putIP(a, ipsetAttrIP, addrV4(10, 0, 0, 1))
		a.net32(ipsetAttrTimeout, 60)
		a.str(ipsetAttrComment, "frontend")
	}))
	if errno := c.fails(c.elemReq(ipsetCmdAdd, addFlags(), "web", func(a *attrBuilder) {
		putIP(a, ipsetAttrIP, addrV4(10, 0, 0, 1))
	})); errno != ipset.ErrExist {
		t.Errorf("duplicate add errno = %d, want ErrExist", errno)
	}
	// Without NLM_F_EXCL the duplicate is no error: ipset -exist.
	c.ok(c.elemReq(ipsetCmdAdd, reqFlags, "web", func(a *attrBuilder) {
		putIP(a, ipsetAttrIP, addrV4(10, 0, 0, 1))
		a.net32(ipsetAttrTimeout, 60)
		a.str(ipsetAttrComment, "frontend")
	}))
	c.ok(c.elemReq(ipsetCmdTest, reqFlags, "web", func(a *attrBuilder) { putIP(a, ipsetAttrIP, addrV4(10, 0, 0, 1)) }))
	if errno := c.fails(c.elemReq(ipsetCmdTest, reqFlags, "web", func(a *attrBuilder) {
		putIP(a, ipsetAttrIP, addrV4(10, 0, 0, 2))
	})); errno != ipset.ErrExist {
		t.Errorf("test of a non-member errno = %d, want ErrExist", errno)
	}

	out := c.send(c.listReq("web", 0))
	if len(out) != 1 {
		t.Fatalf("listing has %d messages, want 1", len(out))
	}
	r := out[0]
	if r.hdr.Type != uint16(linux.NFNL_SUBSYS_IPSET)<<8|ipsetCmdList || r.hdr.Flags&linux.NLM_F_MULTI == 0 {
		t.Errorf("header = %+v, want a multipart LIST message", r.hdr)
	}
	if r.attrs[ipsetAttrSetname].str() != "web" || r.attrs[ipsetAttrTypename].str() != "hash:ip" ||
		r.attrs[ipsetAttrFamily].u8() != linux.AF_INET || r.attrs[ipsetAttrRevision].u8() == 0 {
		t.Errorf("listing identity = %+v", r.attrs)
	}
	index := r.attrs[ipsetAttrIndex]
	if !index.netOrder() || index.be16() != 0 {
		t.Errorf("index attribute = %+v, want net byte order 0", index)
	}
	head, _ := parseIPSetAttrs(r.attrs[ipsetAttrData].value, 0, ipsetAttrCreateMax, nil)
	if head[ipsetAttrHashsize].be32() != 1024 || head[ipsetAttrMaxelem].be32() != 100 ||
		head[ipsetAttrElements].be32() != 1 || head[ipsetAttrTimeout].be32() != 300 {
		t.Errorf("header attributes = %+v", head)
	}
	if flags := head[ipsetAttrCadtFlags].be32(); flags != ipset.CadtWithCounters|ipset.CadtWithComment {
		t.Errorf("cadt flags = %#x", flags)
	}
	if !head[ipsetAttrHashsize].netOrder() || r.attrs[ipsetAttrData].flags&nlaFNested == 0 {
		t.Errorf("header attributes lack the net byte order or nested flags")
	}
	elems := nestedElements(t, r.attrs[ipsetAttrADT])
	if len(elems) != 1 {
		t.Fatalf("listing holds %d elements, want 1", len(elems))
	}
	e := elems[0]
	ipAttrs, _ := parseIPSetAttrs(e[ipsetAttrIP].value, 0, ipsetAttrIPAddrMax, nil)
	if got := ipAttrs[ipsetAttrIPAddrV4].value; fmt.Sprint(got) != "[10 0 0 1]" {
		t.Errorf("element address = %v", got)
	}
	if got := e[ipsetAttrTimeout].be32(); got < 59 || got > 60 {
		t.Errorf("element timeout = %d, want about 60", got)
	}
	if e[ipsetAttrComment].str() != "frontend" || e[ipsetAttrPackets].be64() != 0 || !e[ipsetAttrBytes].netOrder() {
		t.Errorf("element extensions = %+v", e)
	}

	c.ok(c.elemReq(ipsetCmdDel, addFlags(), "web", func(a *attrBuilder) { putIP(a, ipsetAttrIP, addrV4(10, 0, 0, 1)) }))
	if errno := c.fails(c.elemReq(ipsetCmdDel, addFlags(), "web", func(a *attrBuilder) {
		putIP(a, ipsetAttrIP, addrV4(10, 0, 0, 1))
	})); errno != ipset.ErrExist {
		t.Errorf("delete of a missing element errno = %d, want ErrExist", errno)
	}
}

// nestedElements parses the ADT attribute of a listing into the attributes
// of each element.
func nestedElements(t *testing.T, adt ipsetAttr) []ipsetAttrs {
	t.Helper()
	var out []ipsetAttrs
	b := adt.value
	for len(b) >= 4 {
		l := int(binary.NativeEndian.Uint16(b))
		attrs, ok := parseIPSetAttrs(b[4:l], 0, ipsetAttrADTMax, nil)
		if !ok {
			t.Fatalf("malformed element in % x", b)
		}
		out = append(out, attrs)
		b = b[(l+3)&^3:]
	}
	return out
}

func TestIPSetErrorsCarryTheRequest(t *testing.T) {
	c := newIPSetClient(t)
	c.createSet("one", "hash:ip", linux.AF_INET, nil)
	again := c.createReq(createFlags(), "one", "hash:ip", linux.AF_INET, c.maxRevision("hash:ip", linux.AF_INET), nil)
	out := c.send(again)
	if len(out) != 1 {
		t.Fatalf("answer = %+v, want one error and no acknowledgement", out)
	}
	if out[0].errno != -17 {
		t.Errorf("errno = %d, want -EEXIST", out[0].errno)
	}
	if len(out[0].echo) != len(again) || out[0].hdr.Length != uint32(20+len(again)) {
		t.Errorf("error message length %d with %d echoed bytes for a %d byte request", out[0].hdr.Length, len(out[0].echo), len(again))
	}
	// With the exist flag an identical create is fine.
	flags := uint16(reqFlags | linux.NLM_F_CREATE)
	c.ok(c.createReq(flags, "one", "hash:ip", linux.AF_INET, c.maxRevision("hash:ip", linux.AF_INET), nil))

	if errno := c.fails(c.elemReq(ipsetCmdAdd, addFlags(), "nope", func(a *attrBuilder) {
		putIP(a, ipsetAttrIP, addrV4(1, 1, 1, 1))
	})); errno != 2 {
		t.Errorf("add to a missing set errno = %d, want ENOENT", errno)
	}
	old := c.request(ipsetCmdDestroy, reqFlags, func(a *attrBuilder) { a.u8(ipsetAttrProtocol, 5) })
	if errno := c.fails(old); errno != ipset.ErrProtocol {
		t.Errorf("protocol 5 errno = %d, want the protocol error", errno)
	}
	badCmd := c.request(ipsetMsgMax+3, reqFlags, protocolAttr)
	if errno := c.fails(badCmd); errno != 22 {
		t.Errorf("unknown command errno = %d, want EINVAL", errno)
	}
	none := c.request(ipsetCmdNone, reqFlags, protocolAttr)
	if errno := c.fails(none); errno != 95 {
		t.Errorf("command NONE errno = %d, want EOPNOTSUPP", errno)
	}
	// A set name of 32 bytes does not fit the policy.
	long := c.request(ipsetCmdFlush, reqFlags, func(a *attrBuilder) {
		protocolAttr(a)
		a.str(ipsetAttrSetname, "0123456789012345678901234567890123")
	})
	if errno := c.fails(long); errno != 22 {
		t.Errorf("long name errno = %d, want EINVAL", errno)
	}
}

func TestIPSetBatchReportsTheLineOfTheFailure(t *testing.T) {
	c := newIPSetClient(t)
	c.createSet("batch", "hash:ip", linux.AF_INET, nil)
	c.ok(c.elemReq(ipsetCmdAdd, addFlags(), "batch", func(a *attrBuilder) { putIP(a, ipsetAttrIP, addrV4(10, 0, 0, 2)) }))

	lineno := func(a *attrBuilder, n uint32) { a.net32(ipsetAttrLineno, n) }
	req := c.request(ipsetCmdAdd, addFlags(), func(a *attrBuilder) {
		protocolAttr(a)
		a.str(ipsetAttrSetname, "batch")
		lineno(a, 1)
		a.nest(ipsetAttrADT, func() {
			for i, last := range []byte{1, 2, 3} {
				a.nest(ipsetAttrData, func() {
					putIP(a, ipsetAttrIP, addrV4(10, 0, 0, last))
					lineno(a, uint32(10+i))
				})
			}
		})
	})
	out := c.send(req)
	if len(out) != 1 || out[0].errno != -ipset.ErrExist {
		t.Fatalf("answer = %+v, want one error", out)
	}
	// The error carries the request with the line of the failed element.
	attrs, ok := parseIPSetAttrs(out[0].echo[linux.NetlinkMessageHeaderSize+4:], 0, ipsetAttrCmdMax, nil)
	if !ok || attrs[ipsetAttrLineno].be32() != 11 {
		t.Errorf("echoed line number = %+v, want 11", attrs[ipsetAttrLineno])
	}
	if got := c.reg.Uadt("batch", ipset.AdtTest, &ipset.Element{Has: ipset.HasIP, IP: ipset.Addr{10, 0, 0, 1}}, 0); got <= 0 {
		t.Errorf("the element before the failure was not added")
	}
	if got := c.reg.Uadt("batch", ipset.AdtTest, &ipset.Element{Has: ipset.HasIP, IP: ipset.Addr{10, 0, 0, 3}}, 0); got > 0 {
		t.Errorf("the element after the failure was added")
	}
}

func TestIPSetDumpSplitsLargeSetsIntoMessages(t *testing.T) {
	c := newIPSetClient(t)
	c.createSet("big", "hash:ip", linux.AF_INET, func(a *attrBuilder) { a.net32(ipsetAttrMaxelem, 100000) })
	const count = 3000
	for i := range count {
		c.ok(c.elemReq(ipsetCmdAdd, addFlags(), "big", func(a *attrBuilder) {
			putIP(a, ipsetAttrIP, addrV4(10, byte(i>>16), byte(i>>8), byte(i)+1))
		}))
	}
	out := c.send(c.listReq("big", 0))
	if len(out) < 3 {
		t.Fatalf("a set of %d elements fits into %d messages", count, len(out))
	}
	seen := map[string]bool{}
	for i, r := range out {
		_, hasData := r.attrs[ipsetAttrData]
		if hasData != (i == 0) {
			t.Errorf("message %d: DATA present = %v, only the first message carries the header", i, hasData)
		}
		if r.attrs[ipsetAttrSetname].str() != "big" {
			t.Errorf("message %d lacks the set name", i)
		}
		for _, e := range nestedElements(t, r.attrs[ipsetAttrADT]) {
			ipAttrs, _ := parseIPSetAttrs(e[ipsetAttrIP].value, 0, ipsetAttrIPAddrMax, nil)
			seen[fmt.Sprint(ipAttrs[ipsetAttrIPAddrV4].value)] = true
		}
	}
	if len(seen) != count {
		t.Errorf("the listing returned %d distinct elements, want %d", len(seen), count)
	}
}

func TestIPSetListFlagsAndOrder(t *testing.T) {
	c := newIPSetClient(t)
	c.createSet("zlist", "list:set", linux.AF_UNSPEC, nil)
	c.createSet("a", "hash:ip", linux.AF_INET, nil)
	c.createSet("b", "hash:net", linux.AF_INET, nil)
	c.ok(c.elemReq(ipsetCmdAdd, addFlags(), "b", func(a *attrBuilder) {
		putIP(a, ipsetAttrIP, addrV4(10, 0, 0, 0))
		a.u8(ipsetAttrCIDR, 8)
	}))

	names := func(out []reply) []string {
		var n []string
		for _, r := range out {
			n = append(n, r.attrs[ipsetAttrSetname].str())
		}
		return n
	}
	out := c.send(c.listReq("", ipset.FlagListSetname))
	if fmt.Sprint(names(out)) != "[a b zlist]" {
		t.Errorf("names = %v, want [a b zlist]", names(out))
	}
	for _, r := range out {
		if _, ok := r.attrs[ipsetAttrData]; ok {
			t.Errorf("a name listing carries a header")
		}
	}
	out = c.send(c.listReq("", ipset.FlagListHeader))
	for _, r := range out {
		if _, ok := r.attrs[ipsetAttrADT]; ok {
			t.Errorf("a header listing carries elements")
		}
		if _, ok := r.attrs[ipsetAttrData]; !ok {
			t.Errorf("a header listing lacks the header")
		}
	}
	if got := c.send(c.listReq("missing", 0)); len(got) != 1 || got[0].errno != -2 {
		t.Errorf("listing of a missing set = %+v, want ENOENT", got)
	}
}

func TestIPSetElementEncodings(t *testing.T) {
	c := newIPSetClient(t)
	c.createSet("svc", "hash:net,port", linux.AF_INET, nil)
	c.ok(c.elemReq(ipsetCmdAdd, addFlags(), "svc", func(a *attrBuilder) {
		putIP(a, ipsetAttrIP, addrV4(10, 8, 0, 0))
		a.u8(ipsetAttrCIDR, 16)
		a.net16(ipsetAttrPort, 8080)
		a.u8(ipsetAttrProto, 6)
		a.net32(ipsetAttrCadtFlags, ipset.CadtNomatch)
	}))
	c.ok(c.elemReq(ipsetCmdTest, reqFlags, "svc", func(a *attrBuilder) {
		putIP(a, ipsetAttrIP, addrV4(10, 8, 0, 0))
		a.u8(ipsetAttrCIDR, 16)
		a.net16(ipsetAttrPort, 8080)
		a.u8(ipsetAttrProto, 6)
		a.net32(ipsetAttrCadtFlags, ipset.CadtNomatch)
	}))
	out := c.send(c.listReq("svc", 0))
	e := nestedElements(t, out[0].attrs[ipsetAttrADT])[0]
	if e[ipsetAttrCIDR].u8() != 16 || e[ipsetAttrPort].be16() != 8080 || !e[ipsetAttrPort].netOrder() ||
		e[ipsetAttrProto].u8() != 6 || e[ipsetAttrCadtFlags].be32() != ipset.CadtNomatch {
		t.Errorf("element attributes = %+v", e)
	}

	c.createSet("v6", "hash:ip", linux.AF_INET6, nil)
	addr := []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	c.ok(c.elemReq(ipsetCmdAdd, addFlags(), "v6", func(a *attrBuilder) {
		a.nest(ipsetAttrIP, func() { a.put(ipsetAttrIPAddrV6|nlaFNetByteorder, addr) })
	}))
	out = c.send(c.listReq("v6", 0))
	e = nestedElements(t, out[0].attrs[ipsetAttrADT])[0]
	ipAttrs, _ := parseIPSetAttrs(e[ipsetAttrIP].value, 0, ipsetAttrIPAddrMax, nil)
	if got := ipAttrs[ipsetAttrIPAddrV6].value; fmt.Sprint(got) != fmt.Sprint(addr) {
		t.Errorf("IPv6 element = %v", got)
	}
	// An IPv4 address in an IPv6 set is a protocol error.
	if errno := c.fails(c.elemReq(ipsetCmdAdd, addFlags(), "v6", func(a *attrBuilder) {
		putIP(a, ipsetAttrIP, addrV4(1, 2, 3, 4))
	})); errno != ipset.ErrProtocol {
		t.Errorf("IPv4 address in an IPv6 set errno = %d, want the protocol error", errno)
	}
	// A number without the net byte order flag is a protocol error.
	if errno := c.fails(c.elemReq(ipsetCmdAdd, addFlags(), "svc", func(a *attrBuilder) {
		putIP(a, ipsetAttrIP, addrV4(10, 9, 0, 0))
		a.put(ipsetAttrPort, []byte{0x1f, 0x90})
		a.u8(ipsetAttrProto, 6)
	})); errno != ipset.ErrProtocol {
		t.Errorf("port without net byte order errno = %d, want the protocol error", errno)
	}
}

func TestIPSetRenameSwapFlushDestroy(t *testing.T) {
	c := newIPSetClient(t)
	c.createSet("a", "hash:ip", linux.AF_INET, nil)
	c.createSet("b", "hash:ip", linux.AF_INET, nil)
	c.ok(c.elemReq(ipsetCmdAdd, addFlags(), "a", func(a *attrBuilder) { putIP(a, ipsetAttrIP, addrV4(10, 0, 0, 1)) }))

	names := func(cmd int, from, to string) []byte {
		return c.request(cmd, reqFlags, func(a *attrBuilder) {
			protocolAttr(a)
			a.str(ipsetAttrSetname, from)
			a.str(ipsetAttrSetname2, to)
		})
	}
	c.ok(names(ipsetCmdSwap, "a", "b"))
	c.ok(c.elemReq(ipsetCmdTest, reqFlags, "b", func(a *attrBuilder) { putIP(a, ipsetAttrIP, addrV4(10, 0, 0, 1)) }))
	if errno := c.fails(names(ipsetCmdRename, "a", "b")); errno != ipset.ErrExistSetname2 {
		t.Errorf("rename onto an existing name errno = %d", errno)
	}
	c.ok(names(ipsetCmdRename, "a", "c"))
	if errno := c.fails(names(ipsetCmdSwap, "a", "c")); errno != 2 {
		t.Errorf("swap of a missing set errno = %d, want ENOENT", errno)
	}
	flush := c.request(ipsetCmdFlush, reqFlags, func(a *attrBuilder) {
		protocolAttr(a)
		a.str(ipsetAttrSetname, "b")
	})
	c.ok(flush)
	if errno := c.fails(c.elemReq(ipsetCmdTest, reqFlags, "b", func(a *attrBuilder) {
		putIP(a, ipsetAttrIP, addrV4(10, 0, 0, 1))
	})); errno != ipset.ErrExist {
		t.Errorf("test after flush errno = %d", errno)
	}
	destroy := func(name string, flags uint16) []byte {
		return c.request(ipsetCmdDestroy, flags, func(a *attrBuilder) {
			protocolAttr(a)
			if name != "" {
				a.str(ipsetAttrSetname, name)
			}
		})
	}
	c.ok(destroy("b", reqFlags|linux.NLM_F_EXCL))
	if errno := c.fails(destroy("b", reqFlags|linux.NLM_F_EXCL)); errno != 2 {
		t.Errorf("destroy of a missing set errno = %d, want ENOENT", errno)
	}
	c.ok(destroy("b", reqFlags))
	c.ok(destroy("", reqFlags|linux.NLM_F_EXCL))
	if _, _, ok := c.reg.Lookup("c"); ok {
		t.Error("destroy without a name left a set")
	}
}

func TestIPSetHeaderGetByNameAndIndex(t *testing.T) {
	c := newIPSetClient(t)
	c.createSet("first", "hash:ip", linux.AF_INET, nil)
	c.createSet("second", "hash:net", linux.AF_INET6, nil)

	out := c.send(c.request(ipsetCmdHeader, linux.NLM_F_REQUEST, func(a *attrBuilder) {
		protocolAttr(a)
		a.str(ipsetAttrSetname, "second")
	}))
	if len(out) != 1 || out[0].attrs[ipsetAttrTypename].str() != "hash:net" || out[0].attrs[ipsetAttrFamily].u8() != linux.AF_INET6 {
		t.Errorf("HEADER answer = %+v", out)
	}
	out = c.send(c.request(ipsetCmdGetByName, linux.NLM_F_REQUEST, func(a *attrBuilder) {
		protocolAttr(a)
		a.str(ipsetAttrSetname, "second")
	}))
	if len(out) != 1 || out[0].attrs[ipsetAttrIndex].be16() != 1 || out[0].attrs[ipsetAttrFamily].u8() != linux.AF_INET6 {
		t.Errorf("GET_BYNAME answer = %+v", out)
	}
	out = c.send(c.request(ipsetCmdGetByIndex, linux.NLM_F_REQUEST, func(a *attrBuilder) {
		protocolAttr(a)
		a.net16(ipsetAttrIndex, 0)
	}))
	if len(out) != 1 || out[0].attrs[ipsetAttrSetname].str() != "first" {
		t.Errorf("GET_BYINDEX answer = %+v", out)
	}
	missing := c.request(ipsetCmdGetByName, linux.NLM_F_REQUEST, func(a *attrBuilder) {
		protocolAttr(a)
		a.str(ipsetAttrSetname, "nope")
	})
	if out := c.send(missing); len(out) != 1 || out[0].errno != -2 {
		t.Errorf("GET_BYNAME of a missing set = %+v, want ENOENT", out)
	}
}

func TestIPSetTimeoutExpiryThroughTheProtocol(t *testing.T) {
	c := newIPSetClient(t)
	c.createSet("ttl", "hash:ip", linux.AF_INET, func(a *attrBuilder) { a.net32(ipsetAttrTimeout, 10) })
	c.ok(c.elemReq(ipsetCmdAdd, addFlags(), "ttl", func(a *attrBuilder) { putIP(a, ipsetAttrIP, addrV4(10, 0, 0, 1)) }))
	c.ok(c.elemReq(ipsetCmdTest, reqFlags, "ttl", func(a *attrBuilder) { putIP(a, ipsetAttrIP, addrV4(10, 0, 0, 1)) }))
	c.clock.now += 11 * time.Second
	if errno := c.fails(c.elemReq(ipsetCmdTest, reqFlags, "ttl", func(a *attrBuilder) {
		putIP(a, ipsetAttrIP, addrV4(10, 0, 0, 1))
	})); errno != ipset.ErrExist {
		t.Errorf("test after the timeout errno = %d, want ErrExist", errno)
	}
}

func TestIPSetBitmapPortAndListSetCreate(t *testing.T) {
	c := newIPSetClient(t)
	c.createSet("ports", "bitmap:port", linux.AF_UNSPEC, func(a *attrBuilder) {
		a.net16(ipsetAttrPort, 1)
		a.net16(ipsetAttrPortTo, 1024)
	})
	c.ok(c.elemReq(ipsetCmdAdd, addFlags(), "ports", func(a *attrBuilder) { a.net16(ipsetAttrPort, 22) }))
	c.ok(c.elemReq(ipsetCmdTest, reqFlags, "ports", func(a *attrBuilder) { a.net16(ipsetAttrPort, 22) }))
	if errno := c.fails(c.elemReq(ipsetCmdAdd, addFlags(), "ports", func(a *attrBuilder) {
		a.net16(ipsetAttrPort, 5000)
	})); errno != ipset.ErrBitmapRange {
		t.Errorf("port out of range errno = %d, want the bitmap range error", errno)
	}
	out := c.send(c.listReq("ports", 0))
	head, _ := parseIPSetAttrs(out[0].attrs[ipsetAttrData].value, 0, ipsetAttrCreateMax, nil)
	if head[ipsetAttrPort].be16() != 1 || head[ipsetAttrPortTo].be16() != 1024 {
		t.Errorf("bitmap header = %+v", head)
	}

	c.createSet("members", "list:set", linux.AF_UNSPEC, func(a *attrBuilder) { a.net32(ipsetAttrSize, 16) })
	c.createSet("m1", "hash:ip", linux.AF_INET, nil)
	c.ok(c.elemReq(ipsetCmdAdd, addFlags(), "members", func(a *attrBuilder) { a.str(ipsetAttrName, "m1") }))
	out = c.send(c.listReq("members", 0))
	e := nestedElements(t, out[0].attrs[ipsetAttrADT])
	if len(e) != 1 || e[0][ipsetAttrName].str() != "m1" {
		t.Errorf("list:set members = %+v", e)
	}
	destroy := c.request(ipsetCmdDestroy, reqFlags, func(a *attrBuilder) {
		protocolAttr(a)
		a.str(ipsetAttrSetname, "m1")
	})
	if errno := c.fails(destroy); errno != ipset.ErrBusy {
		t.Errorf("destroy of a member errno = %d, want the busy error", errno)
	}
}
