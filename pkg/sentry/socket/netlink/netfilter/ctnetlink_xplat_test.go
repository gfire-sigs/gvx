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
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// fakeTable is a connection table that holds a list of entries. A scan reads
// perBucket entries at a time, as a scan of the real table reads one bucket.
type fakeTable struct {
	entries   []stack.ConntrackEntry
	removed   map[uint32]bool
	perBucket int

	scans   int // The number of bucket reads.
	deletes int // The number of calls of ConntrackDelete, which scans the table.
}

func (f *fakeTable) alive(e stack.ConntrackEntry) bool { return !f.removed[e.ID] }

func (f *fakeTable) remove(id uint32) {
	if f.removed == nil {
		f.removed = make(map[uint32]bool)
	}
	f.removed[id] = true
}

func (f *fakeTable) ConntrackScanner() stack.ConntrackScan {
	pos := 0
	return func(dst []stack.ConntrackEntry) ([]stack.ConntrackEntry, bool) {
		f.scans++
		end := min(pos+f.perBucket, len(f.entries))
		for _, e := range f.entries[pos:end] {
			if f.alive(e) {
				dst = append(dst, e)
			}
		}
		pos = end
		return dst, pos < len(f.entries)
	}
}

func (f *fakeTable) ConntrackLookup(t stack.ConntrackTuple) (stack.ConntrackEntry, bool) {
	for _, e := range f.entries {
		if f.alive(e) && (e.Original == t || e.Reply == t) {
			return e, true
		}
	}
	return stack.ConntrackEntry{}, false
}

func (f *fakeTable) ConntrackDeleteTuple(t stack.ConntrackTuple, accept func(stack.ConntrackEntry) bool) (stack.ConntrackEntry, bool) {
	e, ok := f.ConntrackLookup(t)
	if !ok || (accept != nil && !accept(e)) {
		return e, false
	}
	f.remove(e.ID)
	return e, true
}

func (f *fakeTable) ConntrackDelete(match func(stack.ConntrackEntry) bool) int {
	f.deletes++
	n := 0
	for _, e := range f.entries {
		if f.alive(e) && match(e) {
			f.remove(e.ID)
			n++
		}
	}
	return n
}

// startedDump records the dump that a request registered.
type startedDump struct {
	dump netlink.Dumper
	err  *syserr.Error
}

func (s *startedDump) StartDump(d netlink.Dumper) *syserr.Error {
	s.dump = d
	return s.err
}

var (
	ctClient  = tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
	ctService = tcpip.AddrFrom4([4]byte{10, 96, 0, 10})
	ctBackend = tcpip.AddrFrom4([4]byte{10, 244, 1, 7})
)

// udpEntry returns a DNAT-ed UDP connection from the client port to the
// service, which a backend answers.
func udpEntry(id uint32, clientPort uint16) stack.ConntrackEntry {
	return stack.ConntrackEntry{
		ID: id,
		Original: stack.ConntrackTuple{
			NetProto: header.IPv4ProtocolNumber, TransProto: header.UDPProtocolNumber,
			Src: ctClient, Dst: ctService, SrcPort: clientPort, DstPort: 53,
		},
		Reply: stack.ConntrackTuple{
			NetProto: header.IPv4ProtocolNumber, TransProto: header.UDPProtocolNumber,
			Src: ctBackend, Dst: ctClient, SrcPort: 5353, DstPort: clientPort,
		},
		Status:  stack.ConntrackStatusConfirmed | stack.ConntrackStatusSeenReply | stack.ConntrackStatusDstNAT,
		Timeout: 25 * time.Second,
	}
}

// tcpEntry returns an established TCP connection from the client port to the
// service.
func tcpEntry(id uint32, clientPort uint16) stack.ConntrackEntry {
	e := udpEntry(id, clientPort)
	e.Original.TransProto, e.Reply.TransProto = header.TCPProtocolNumber, header.TCPProtocolNumber
	e.Original.DstPort, e.Reply.SrcPort = 80, 8080
	e.HasTCPState, e.TCPState = true, stack.ConntrackTCPEstablished
	e.Status |= stack.ConntrackStatusAssured
	e.Timeout = 120 * time.Hour
	return e
}

// v6Entry returns a UDP connection over IPv6.
func v6Entry(id uint32, clientPort uint16) stack.ConntrackEntry {
	e := udpEntry(id, clientPort)
	a := tcpip.AddrFrom16([16]byte{0xfd, 0, 15: 1})
	b := tcpip.AddrFrom16([16]byte{0xfd, 0, 15: 2})
	e.Original.NetProto, e.Reply.NetProto = header.IPv6ProtocolNumber, header.IPv6ProtocolNumber
	e.Original.Src, e.Original.Dst, e.Reply.Src, e.Reply.Dst = a, b, b, a
	return e
}

// requestTuple returns the attribute of a tuple in a request, built from the
// wire format rather than from tupleAttrs.
func requestTuple(typ uint16, t stack.ConntrackTuple) (uint16, nlmsg.NestedAttr) {
	var ip nlmsg.NestedAttr
	ip.PutAttr(ctaIPv4Src, primitive.AsByteSlice(t.Src.AsSlice()))
	ip.PutAttr(ctaIPv4Dst, primitive.AsByteSlice(t.Dst.AsSlice()))
	var proto nlmsg.NestedAttr
	proto.PutAttr(ctaProtoNum, nlmsg.PutU8(uint8(t.TransProto)))
	proto.PutAttr(ctaProtoSrcPort, nlmsg.PutU16(t.SrcPort))
	proto.PutAttr(ctaProtoDstPort, nlmsg.PutU16(t.DstPort))
	var tuple nlmsg.NestedAttr
	tuple.PutAttr(ctaTupleIP|linux.NLA_F_NESTED, primitive.AsByteSlice(ip))
	tuple.PutAttr(ctaTupleProto|linux.NLA_F_NESTED, primitive.AsByteSlice(proto))
	return typ | linux.NLA_F_NESTED, tuple
}

// request holds the parts of one ctnetlink request.
type request struct {
	msgType uint8
	flags   uint16
	family  uint8
	orig    *stack.ConntrackTuple
	reply   *stack.ConntrackTuple
	id      *uint32
	// mark and markMask are CTA_MARK and CTA_MARK_MASK. A nil value omits the
	// attribute.
	mark, markMask *uint32
	// partial removes the destination port from the original tuple.
	partial bool
}

// message encodes the request and parses it again, as the socket does for a
// datagram from the user.
func (r request) message(t *testing.T) *nlmsg.Message {
	t.Helper()
	m := nlmsg.NewMessage(linux.NetlinkMessageHeader{
		Type:  uint16(linux.NFNL_SUBSYS_CTNETLINK)<<8 | uint16(r.msgType),
		Flags: linux.NLM_F_REQUEST | r.flags,
		Seq:   99,
	})
	m.Put(&linux.NetFilterGenMsg{Family: r.family, Version: linux.NFNETLINK_V0})
	if r.orig != nil {
		typ, attr := requestTuple(ctaTupleOrig, *r.orig)
		if r.partial {
			var ip nlmsg.NestedAttr
			ip.PutAttr(ctaIPv4Src, primitive.AsByteSlice(r.orig.Src.AsSlice()))
			attr = nil
			attr.PutAttr(ctaTupleIP|linux.NLA_F_NESTED, primitive.AsByteSlice(ip))
		}
		m.PutNestedAttr(typ, attr)
	}
	if r.reply != nil {
		typ, attr := requestTuple(ctaTupleReply, *r.reply)
		m.PutNestedAttr(typ, attr)
	}
	if r.id != nil {
		m.PutAttr(ctaID, nlmsg.PutU32(*r.id))
	}
	if r.mark != nil {
		m.PutAttr(ctaMark, nlmsg.PutU32(*r.mark))
	}
	if r.markMask != nil {
		m.PutAttr(ctaMarkMask, nlmsg.PutU32(*r.markMask))
	}
	parsed, _, ok := nlmsg.ParseMessage(m.Finalize())
	if !ok {
		t.Fatal("the request does not parse")
	}
	return parsed
}

// serve runs the request against the table.
func (r request) serve(t *testing.T, table conntrackTable, dumps dumpStarter) (*nlmsg.MessageSet, *syserr.Error) {
	t.Helper()
	ms := nlmsg.NewMessageSet(1, 99)
	err := serveConntrack(table, dumps, r.message(t), ms)
	return ms, err
}

// attrsOf returns the attributes of one reply message.
func attrsOf(t *testing.T, m *nlmsg.Message) (uint8, map[uint16][]byte) {
	t.Helper()
	var gen linux.NetFilterGenMsg
	view, ok := m.GetData(&gen)
	if !ok {
		t.Fatal("the reply has no netfilter header")
	}
	attrs, ok := parseNlAttrs(view)
	if !ok {
		t.Fatal("the reply attributes do not parse")
	}
	return gen.Family, attrs
}

// tupleOf decodes a tuple attribute of a reply.
func tupleOf(t *testing.T, attrs map[uint16][]byte, typ uint16, reply bool) tupleSpec {
	t.Helper()
	spec, err := parseTuple(attrs[typ], reply)
	if err != nil {
		t.Fatalf("tuple %d does not parse: %v", typ, err)
	}
	return spec
}

func wantSpec(t *testing.T, got tupleSpec, want stack.ConntrackTuple) {
	t.Helper()
	if !got.full() || !got.matches(want) {
		t.Errorf("tuple = %+v, want %+v", got, want)
	}
}

func TestCtnetlinkGetAnswersWithTheAttributesOfTheConnection(t *testing.T) {
	udp, tcp := udpEntry(7, 40000), tcpEntry(8, 40001)
	udp.Mark = 0xca6c
	table := &fakeTable{entries: []stack.ConntrackEntry{udp, tcp}, perBucket: 10}
	tests := []struct {
		name string
		req  request
		want stack.ConntrackEntry
	}{
		{"UDP by its original tuple", request{orig: &udp.Original}, udp},
		{"UDP by its reply tuple", request{reply: &udp.Reply}, udp},
		{"TCP by its original tuple", request{orig: &tcp.Original}, tcp},
		{"TCP by original tuple and ID", request{orig: &tcp.Original, id: new(tcp.ID)}, tcp},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.req.msgType = ipctnlMsgCtGet
			ms, err := tc.req.serve(t, table, nil)
			if err != nil {
				t.Fatalf("serve = %v", err)
			}
			if len(ms.Messages) != 1 || ms.Multi {
				t.Fatalf("got %d messages with Multi %t, want one single message", len(ms.Messages), ms.Multi)
			}
			if hdr := ms.Messages[0].Header(); hdr.Type != ctnetlinkNewMsgType || hdr.Seq != 99 {
				t.Errorf("header = %+v, want type %#x and seq 99", hdr, ctnetlinkNewMsgType)
			}
			family, attrs := attrsOf(t, ms.Messages[0])
			if family != afInet {
				t.Errorf("family = %d, want %d", family, afInet)
			}
			wantSpec(t, tupleOf(t, attrs, ctaTupleOrig, false), tc.want.Original)
			wantSpec(t, tupleOf(t, attrs, ctaTupleReply, true), tc.want.Reply)
			if status, _ := readU32(attrs[ctaStatus]); status != tc.want.Status {
				t.Errorf("status = %#x, want %#x", status, tc.want.Status)
			}
			if timeout, _ := readU32(attrs[ctaTimeout]); time.Duration(timeout)*time.Second != tc.want.Timeout {
				t.Errorf("timeout = %d s, want %v", timeout, tc.want.Timeout)
			}
			if mark, ok := readU32(attrs[ctaMark]); !ok || mark != tc.want.Mark {
				t.Errorf("CTA_MARK = %#x (present %t), want %#x", mark, ok, tc.want.Mark)
			}
			if id, _ := readU32(attrs[ctaID]); id != tc.want.ID {
				t.Errorf("id = %d, want %d", id, tc.want.ID)
			}
			info, hasInfo := attrs[ctaProtoInfo]
			if hasInfo != tc.want.HasTCPState {
				t.Fatalf("has protocol info = %t, want %t", hasInfo, tc.want.HasTCPState)
			}
			if hasInfo {
				tcpInfo, _ := parseNlAttrs(info)
				state, _ := parseNlAttrs(tcpInfo[ctaProtoInfoTCP])
				if got := state[ctaProtoInfoTCPState]; len(got) != 1 || got[0] != tc.want.TCPState {
					t.Errorf("TCP state = %v, want %d", got, tc.want.TCPState)
				}
			}
		})
	}
	if table.scans != 0 || table.deletes != 0 {
		t.Errorf("a get by tuple scanned the table %d times, want a lookup only", table.scans)
	}
}

func TestCtnetlinkGetFailsLikeLinux(t *testing.T) {
	udp := udpEntry(7, 40000)
	missing := udpEntry(8, 40001)
	table := &fakeTable{entries: []stack.ConntrackEntry{udp}, perBucket: 10}
	tests := []struct {
		name string
		req  request
		want *syserr.Error
	}{
		{"unknown tuple", request{orig: &missing.Original}, syserr.ErrNoFileOrDir},
		{"ID of another connection", request{orig: &udp.Original, id: new(udp.ID + 1)}, syserr.ErrNoFileOrDir},
		{"no tuple", request{}, syserr.ErrInvalidArgument},
		{"partial tuple", request{orig: &udp.Original, partial: true}, syserr.ErrInvalidArgument},
	}
	for _, tc := range tests {
		tc.req.msgType = ipctnlMsgCtGet
		if ms, err := tc.req.serve(t, table, nil); err != tc.want || len(ms.Messages) != 0 {
			t.Errorf("%s: serve = %v with %d messages, want %v and none", tc.name, err, len(ms.Messages), tc.want)
		}
	}
}

func TestCtnetlinkDeleteByTupleDoesNotScanTheTable(t *testing.T) {
	entries := []stack.ConntrackEntry{udpEntry(1, 40000), udpEntry(2, 40001), udpEntry(3, 40002), tcpEntry(4, 40003)}
	tests := []struct {
		name string
		req  request
		gone uint32
	}{
		{"original tuple", request{orig: &entries[1].Original}, 2},
		{"reply tuple", request{reply: &entries[2].Reply}, 3},
		{"original tuple and its ID", request{orig: &entries[3].Original, id: new(uint32(4))}, 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			table := &fakeTable{entries: entries, perBucket: 2}
			tc.req.msgType = ipctnlMsgCtDelete
			if ms, err := tc.req.serve(t, table, nil); err != nil || len(ms.Messages) != 0 {
				t.Fatalf("serve = %v with %d messages, want success and none", err, len(ms.Messages))
			}
			for _, e := range entries {
				if gone := table.removed[e.ID]; gone != (e.ID == tc.gone) {
					t.Errorf("connection %d removed = %t, want %t", e.ID, gone, e.ID == tc.gone)
				}
			}
			if table.scans != 0 || table.deletes != 0 {
				t.Errorf("the delete scanned the table (%d bucket reads, %d filter deletes), want a single lookup", table.scans, table.deletes)
			}
		})
	}
}

func TestCtnetlinkDeleteByTupleFailsWhenNothingMatches(t *testing.T) {
	udp := udpEntry(1, 40000)
	missing := udpEntry(2, 40001)
	table := &fakeTable{entries: []stack.ConntrackEntry{udp}, perBucket: 2}
	for name, req := range map[string]request{
		"unknown tuple":    {orig: &missing.Original},
		"ID of another":    {orig: &udp.Original, id: new(uint32(9))},
		"unknown reply":    {reply: &missing.Reply},
		"reply with other": {reply: &udp.Reply, id: new(uint32(9))},
	} {
		req.msgType = ipctnlMsgCtDelete
		if _, err := req.serve(t, table, nil); err != syserr.ErrNoFileOrDir {
			t.Errorf("%s: serve = %v, want ENOENT", name, err)
		}
	}
	if len(table.removed) != 0 {
		t.Errorf("a failed delete removed %v", table.removed)
	}
}

func TestCtnetlinkDeleteWithAPartialTupleRemovesTheMatches(t *testing.T) {
	entries := []stack.ConntrackEntry{udpEntry(1, 40000), udpEntry(2, 40001), v6Entry(3, 40002)}
	other := udpEntry(4, 40003)
	other.Original.Src = tcpip.AddrFrom4([4]byte{10, 0, 0, 77})
	entries = append(entries, other)
	table := &fakeTable{entries: entries, perBucket: 2}
	req := request{msgType: ipctnlMsgCtDelete, family: afInet, orig: &entries[0].Original, partial: true}
	if _, err := req.serve(t, table, nil); err != nil {
		t.Fatalf("serve = %v", err)
	}
	// The partial tuple names only the source address 10.0.0.2 of IPv4.
	for id, wantGone := range map[uint32]bool{1: true, 2: true, 3: false, 4: false} {
		if table.removed[id] != wantGone {
			t.Errorf("connection %d removed = %t, want %t", id, table.removed[id], wantGone)
		}
	}
}

// drainDump calls DumpChunk until the dump ends. It returns the messages of
// each chunk. between runs before each call after the first.
func drainDump(t *testing.T, d netlink.Dumper, limit int, between func(chunk int)) [][]*nlmsg.Message {
	t.Helper()
	var chunks [][]*nlmsg.Message
	for i := 0; ; i++ {
		if i > 0 && between != nil {
			between(i)
		}
		set := nlmsg.NewMessageSet(1, 99)
		set.Multi = true
		more, err := d.DumpChunk(context.Background(), set, limit)
		if err != nil {
			t.Fatalf("DumpChunk %d = %v", i, err)
		}
		if len(set.Messages) > 0 {
			chunks = append(chunks, set.Messages)
		}
		if !more {
			d.DumpDone()
			return chunks
		}
		if len(set.Messages) == 0 && i > 1<<20 {
			t.Fatal("the dump does not end")
		}
	}
}

func chunkBytes(msgs []*nlmsg.Message) int {
	n := 0
	for _, m := range msgs {
		n += netlink.MessageSize(m)
	}
	return n
}

// idsOf returns the connection ID of each message, and it checks the header
// of the message.
func idsOf(t *testing.T, msgs []*nlmsg.Message) []uint32 {
	t.Helper()
	var ids []uint32
	for _, m := range msgs {
		hdr := m.Header()
		if hdr.Type != ctnetlinkNewMsgType || hdr.Flags != linux.NLM_F_MULTI || hdr.Seq != 99 {
			t.Errorf("dump message header = %+v, want type %#x with only NLM_F_MULTI", hdr, ctnetlinkNewMsgType)
		}
		_, attrs := attrsOf(t, m)
		id, ok := readU32(attrs[ctaID])
		if !ok {
			t.Fatal("a dump message has no ID")
		}
		ids = append(ids, id)
	}
	return ids
}

func manyEntries(n int) []stack.ConntrackEntry {
	entries := make([]stack.ConntrackEntry, n)
	for i := range entries {
		entries[i] = udpEntry(uint32(i+1), uint16(10000+i))
	}
	return entries
}

func TestCtnetlinkDumpStartsOneDumpWithoutAnswering(t *testing.T) {
	table := &fakeTable{entries: manyEntries(3), perBucket: 2}
	var dumps startedDump
	req := request{msgType: ipctnlMsgCtGet, flags: linux.NLM_F_DUMP}
	ms, err := req.serve(t, table, &dumps)
	if err != nil || dumps.dump == nil {
		t.Fatalf("serve = %v with dump %v, want a registered dump", err, dumps.dump)
	}
	if len(ms.Messages) != 0 || ms.Multi {
		t.Errorf("the request answered %d messages with Multi %t, want none: the socket sends the chunks", len(ms.Messages), ms.Multi)
	}
	if table.scans != 0 {
		t.Errorf("the request scanned %d buckets, want none before the first chunk", table.scans)
	}

	busy := startedDump{err: syserr.ErrBusy}
	if _, err := req.serve(t, table, &busy); err != syserr.ErrBusy {
		t.Errorf("serve with a running dump = %v, want EBUSY", err)
	}
}

func TestCtnetlinkDumpPastTheFormerLimitListsEveryConnection(t *testing.T) {
	const entries = 5000
	table := &fakeTable{entries: manyEntries(entries), perBucket: 3}
	var dumps startedDump
	req := request{msgType: ipctnlMsgCtGet, flags: linux.NLM_F_DUMP}
	if _, err := req.serve(t, table, &dumps); err != nil {
		t.Fatalf("serve = %v", err)
	}
	const limit = 3776
	chunks := drainDump(t, dumps.dump, limit, nil)
	seen := make(map[uint32]int)
	total := 0
	for i, chunk := range chunks {
		total += chunkBytes(chunk)
		if n := chunkBytes(chunk); n > limit && len(chunk) > 1 {
			t.Errorf("chunk %d has %d bytes with %d messages, want at most %d", i, n, len(chunk), limit)
		}
		for _, id := range idsOf(t, chunk) {
			seen[id]++
		}
	}
	if len(seen) != entries {
		t.Fatalf("dump lists %d connections, want %d", len(seen), entries)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("connection %d appears %d times, want once", id, n)
		}
	}
	// The former dump stopped at 192 KiB.
	if total <= 192<<10 {
		t.Errorf("the dump has %d bytes, want more than 192 KiB", total)
	}
}

func TestCtnetlinkDumpReadsTheTableOnlyAsTheReaderAdvances(t *testing.T) {
	table := &fakeTable{entries: manyEntries(1000), perBucket: 1}
	var dumps startedDump
	req := request{msgType: ipctnlMsgCtGet, flags: linux.NLM_F_DUMP}
	if _, err := req.serve(t, table, &dumps); err != nil {
		t.Fatalf("serve = %v", err)
	}
	set := nlmsg.NewMessageSet(1, 99)
	set.Multi = true
	more, err := dumps.dump.DumpChunk(context.Background(), set, 3776)
	if err != nil || !more || len(set.Messages) == 0 {
		t.Fatalf("first chunk = %d messages, more %t, error %v, want messages and more", len(set.Messages), more, err)
	}
	if table.scans >= len(table.entries)/2 {
		t.Errorf("the first chunk read %d of %d buckets, want only the buckets that it needs", table.scans, len(table.entries))
	}
}

func TestCtnetlinkDumpKeepsConnectionsThatSurviveTableChanges(t *testing.T) {
	const entries = 600
	table := &fakeTable{entries: manyEntries(entries), perBucket: 2}
	var dumps startedDump
	req := request{msgType: ipctnlMsgCtGet, flags: linux.NLM_F_DUMP}
	if _, err := req.serve(t, table, &dumps); err != nil {
		t.Fatalf("serve = %v", err)
	}
	// Between two chunks, delete the connections 100 to 109 and 500 to 509.
	// The dump may list a deleted connection, but it must list every other.
	gone := map[uint32]bool{}
	for i := 100; i < 110; i++ {
		gone[uint32(i+1)], gone[uint32(i+401)] = true, true
	}
	chunks := drainDump(t, dumps.dump, 3776, func(chunk int) {
		if chunk != 5 {
			return
		}
		for id := range gone {
			table.remove(id)
		}
	})
	seen := make(map[uint32]bool)
	for _, chunk := range chunks {
		for _, id := range idsOf(t, chunk) {
			seen[id] = true
		}
	}
	for _, e := range table.entries {
		if !gone[e.ID] && !seen[e.ID] {
			t.Errorf("connection %d lived through the dump and is missing", e.ID)
		}
	}
}

func TestCtnetlinkDumpAppliesTheFamilyAndTheTupleFilter(t *testing.T) {
	entries := manyEntries(30)
	for i := 0; i < len(entries); i += 3 {
		entries[i] = v6Entry(uint32(i+1), uint16(10000+i))
	}
	table := &fakeTable{entries: entries, perBucket: 4}
	wantV6 := 10
	tests := []struct {
		name string
		req  request
		want int
	}{
		{"AF_INET6", request{family: afInet6}, wantV6},
		{"AF_INET", request{family: afInet}, len(entries) - wantV6},
		{"AF_UNSPEC", request{family: afUnspec}, len(entries)},
		{"source of one IPv4 connection", request{family: afInet, orig: &entries[1].Original, partial: true}, len(entries) - wantV6},
		{"ID of one connection", request{family: afUnspec, id: new(entries[4].ID)}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var dumps startedDump
			tc.req.msgType, tc.req.flags = ipctnlMsgCtGet, linux.NLM_F_DUMP
			if _, err := tc.req.serve(t, table, &dumps); err != nil {
				t.Fatalf("serve = %v", err)
			}
			listed := 0
			for _, chunk := range drainDump(t, dumps.dump, 3776, nil) {
				listed += len(chunk)
			}
			if listed != tc.want {
				t.Errorf("dump lists %d connections, want %d", listed, tc.want)
			}
		})
	}
}

func TestCtnetlinkDumpFiltersByTheConnectionMark(t *testing.T) {
	entries := manyEntries(12)
	for i := range entries {
		entries[i].Mark = uint32(i%3) << 8
	}
	table := &fakeTable{entries: entries, perBucket: 4}
	tests := []struct {
		name       string
		mark, mask uint32
		useMask    bool
		want       int
	}{
		{"one mark without a mask", 0x100, 0, false, 4},
		{"mark 0", 0, 0, false, 4},
		{"mark under a mask that hides the difference", 0x1, 0xff, true, 0},
		{"mark under a mask that selects one mark", 0x100, 0x300, true, 4},
		{"empty mask selects all", 0x200, 0, true, 12},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var dumps startedDump
			req := request{family: afUnspec, msgType: ipctnlMsgCtGet, flags: linux.NLM_F_DUMP, mark: &tc.mark}
			if tc.useMask {
				req.markMask = &tc.mask
			}
			if _, err := req.serve(t, table, &dumps); err != nil {
				t.Fatalf("serve = %v", err)
			}
			listed := 0
			for _, chunk := range drainDump(t, dumps.dump, 3776, nil) {
				listed += len(chunk)
			}
			if listed != tc.want {
				t.Errorf("dump lists %d connections, want %d", listed, tc.want)
			}
		})
	}
}

func TestCtnetlinkDumpOfAnEmptyTableEndsAtOnce(t *testing.T) {
	table := &fakeTable{perBucket: 4}
	var dumps startedDump
	req := request{msgType: ipctnlMsgCtGet, flags: linux.NLM_F_DUMP}
	if _, err := req.serve(t, table, &dumps); err != nil {
		t.Fatalf("serve = %v", err)
	}
	set := nlmsg.NewMessageSet(1, 99)
	set.Multi = true
	if more, err := dumps.dump.DumpChunk(context.Background(), set, 3776); more || err != nil || len(set.Messages) != 0 {
		t.Errorf("DumpChunk = %d messages, more %t, error %v, want no message and the end", len(set.Messages), more, err)
	}
}

func TestCtnetlinkRejectsAnUnknownMessage(t *testing.T) {
	req := request{msgType: 42}
	if _, err := req.serve(t, &fakeTable{}, nil); err != syserr.ErrNotSupported {
		t.Errorf("serve = %v, want EOPNOTSUPP", err)
	}
}
