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

package netlink

import (
	"encoding/binary"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/abi/linux/errno"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/sentry/socket/unix"
	"z.gfire.dev/gvx/pkg/sentry/socket/unix/transport"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/usermem"
)

const (
	testItemType    = linux.NLMSG_MIN_TYPE + 1
	testItemPayload = 200
	testSeq         = 77
	testPortID      = 4242
)

// testDumper is a Dumper that sends items numbered from zero. Each item is a
// message of testItemPayload bytes whose first four bytes hold the number.
type testDumper struct {
	items   int
	next    int
	chunks  int
	limits  []int
	done    int
	failAt  int // The chunk call that fails, counted from one. Zero means none.
	failErr *syserr.Error
}

func (d *testDumper) DumpChunk(_ context.Context, chunk *nlmsg.MessageSet, limit int) (bool, *syserr.Error) {
	d.chunks++
	d.limits = append(d.limits, limit)
	if d.failAt == d.chunks {
		return false, d.failErr
	}
	size := 0
	for d.next < d.items {
		m := chunk.AddMessage(linux.NetlinkMessageHeader{Type: testItemType})
		payload := make([]byte, testItemPayload)
		binary.LittleEndian.PutUint32(payload, uint32(d.next))
		m.Put(primitive.AsByteSlice(payload))
		size += MessageSize(m)
		if size > limit && len(chunk.Messages) > 1 {
			chunk.Messages = chunk.Messages[:len(chunk.Messages)-1]
			return true, nil
		}
		d.next++
		if size >= limit {
			return true, nil
		}
	}
	return false, nil
}

func (d *testDumper) DumpDone() { d.done++ }

// dumpProtocol starts the dumper of the test for each request with the
// NLM_F_DUMP flag.
type dumpProtocol struct {
	dumper *testDumper
}

func (p *dumpProtocol) Protocol() int { return 0 }
func (p *dumpProtocol) CanSend() bool { return true }
func (p *dumpProtocol) Receive(context.Context, *Socket, []byte) *syserr.Error {
	return nil
}
func (p *dumpProtocol) ProcessMessage(_ context.Context, s *Socket, msg *nlmsg.Message, _ *nlmsg.MessageSet) *syserr.Error {
	if msg.Header().Flags&linux.NLM_F_DUMP != linux.NLM_F_DUMP {
		return syserr.ErrNotSupported
	}
	return s.StartDump(p.dumper)
}

// newDumpSocket returns a socket whose protocol answers a dump with d.
func newDumpSocket(t *testing.T, d *testDumper) (*Socket, context.Context) {
	t.Helper()
	ctx := context.Background()
	ep := transport.NewConnectionless(ctx)
	if err := ep.Bind(transport.Address{Addr: "dummy"}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	connection, err := ep.(transport.BoundEndpoint).UnidirectionalConnect(ctx)
	if err != nil {
		t.Fatalf("UnidirectionalConnect: %v", err)
	}
	s := &Socket{
		protocol:   &dumpProtocol{dumper: d},
		ep:         ep,
		connection: connection,
		bound:      true,
		portID:     testPortID,
	}
	t.Cleanup(func() {
		connection.Release(ctx)
		ep.Close(ctx)
	})
	return s, ctx
}

// dumpRequest returns a request with the given flags.
func dumpRequest(flags uint16) []byte {
	m := nlmsg.NewMessage(linux.NetlinkMessageHeader{Type: testItemType, Flags: flags, Seq: testSeq})
	return m.Finalize()
}

// recvDatagram reads one datagram as RecvMsg does, and then runs the hook that
// RecvMsg runs. It returns the messages of the datagram, and nil when the
// receive queue is empty.
func recvDatagram(t *testing.T, ctx context.Context, s *Socket, bufLen int) []*nlmsg.Message {
	t.Helper()
	r := unix.EndpointReader{Ctx: ctx, Endpoint: s.ep}
	buf := make([]byte, bufLen)
	n, err := usermem.BytesIOSequence(buf).CopyOutFrom(ctx, &r)
	if err == linuxerr.ErrWouldBlock {
		return nil
	}
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if r.MsgSize > int64(n) {
		t.Fatalf("datagram of %d bytes does not fit the %d-byte buffer", r.MsgSize, bufLen)
	}
	s.dumpAfterRecv(ctx, bufLen, true /* consumed */)
	var msgs []*nlmsg.Message
	for rest := buf[:n]; len(rest) > 0; {
		m, next, ok := nlmsg.ParseMessage(rest)
		if !ok {
			t.Fatalf("malformed message in the datagram: % x", rest)
		}
		msgs = append(msgs, m)
		rest = next
	}
	return msgs
}

// readAll reads datagrams until the receive queue is empty. It returns the
// numbers of the dump items in order, the datagram sizes, and the messages
// that are not items.
func readAll(t *testing.T, ctx context.Context, s *Socket, bufLen int) (items []uint32, sizes []int, others []*nlmsg.Message) {
	t.Helper()
	for {
		msgs := recvDatagram(t, ctx, s, bufLen)
		if msgs == nil {
			return
		}
		size := 0
		for _, m := range msgs {
			size += MessageSize(m)
			hdr := m.Header()
			if hdr.Type != testItemType {
				others = append(others, m)
				continue
			}
			if hdr.Flags&linux.NLM_F_MULTI == 0 || hdr.Seq != testSeq || hdr.PortID != testPortID {
				t.Errorf("item header = %+v, want NLM_F_MULTI, seq %d, and port %d", hdr, testSeq, testPortID)
			}
			items = append(items, binary.LittleEndian.Uint32(m.Buffer()[linux.NetlinkMessageHeaderSize:]))
		}
		sizes = append(sizes, size)
	}
}

// doneErrno returns the error number in the payload of an NLMSG_DONE message.
func doneErrno(t *testing.T, m *nlmsg.Message) int32 {
	t.Helper()
	if hdr := m.Header(); hdr.Type != linux.NLMSG_DONE || hdr.Flags&linux.NLM_F_MULTI == 0 {
		t.Fatalf("header = %+v, want NLMSG_DONE with NLM_F_MULTI", hdr)
	}
	return int32(binary.LittleEndian.Uint32(m.Buffer()[linux.NetlinkMessageHeaderSize:]))
}

func checkItems(t *testing.T, items []uint32, want int) {
	t.Helper()
	if len(items) != want {
		t.Fatalf("got %d items, want %d", len(items), want)
	}
	for i, n := range items {
		if n != uint32(i) {
			t.Fatalf("item %d has the number %d", i, n)
		}
	}
}

func TestDumpSendsOneChunkAndResumesWithEachRead(t *testing.T) {
	d := &testDumper{items: 300}
	s, ctx := newDumpSocket(t, d)
	if err := s.ProcessMessages(ctx, dumpRequest(linux.NLM_F_REQUEST|linux.NLM_F_DUMP)); err != nil {
		t.Fatalf("ProcessMessages: %v", err)
	}
	if d.chunks != 1 {
		t.Fatalf("the request produced %d chunks, want 1", d.chunks)
	}
	var items []uint32
	reads := 0
	for {
		before := d.chunks
		msgs := recvDatagram(t, ctx, s, 4096)
		if msgs == nil {
			break
		}
		reads++
		for _, m := range msgs {
			if m.Header().Type == testItemType {
				items = append(items, binary.LittleEndian.Uint32(m.Buffer()[linux.NetlinkMessageHeaderSize:]))
			} else if got := doneErrno(t, m); got != 0 {
				t.Errorf("NLMSG_DONE errno = %d, want 0", got)
			}
		}
		if got := d.chunks - before; got > 1 {
			t.Fatalf("one read produced %d chunks, want at most 1", got)
		}
	}
	checkItems(t, items, 300)
	if reads < 10 {
		t.Errorf("the dump took %d datagrams, want at least 10 for 300 items of %d bytes", reads, testItemPayload)
	}
	// The first chunk comes before any read. A reader with a 4,096-byte
	// buffer then raises the limit to its buffer size.
	for i, limit := range d.limits {
		want := 4096
		if i == 0 {
			want = minDumpChunkBytes
		}
		if limit != want {
			t.Errorf("limit of chunk %d = %d, want %d", i, limit, want)
		}
	}
	if d.done != 1 {
		t.Errorf("DumpDone ran %d times, want 1", d.done)
	}
}

func TestDumpEndsWithOneDoneMessageInItsOwnDatagram(t *testing.T) {
	d := &testDumper{items: 5}
	s, ctx := newDumpSocket(t, d)
	if err := s.ProcessMessages(ctx, dumpRequest(linux.NLM_F_REQUEST|linux.NLM_F_DUMP)); err != nil {
		t.Fatalf("ProcessMessages: %v", err)
	}
	first := recvDatagram(t, ctx, s, 4096)
	if len(first) != 5 {
		t.Fatalf("first datagram holds %d messages, want 5 items", len(first))
	}
	last := recvDatagram(t, ctx, s, 4096)
	if len(last) != 1 || doneErrno(t, last[0]) != 0 {
		t.Fatalf("second datagram = %v, want one NLMSG_DONE", last)
	}
	hdr := last[0].Header()
	if hdr.Seq != testSeq || hdr.PortID != testPortID {
		t.Errorf("NLMSG_DONE header = %+v, want seq %d and port %d", hdr, testSeq, testPortID)
	}
	if extra := recvDatagram(t, ctx, s, 4096); extra != nil {
		t.Errorf("read %d messages after NLMSG_DONE, want none", len(extra))
	}
}

func TestDumpOfNothingSendsOnlyDone(t *testing.T) {
	d := &testDumper{}
	s, ctx := newDumpSocket(t, d)
	if err := s.ProcessMessages(ctx, dumpRequest(linux.NLM_F_REQUEST|linux.NLM_F_DUMP)); err != nil {
		t.Fatalf("ProcessMessages: %v", err)
	}
	items, _, others := readAll(t, ctx, s, 4096)
	if len(items) != 0 || len(others) != 1 || doneErrno(t, others[0]) != 0 {
		t.Fatalf("got %d items and %d other messages, want only NLMSG_DONE", len(items), len(others))
	}
	if d.done != 1 {
		t.Errorf("DumpDone ran %d times, want 1", d.done)
	}
}

func TestDumpDoesNotAcknowledgeTheRequest(t *testing.T) {
	d := &testDumper{items: 1}
	s, ctx := newDumpSocket(t, d)
	if err := s.ProcessMessages(ctx, dumpRequest(linux.NLM_F_REQUEST|linux.NLM_F_DUMP|linux.NLM_F_ACK)); err != nil {
		t.Fatalf("ProcessMessages: %v", err)
	}
	items, _, others := readAll(t, ctx, s, 4096)
	checkItems(t, items, 1)
	if len(others) != 1 || others[0].Header().Type != linux.NLMSG_DONE {
		t.Fatalf("other messages = %v, want only NLMSG_DONE and no NLMSG_ERROR acknowledgement", others)
	}
}

func TestDumpFillsTheBufferOfALargeReader(t *testing.T) {
	d := &testDumper{items: 1000}
	s, ctx := newDumpSocket(t, d)
	if err := s.ProcessMessages(ctx, dumpRequest(linux.NLM_F_REQUEST|linux.NLM_F_DUMP)); err != nil {
		t.Fatalf("ProcessMessages: %v", err)
	}
	// The first chunk fits the small limit. A read with a 64 KiB buffer
	// raises the limit of the later chunks.
	items, sizes, _ := readAll(t, ctx, s, 64<<10)
	checkItems(t, items, 1000)
	if sizes[0] > minDumpChunkBytes {
		t.Errorf("first datagram has %d bytes, want at most %d", sizes[0], minDumpChunkBytes)
	}
	if sizes[1] <= minDumpChunkBytes || sizes[1] > maxDumpChunkBytes {
		t.Errorf("second datagram has %d bytes, want more than %d and at most %d", sizes[1], minDumpChunkBytes, maxDumpChunkBytes)
	}
}

func TestDumpWaitsForAPeekingReader(t *testing.T) {
	d := &testDumper{items: 100}
	s, ctx := newDumpSocket(t, d)
	if err := s.ProcessMessages(ctx, dumpRequest(linux.NLM_F_REQUEST|linux.NLM_F_DUMP)); err != nil {
		t.Fatalf("ProcessMessages: %v", err)
	}
	s.dumpAfterRecv(ctx, 4096, false /* consumed */)
	if d.chunks != 1 {
		t.Errorf("a read that leaves the datagram in the queue produced %d chunks, want 1", d.chunks)
	}
}

func TestDumpStopsWhenTheSocketCloses(t *testing.T) {
	d := &testDumper{items: 300}
	s, ctx := newDumpSocket(t, d)
	if err := s.ProcessMessages(ctx, dumpRequest(linux.NLM_F_REQUEST|linux.NLM_F_DUMP)); err != nil {
		t.Fatalf("ProcessMessages: %v", err)
	}
	if recvDatagram(t, ctx, s, 4096) == nil {
		t.Fatal("the first chunk is missing")
	}
	chunks := d.chunks
	s.cancelDump()
	if d.done != 1 {
		t.Errorf("DumpDone ran %d times after the close, want 1", d.done)
	}
	s.dumpAfterRecv(ctx, 4096, true /* consumed */)
	if d.chunks != chunks {
		t.Errorf("the dump produced %d more chunks after the close, want none", d.chunks-chunks)
	}
	// A second close does not run DumpDone again.
	s.cancelDump()
	if d.done != 1 {
		t.Errorf("DumpDone ran %d times after two closes, want 1", d.done)
	}
}

func TestDumpRejectsASecondDumpWhileOneRuns(t *testing.T) {
	d := &testDumper{items: 300}
	s, ctx := newDumpSocket(t, d)
	request := dumpRequest(linux.NLM_F_REQUEST | linux.NLM_F_DUMP)
	if err := s.ProcessMessages(ctx, request); err != nil {
		t.Fatalf("ProcessMessages: %v", err)
	}
	first := recvDatagram(t, ctx, s, 4096)
	if err := s.ProcessMessages(ctx, request); err != nil {
		t.Fatalf("ProcessMessages: %v", err)
	}
	// The second request fails with EBUSY and leaves the first dump alone.
	var busy bool
	for _, m := range recvAll(t, ctx, s) {
		if m.Header().Type != linux.NLMSG_ERROR {
			continue
		}
		var errMsg linux.NetlinkErrorMessage
		errMsg.UnmarshalUnsafe(m.Buffer()[linux.NetlinkMessageHeaderSize:])
		busy = errMsg.Error == -int32(errno.EBUSY)
	}
	if !busy {
		t.Error("the second dump request did not fail with EBUSY")
	}
	if len(first) == 0 || d.done != 1 {
		t.Errorf("DumpDone ran %d times, want 1 after the first dump ended", d.done)
	}
}

// recvAll reads datagrams until the queue is empty, and it returns every
// message in order.
func recvAll(t *testing.T, ctx context.Context, s *Socket) []*nlmsg.Message {
	t.Helper()
	var all []*nlmsg.Message
	for {
		msgs := recvDatagram(t, ctx, s, maxDumpChunkBytes)
		if msgs == nil {
			return all
		}
		all = append(all, msgs...)
	}
}

func TestDumpRunsAgainAfterTheFirstEnds(t *testing.T) {
	d := &testDumper{items: 3}
	s, ctx := newDumpSocket(t, d)
	request := dumpRequest(linux.NLM_F_REQUEST | linux.NLM_F_DUMP)
	for run := range 2 {
		d.next = 0
		if err := s.ProcessMessages(ctx, request); err != nil {
			t.Fatalf("run %d: ProcessMessages: %v", run, err)
		}
		items, _, _ := readAll(t, ctx, s, 4096)
		checkItems(t, items, 3)
	}
}

func TestDumpFailureOfALaterChunkEndsWithTheErrnoInDone(t *testing.T) {
	d := &testDumper{items: 300, failAt: 3, failErr: syserr.ErrNoBufferSpace}
	s, ctx := newDumpSocket(t, d)
	if err := s.ProcessMessages(ctx, dumpRequest(linux.NLM_F_REQUEST|linux.NLM_F_DUMP)); err != nil {
		t.Fatalf("ProcessMessages: %v", err)
	}
	items, _, others := readAll(t, ctx, s, 4096)
	if len(items) == 0 || len(items) >= 300 {
		t.Errorf("got %d items, want the items of the chunks before the failure", len(items))
	}
	if len(others) != 1 || doneErrno(t, others[0]) != -int32(errno.ENOBUFS) {
		t.Fatalf("other messages = %v, want one NLMSG_DONE with -ENOBUFS", others)
	}
	if d.done != 1 {
		t.Errorf("DumpDone ran %d times, want 1", d.done)
	}
}

func TestDumpFailureOfTheFirstChunkAnswersTheRequest(t *testing.T) {
	d := &testDumper{items: 300, failAt: 1, failErr: syserr.ErrInvalidArgument}
	s, ctx := newDumpSocket(t, d)
	if err := s.ProcessMessages(ctx, dumpRequest(linux.NLM_F_REQUEST|linux.NLM_F_DUMP)); err != nil {
		t.Fatalf("ProcessMessages: %v", err)
	}
	msgs := recvAll(t, ctx, s)
	if len(msgs) != 1 || msgs[0].Header().Type != linux.NLMSG_ERROR {
		t.Fatalf("got %d messages, want one NLMSG_ERROR", len(msgs))
	}
	var errMsg linux.NetlinkErrorMessage
	errMsg.UnmarshalUnsafe(msgs[0].Buffer()[linux.NetlinkMessageHeaderSize:])
	if errMsg.Error != -int32(errno.EINVAL) {
		t.Errorf("error = %d, want -EINVAL", errMsg.Error)
	}
	if d.done != 1 {
		t.Errorf("DumpDone ran %d times, want 1", d.done)
	}
	// The failed dump leaves no dump behind, so a new one starts.
	d.failAt, d.next = 0, 0
	if err := s.ProcessMessages(ctx, dumpRequest(linux.NLM_F_REQUEST|linux.NLM_F_DUMP)); err != nil {
		t.Fatalf("ProcessMessages: %v", err)
	}
	items, _, _ := readAll(t, ctx, s, maxDumpChunkBytes)
	checkItems(t, items, 300)
}

func TestDumpKeepsEveryItemWhenTheReceiveQueueIsFull(t *testing.T) {
	d := &testDumper{items: 100}
	s, ctx := newDumpSocket(t, d)
	// Fill the receive queue with datagrams that other senders, such as
	// multicast events, queued.
	filler := make([]byte, 16<<10)
	junk := 0
	for s.queueDatagram(ctx, [][]byte{filler}) {
		junk++
	}
	if junk == 0 {
		t.Fatal("the receive queue accepted no filler")
	}
	if err := s.ProcessMessages(ctx, dumpRequest(linux.NLM_F_REQUEST|linux.NLM_F_DUMP)); err != nil {
		t.Fatalf("ProcessMessages: %v", err)
	}
	if d.chunks != 1 {
		t.Fatalf("the request produced %d chunks, want 1 that waits for room", d.chunks)
	}
	var items []uint32
	var gotDone bool
	for i := range junk {
		// A read of the filler datagrams frees room for the dump.
		r := unix.EndpointReader{Ctx: ctx, Endpoint: s.ep}
		if _, err := usermem.BytesIOSequence(make([]byte, len(filler))).CopyOutFrom(ctx, &r); err != nil {
			t.Fatalf("read of filler %d: %v", i, err)
		}
		s.dumpAfterRecv(ctx, len(filler), true /* consumed */)
	}
	for _, m := range recvAll(t, ctx, s) {
		switch m.Header().Type {
		case testItemType:
			items = append(items, binary.LittleEndian.Uint32(m.Buffer()[linux.NetlinkMessageHeaderSize:]))
		case linux.NLMSG_DONE:
			gotDone = true
		}
	}
	checkItems(t, items, 100)
	if !gotDone {
		t.Error("the dump did not end with NLMSG_DONE")
	}
}
