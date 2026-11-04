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
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/sentry/socket/unix/transport"
	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/syserr"
)

// This file implements the resumable dump of a netlink socket. A request with
// the NLM_F_DUMP flag starts a dump. The dump sends one chunk at once, as one
// datagram. Each recvmsg that consumes a datagram then asks the dump for the
// next chunk, until the dump ends with NLMSG_DONE. The receive queue of the
// socket never holds more than one chunk, however large the answer is.
//
// Ref: net/netlink/af_netlink.c (netlink_dump_start, netlink_dump, and
// netlink_recvmsg).

const (
	// minDumpChunkBytes is the size limit of the first chunk. It is
	// NLMSG_GOODSIZE of Linux on a host with 4 KiB pages: a page less the
	// skb_shared_info that the page also holds. A reader with a 4,096-byte
	// buffer reads it whole.
	minDumpChunkBytes = 3776

	// maxDumpChunkBytes is the largest chunk. The limit of Linux is one skb of
	// 32 KiB less its shared info.
	maxDumpChunkBytes = 32768 - 320
)

// Dumper produces the answer of one request with the NLM_F_DUMP flag. A
// protocol registers a Dumper with Socket.StartDump while it handles the
// request. The socket calls the methods of one Dumper one at a time.
type Dumper interface {
	// DumpChunk appends the next messages of the answer to chunk. A message
	// takes MessageSize bytes. DumpChunk stops adding messages once the
	// chunk holds limit bytes, and it adds at least one message when one
	// remains. The chunk marks each message with NLM_F_MULTI.
	//
	// DumpChunk reports true when it can add more messages in a later call.
	// It reports false after the last message. A call that adds no message
	// and reports false ends the dump. An error ends the dump too: the
	// socket sends NLMSG_DONE with the negative errno in its payload, or it
	// answers the request with the error when the first chunk fails.
	DumpChunk(ctx context.Context, chunk *nlmsg.MessageSet, limit int) (more bool, err *syserr.Error)

	// DumpDone releases the state of the dump. The socket calls it once,
	// after the last DumpChunk call or when the socket closes before the dump
	// ends.
	DumpDone()
}

// MessageSize returns the size that m takes in a datagram, with the padding
// that follows it.
func MessageSize(m *nlmsg.Message) int {
	return (len(m.Buffer()) + linux.NLMSG_ALIGNTO - 1) &^ (linux.NLMSG_ALIGNTO - 1)
}

// dumpState is the dump of a socket. The zero value has no dump.
type dumpState struct {
	mu sync.Mutex

	// starting is the Dumper that the protocol registered while it handled
	// the current request. startDump takes it.
	starting Dumper

	// active is the running dump. It is nil after the dump produced its last
	// chunk.
	active Dumper

	// seq and portID come from the request that started the dump. They go
	// into each message of the dump.
	seq    uint32
	portID int32

	// maxRecvLen is the largest buffer that a reader offered. The next chunk
	// can fill that buffer.
	maxRecvLen int

	// queue holds the datagrams that the receive queue of the socket had no
	// room for. Each call that consumes a datagram tries to send them again.
	queue [][][]byte
}

// chunkLimit returns the size limit of the next chunk.
func (d *dumpState) chunkLimit() int {
	return min(max(d.maxRecvLen, minDumpChunkBytes), maxDumpChunkBytes)
}

// StartDump registers the dump that answers the request that the protocol
// handles now. The protocol returns nil after the call, and it leaves
// ms.Multi false. The socket then sends the first chunk. It does not send an
// acknowledgement for the request. A socket runs one dump at a time: the call
// fails with EBUSY while another dump runs.
func (s *Socket) StartDump(d Dumper) *syserr.Error {
	s.dump.mu.Lock()
	defer s.dump.mu.Unlock()
	if s.dump.active != nil || s.dump.starting != nil {
		return syserr.ErrBusy
	}
	s.dump.starting = d
	return nil
}

// startDump runs after the protocol handled the request with the header hdr
// and returned handlerErr. It reports whether the request started a dump. A
// non-nil error of the result answers the request.
func (s *Socket) startDump(ctx context.Context, hdr linux.NetlinkMessageHeader, handlerErr *syserr.Error) (bool, *syserr.Error) {
	portID := s.GetPortID()
	d := &s.dump
	d.mu.Lock()
	defer d.mu.Unlock()
	starting := d.starting
	if starting == nil {
		return false, handlerErr
	}
	d.starting = nil
	if handlerErr != nil {
		starting.DumpDone()
		return false, handlerErr
	}
	d.active, d.seq, d.portID = starting, hdr.Seq, portID
	if err := s.advanceDumpLocked(ctx, true /* first */); err != nil {
		return false, err
	}
	return true, nil
}

// dumpAfterRecv runs when a read of the socket ends. recvLen is the size of
// the buffer of the reader. consumed is true when the read took a datagram out
// of the receive queue. It sends the next chunk of a running dump.
func (s *Socket) dumpAfterRecv(ctx context.Context, recvLen int, consumed bool) {
	d := &s.dump
	d.mu.Lock()
	defer d.mu.Unlock()
	d.maxRecvLen = max(d.maxRecvLen, recvLen)
	if !consumed || (d.active == nil && len(d.queue) == 0) {
		return
	}
	s.advanceDumpLocked(ctx, false /* first */)
}

// cancelDump stops a running dump. The socket calls it when it closes.
func (s *Socket) cancelDump() {
	d := &s.dump
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.starting != nil {
		d.starting.DumpDone()
		d.starting = nil
	}
	if d.active != nil {
		d.active.DumpDone()
		d.active = nil
	}
	d.queue = nil
}

// advanceDumpLocked sends the datagrams that wait for room, and then it
// produces and sends the next chunk of the dump. It produces no chunk while a
// datagram still waits: the receive queue is full. first is true for the chunk
// that answers the request. A failure of that chunk ends the dump and the
// call returns its error.
//
// Preconditions: s.dump.mu is held.
func (s *Socket) advanceDumpLocked(ctx context.Context, first bool) *syserr.Error {
	d := &s.dump
	if s.flushDumpQueueLocked(ctx) && d.active != nil {
		if err := s.produceChunkLocked(ctx, first); err != nil {
			return err
		}
		s.flushDumpQueueLocked(ctx)
	}
	return nil
}

// produceChunkLocked asks the dump for the next chunk and queues it. It queues
// NLMSG_DONE after the last chunk, and it ends the dump.
//
// Preconditions: s.dump.mu is held and d.active is not nil.
func (s *Socket) produceChunkLocked(ctx context.Context, first bool) *syserr.Error {
	d := &s.dump
	for {
		chunk := nlmsg.NewMessageSet(d.portID, d.seq)
		chunk.Multi = true
		more, err := d.active.DumpChunk(ctx, chunk, d.chunkLimit())
		if err != nil && first {
			d.active.DumpDone()
			d.active = nil
			return err
		}
		if len(chunk.Messages) > 0 && err == nil {
			bufs := make([][]byte, 0, len(chunk.Messages))
			for _, m := range chunk.Messages {
				bufs = append(bufs, m.Finalize())
			}
			d.queue = append(d.queue, bufs)
		}
		first = false
		if err != nil || !more {
			d.queue = append(d.queue, [][]byte{doneMessage(d.portID, d.seq, err)})
			d.active.DumpDone()
			d.active = nil
			return nil
		}
		if len(chunk.Messages) > 0 {
			return nil
		}
	}
}

// doneMessage returns the NLMSG_DONE message that ends a dump. Its payload
// is dump_done_errno: zero, or the negative errno of the failure.
func doneMessage(portID int32, seq uint32, err *syserr.Error) []byte {
	m := nlmsg.NewMessage(linux.NetlinkMessageHeader{
		Type:   linux.NLMSG_DONE,
		Flags:  linux.NLM_F_MULTI,
		Seq:    seq,
		PortID: uint32(portID),
	})
	errno := int32(0)
	if err != nil {
		errno = -int32(err.ToLinux())
	}
	m.Put(primitive.AllocateInt32(errno))
	return m.Finalize()
}

// flushDumpQueueLocked puts the waiting datagrams into the receive queue of
// the socket. It stops at the first datagram that does not fit, and it
// reports whether the dump queue is empty.
//
// Preconditions: s.dump.mu is held.
func (s *Socket) flushDumpQueueLocked(ctx context.Context) bool {
	d := &s.dump
	for len(d.queue) > 0 {
		if !s.queueDatagram(ctx, d.queue[0]) {
			return false
		}
		d.queue[0] = nil
		d.queue = d.queue[1:]
	}
	d.queue = nil
	return true
}

// queueDatagram puts one datagram that holds the messages bufs into the
// receive queue of the socket. It reports false when the queue has no room.
func (s *Socket) queueDatagram(ctx context.Context, bufs [][]byte) bool {
	cms := transport.ControlMessages{Credentials: kernelCreds}
	from := transport.Address{Addr: "0"}
	_, notify, err := s.connection.Send(ctx, bufs, cms, from)
	if err == syserr.ErrWouldBlock {
		return false
	}
	// Any other error means that the socket is closing: drop the datagram.
	if notify {
		s.connection.NotifyDataReady()
	}
	return true
}
