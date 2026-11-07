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

package netbackend

import (
	"fmt"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const (
	// tailLossStream is the size of the stream that the sender writes.
	tailLossStream = 256 * 1024
	// tailLossBurstStart and tailLossBurstEnd bound the stream offsets whose
	// first transmission the link drops. The burst makes the sender enter loss
	// recovery.
	tailLossBurstStart = 60000
	tailLossBurstEnd   = 100000
	// tailLossTail is the size of the stream end whose first transmission the
	// link drops. The sender has no later segment to learn about these losses.
	tailLossTail = 3000
	// tailLossRuns is the count of parallel runs. A run that meets the stall
	// needs the race of two timers, so one run does not always meet it.
	tailLossRuns = 16
)

// dropLink forwards the packets of src to dst. It drops the first
// transmission of the TCP data segments that dropFirst selects, and it never
// drops a retransmission.
type dropLink struct {
	dropFirst func(offset uint32) bool

	mu   sync.Mutex
	isn  uint32
	seen map[uint32]bool
}

// forward starts the goroutine that moves packets until the test ends.
func (l *dropLink) forward(t *testing.T, src, dst *channel.Endpoint) {
	t.Helper()
	l.seen = make(map[uint32]bool)
	go func() {
		for {
			pkt := src.ReadContext(t.Context())
			if pkt == nil {
				return
			}
			var raw []byte
			for _, s := range pkt.AsSlices() {
				raw = append(raw, s...)
			}
			pkt.DecRef()
			if l.drops(raw) {
				continue
			}
			in := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
			dst.InjectInbound(ipv4.ProtocolNumber, in)
			in.DecRef()
		}
	}()
}

// drops reports whether the link loses the IPv4 packet raw.
func (l *dropLink) drops(raw []byte) bool {
	if l.dropFirst == nil || len(raw) < header.IPv4MinimumSize {
		return false
	}
	ip := header.IPv4(raw)
	if ip.Protocol() != uint8(header.TCPProtocolNumber) {
		return false
	}
	tcp := header.TCP(raw[ip.HeaderLength():])
	l.mu.Lock()
	defer l.mu.Unlock()
	if tcp.Flags().Contains(header.TCPFlagSyn) {
		l.isn = tcp.SequenceNumber()
	}
	if int(ip.TotalLength())-int(ip.HeaderLength())-int(tcp.DataOffset()) <= 0 {
		return false
	}
	offset := tcp.SequenceNumber() - l.isn - 1
	retransmission := l.seen[offset]
	l.seen[offset] = true
	return !retransmission && l.dropFirst(offset)
}

// TestTCPRecoversFromLossOfTheStreamTail checks that a TCP sender finishes a
// transfer after a burst loss in the middle and the loss of the last
// segments. The sender must keep a retransmit timer while data is unacked. A
// sender that leaves the timer off after loss recovery waits for ever.
func TestTCPRecoversFromLossOfTheStreamTail(t *testing.T) {
	for run := range tailLossRuns {
		t.Run(fmt.Sprintf("run%d", run), func(t *testing.T) {
			t.Parallel()
			guest := netip.MustParseAddr("10.0.2.15")
			remote := netip.MustParseAddr("10.0.2.1")
			client, clientEP := newTestStack(t, DefaultWireGuardMTU, netip.PrefixFrom(guest, 24))
			server, serverEP := newTestStack(t, DefaultWireGuardMTU, netip.PrefixFrom(remote, 24))
			forward := &dropLink{dropFirst: func(offset uint32) bool {
				inBurst := offset >= tailLossBurstStart && offset < tailLossBurstEnd
				return inBurst || offset >= tailLossStream-tailLossTail
			}}
			forward.forward(t, clientEP, serverEP)
			(&dropLink{}).forward(t, serverEP, clientEP)

			l := listenTCP(t, server, remote, 7000)
			received := make(chan error, 1)
			go func() {
				c, err := l.Accept()
				if err != nil {
					received <- err
					return
				}
				defer c.Close()
				n, err := io.Copy(io.Discard, io.LimitReader(c, tailLossStream))
				if err == nil && n != tailLossStream {
					err = fmt.Errorf("server received %d bytes, want %d", n, tailLossStream)
				}
				received <- err
			}()

			c, err := dialTCP(testContext(t), t, client, remote, 7000)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			stream := randomBytes(t, tailLossStream)
			go func() { _, _ = c.Write(stream) }()

			select {
			case err := <-received:
				if err != nil {
					t.Fatalf("transfer: %v", err)
				}
			case <-time.After(testTimeout / 2):
				t.Fatal("transfer stalled: the sender holds unacked data and runs no timer")
			}
		})
	}
}
