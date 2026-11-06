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

package route

import (
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// TestNeighDumpSplitsALargeTableIntoChunks dumps 70,000 entries, more than the
// old cap of a table and far more than one datagram holds. Each chunk must stay
// within the limit, as a reader with a small buffer needs, and the chunks
// together must hold every entry once.
func TestNeighDumpSplitsALargeTableIntoChunks(t *testing.T) {
	const count = 70000
	items := make([]func(*nlmsg.MessageSet), 0, count)
	for i := range count {
		e := stack.NeighborEntry{
			Addr:     tcpip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}),
			LinkAddr: "\x02\x00\x00\x00\x00\x01",
			State:    stack.Static,
		}
		items = append(items, func(ms *nlmsg.MessageSet) { putNeigh(ms, linux.AF_INET, 1, e) })
	}
	d := &neighDump{items: items}
	const limit = 3776
	total, chunks := 0, 0
	for {
		chunk := nlmsg.NewMessageSet(1, 1)
		chunk.Multi = true
		more, err := d.DumpChunk(context.Background(), chunk, limit)
		if err != nil {
			t.Fatal(err)
		}
		size := 0
		for _, m := range chunk.Messages {
			size += netlink.MessageSize(m)
		}
		if size > limit && len(chunk.Messages) > 1 {
			t.Fatalf("chunk %d holds %d bytes in %d messages, want at most %d", chunks, size, len(chunk.Messages), limit)
		}
		if more && len(chunk.Messages) == 0 {
			t.Fatalf("chunk %d is empty but the dump continues", chunks)
		}
		total += len(chunk.Messages)
		chunks++
		if !more {
			break
		}
	}
	if total != count {
		t.Errorf("the dump holds %d messages, want %d", total, count)
	}
	if chunks < count/100 {
		t.Errorf("the dump has %d chunks, want many small chunks", chunks)
	}
	d.DumpDone()
}

func TestNeighDumpOfAnEmptyTableEndsAtOnce(t *testing.T) {
	d := &neighDump{}
	chunk := nlmsg.NewMessageSet(1, 1)
	more, err := d.DumpChunk(context.Background(), chunk, 3776)
	if err != nil || more || len(chunk.Messages) != 0 {
		t.Errorf("DumpChunk = %v, %v with %d messages, want false, nil, 0", more, err, len(chunk.Messages))
	}
}
