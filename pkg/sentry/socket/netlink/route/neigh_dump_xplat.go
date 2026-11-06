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
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
)

// neighDump is the dump of a neighbor table or an FDB. The tables have no size
// limit, so the socket sends the answer in chunks, one datagram for each read,
// as netlink_dump does in Linux. The dump holds a snapshot of the entries that
// the request saw.
type neighDump struct {
	// items add one message each.
	items []func(*nlmsg.MessageSet)
	next  int
}

var _ netlink.Dumper = (*neighDump)(nil)

// DumpChunk implements netlink.Dumper.DumpChunk.
func (d *neighDump) DumpChunk(_ context.Context, chunk *nlmsg.MessageSet, limit int) (bool, *syserr.Error) {
	size := 0
	for d.next < len(d.items) {
		d.items[d.next](chunk)
		size += netlink.MessageSize(chunk.Messages[len(chunk.Messages)-1])
		if size > limit && len(chunk.Messages) > 1 {
			// The message belongs to the next chunk.
			chunk.Messages = chunk.Messages[:len(chunk.Messages)-1]
			return true, nil
		}
		d.items[d.next] = nil
		d.next++
		if size >= limit {
			break
		}
	}
	return d.next < len(d.items), nil
}

// DumpDone implements netlink.Dumper.DumpDone.
func (d *neighDump) DumpDone() { d.items = nil }
