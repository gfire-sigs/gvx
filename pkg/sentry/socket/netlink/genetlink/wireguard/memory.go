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

package wireguard

import (
	"runtime"
	"sort"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/syserr"
)

// A link and a peer have no fixed limit, as in Linux. They hold memory of the
// Sentry process, and not memory of the guest, so the accounting of the guest
// would not count them. Each device and each peer therefore charges an estimate
// of its memory to the accounting of the memory file of its kernel as kernel
// memory. The memory guard of the sandbox, and MemFree of /proc/meminfo, then
// count the links and the peers, and a guest that makes too many of them
// reaches the memory limit like a guest that allocates the memory itself. The
// accounting belongs to one kernel, so the links of one sandbox never count
// against another sandbox of the same process.
const (
	// peerMemory is the estimated memory of one peer. wireguard-go allocates the
	// three packet queues, the timers, the handshake state, and two goroutines
	// for a peer. A measurement of 2,000 peers gave 25 to 28 KiB for each.
	peerMemory = 32 << 10

	// deviceBaseMemory is the estimated memory of a device without its
	// goroutines, and cpuMemory is the estimate for each CPU. wireguard-go
	// starts one encryption, one decryption, and one handshake goroutine for
	// each CPU. A measurement of 10 devices on 8 CPUs gave 400 KiB for each.
	deviceBaseMemory = 64 << 10
	cpuMemory        = 48 << 10

	// maxPeers is MAX_PEERS_PER_DEVICE of drivers/net/wireguard/messages.h. A
	// new peer beyond it fails with ENOMEM, as wg_peer_create does.
	maxPeers = 1 << 20
)

// peerLimit is the count of peers at which a new peer fails. It is a variable
// so that a test can lower it.
var peerLimit = maxPeers

// deviceBytes returns the estimated memory of one device.
func deviceBytes() uint64 {
	return deviceBaseMemory + uint64(runtime.NumCPU())*cpuMemory
}

// accountingOf returns the memory accounting of the kernel that runs ctx. A
// context without a kernel selects the global accounting.
func accountingOf(ctx context.Context) *usage.MemoryLocked {
	if k := kernel.KernelFromContext(ctx); k != nil {
		return k.MemoryFile().Accounting()
	}
	return usage.MemoryAccounting
}

// chargeMemory adds n bytes to acct. It fails with ENOMEM when the total would
// pass the memory of the host, which is the largest value that the Sentry
// reports as total memory. A nil accounting charges nothing, as in a process
// that does not run a sandbox.
func chargeMemory(acct *usage.MemoryLocked, n uint64) *syserr.Error {
	if acct == nil {
		return nil
	}
	if limit := usage.MaximumTotalMemoryBytes; limit > 0 && acct.Total()+n > limit {
		return syserr.ErrNoMemory
	}
	acct.Inc(n, usage.System, 0)
	return nil
}

// refundMemory removes n bytes from acct.
func refundMemory(acct *usage.MemoryLocked, n uint64) {
	if acct != nil && n > 0 {
		acct.Dec(n, usage.System, 0)
	}
}

// resizeCharge changes the memory of the device to the cost of its peers. It
// fails with ENOMEM when the larger size does not fit.
//
// Preconditions: e.updateMu is held.
func (e *linkEndpoint) resizeCharge() *syserr.Error {
	want := deviceBytes() + uint64(e.peers.len())*peerMemory
	switch {
	case want > e.charged:
		if err := chargeMemory(e.acct, want-e.charged); err != nil {
			return err
		}
	case want < e.charged:
		refundMemory(e.acct, e.charged-want)
	}
	e.charged = want
	return nil
}

// releaseMemory gives the whole charge of the device back.
//
// Preconditions: e.updateMu is held.
func (e *linkEndpoint) releaseMemory() {
	refundMemory(e.acct, e.charged)
	e.charged = 0
}

// peerSet lists the public keys of the peers of a device in the order of their
// creation, as the peer list of Linux does. A dump follows that order.
type peerSet struct {
	next uint64
	seq  map[[keyLen]byte]uint64
}

func (s *peerSet) init() { s.seq = make(map[[keyLen]byte]uint64) }

func (s *peerSet) len() int { return len(s.seq) }

func (s *peerSet) has(key [keyLen]byte) bool {
	_, ok := s.seq[key]
	return ok
}

// add records a new peer. It keeps the place of a peer that exists.
func (s *peerSet) add(key [keyLen]byte) {
	if _, ok := s.seq[key]; ok {
		return
	}
	s.next++
	s.seq[key] = s.next
}

func (s *peerSet) remove(key [keyLen]byte) { delete(s.seq, key) }

func (s *peerSet) clear() { clear(s.seq) }

// sortPeers orders peers by creation. A peer that the set does not know goes
// last, ordered by key.
func (s *peerSet) sortPeers(peers []peerInfo) {
	sort.Slice(peers, func(i, j int) bool {
		a, aok := s.seq[peers[i].publicKey]
		b, bok := s.seq[peers[j].publicKey]
		switch {
		case aok && bok:
			return a < b
		case aok != bok:
			return aok
		}
		return string(peers[i].publicKey[:]) < string(peers[j].publicKey[:])
	})
}
