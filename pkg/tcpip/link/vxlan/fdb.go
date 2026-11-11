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

package vxlan

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

// Neighbor states and flags of include/uapi/linux/neighbour.h that an FDB
// entry stores.
const (
	NUDReachable = 0x02
	NUDNoARP     = 0x40
	NUDPermanent = 0x80

	NTFSelf = 0x02
)

// Errors of the FDB operations. The netlink layer maps each one to an errno.
var (
	// ErrExists means the entry exists and the request has NLM_F_EXCL.
	ErrExists = errors.New("vxlan: FDB entry exists")
	// ErrNotFound means the entry or the remote does not exist.
	ErrNotFound = errors.New("vxlan: FDB entry not found")
	// ErrNotSupported means the operation does not apply to the entry.
	ErrNotSupported = errors.New("vxlan: FDB operation not supported for the entry")
	// ErrBadAddress means the remote address has the wrong family.
	ErrBadAddress = errors.New("vxlan: remote address family does not match the link")
	// ErrBadState means the state is neither permanent nor reachable.
	ErrBadState = errors.New("vxlan: FDB state is neither permanent nor reachable")
	// ErrNoSpace means the table has as many entries as the link limit.
	ErrNoSpace = errors.New("vxlan: FDB is full")
)

// zeroMAC is the key of the entry that holds the destinations of frames with an
// unknown destination address.
const zeroMAC tcpip.LinkAddress = "\x00\x00\x00\x00\x00\x00"

// Remote is one destination of an FDB entry: the tunnel endpoint that gets the
// encapsulated frame.
//
// +stateify savable
type Remote struct {
	// IP is the outer destination address. The unspecified address of the
	// family of the link means "no remote", and the link drops the frame.
	IP tcpip.Address
	// Port is the outer destination UDP port.
	Port uint16
	// VNI is the network identifier that the outer packet carries.
	VNI uint32
	// Link is the interface index that NDA_IFINDEX named, or 0.
	Link tcpip.NICID
}

// FDBEntry is a copy of one entry of the forwarding table.
type FDBEntry struct {
	// MAC is the inner destination address.
	MAC tcpip.LinkAddress
	// State is NUDPermanent, NUDNoARP, or NUDReachable, as the request set it.
	State uint16
	// Flags are the NTF flags that the request set.
	Flags uint8
	// Remotes lists the destinations, in the order of addition. It can be empty.
	Remotes []Remote
	// Updated is the time of the last change.
	Updated time.Time
	// Used is the time of the last use for transmission.
	Used time.Time
}

// Static reports whether the entry never ages and learning never moves it.
func (e *FDBEntry) Static() bool { return e.State&(NUDPermanent|NUDNoARP) != 0 }

// UpdateMode holds the NLM_F flags that decide how an update treats an
// existing entry, as vxlan_fdb_update does in Linux.
type UpdateMode struct {
	Create, Excl, Replace, Append bool
}

// fdbEntry is the stored form of an entry.
//
// +stateify savable
type fdbEntry struct {
	mac     tcpip.LinkAddress
	state   uint16
	flags   uint8
	remotes []Remote
	updated time.Time `state:".(int64)"`
	used    time.Time `state:".(int64)"`
}

func saveTimeNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func loadTimeNano(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

func (f *fdbEntry) saveUpdated() int64 { return saveTimeNano(f.updated) }

func (f *fdbEntry) loadUpdated(_ context.Context, ns int64) { f.updated = loadTimeNano(ns) }

func (f *fdbEntry) saveUsed() int64 { return saveTimeNano(f.used) }

func (f *fdbEntry) loadUsed(_ context.Context, ns int64) { f.used = loadTimeNano(ns) }

func (f *fdbEntry) static() bool { return f.state&(NUDPermanent|NUDNoARP) != 0 }

// fdb is the forwarding table of a link. The zero value is an empty table.
//
// +stateify savable
type fdb struct {
	mu      sync.Mutex `state:"nosave"`
	entries map[tcpip.LinkAddress]*fdbEntry
	// nextExpiry is a lower bound of the time at which a dynamic entry can end.
	// The zero value means that no dynamic entry exists, so a lookup scans the
	// table only when an entry can be due.
	nextExpiry time.Time `state:".(int64)"`
}

func (t *fdb) saveNextExpiry() int64 { return saveTimeNano(t.nextExpiry) }

func (t *fdb) loadNextExpiry(_ context.Context, ns int64) { t.nextExpiry = loadTimeNano(ns) }

// noteDynamicLocked records that f is a dynamic entry that ends ageing after
// its last use.
func (t *fdb) noteDynamicLocked(f *fdbEntry, ageing time.Duration) {
	if ageing <= 0 || f.static() {
		return
	}
	if exp := f.used.Add(ageing); t.nextExpiry.IsZero() || exp.Before(t.nextExpiry) {
		t.nextExpiry = exp
	}
}

// full reports whether a table of n entries has reached the link limit. A limit
// of 0 means no limit, as vxlan->cfg.addrmax does in vxlan_fdb_create.
func full(n int, limit uint32) bool { return limit != 0 && uint64(n) >= uint64(limit) }

// expiredLocked removes the dynamic entries that nothing used for ageing. It
// scans the table only when an entry can be due.
func (t *fdb) expiredLocked(now time.Time, ageing time.Duration) {
	if ageing <= 0 || t.nextExpiry.IsZero() || now.Before(t.nextExpiry) {
		return
	}
	var next time.Time
	for mac, f := range t.entries {
		if f.static() {
			continue
		}
		exp := f.used.Add(ageing)
		if !now.Before(exp) {
			delete(t.entries, mac)
		} else if next.IsZero() || exp.Before(next) {
			next = exp
		}
	}
	t.nextExpiry = next
}

func isMulticastOrZero(mac tcpip.LinkAddress) bool {
	return mac == zeroMAC || header.IsMulticastEthernetAddress(mac)
}

// lookup returns the destinations for a frame to mac and marks the entry as
// used. A frame with no entry goes to the all-zeros entry. The returned slice
// belongs to the caller.
func (t *fdb) lookup(mac tcpip.LinkAddress, now time.Time, ageing time.Duration, dst []Remote) []Remote {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expiredLocked(now, ageing)
	f := t.entries[mac]
	if f == nil {
		f = t.entries[zeroMAC]
	}
	if f == nil {
		return dst
	}
	f.used = now
	return append(dst, f.remotes...)
}

// update adds or changes an entry. It follows vxlan_fdb_update: an existing
// entry with the exclusive flag fails, a missing one needs the create flag, and
// the replace flag changes the first remote of a unicast entry. The append
// flag adds a remote to a multicast or all-zeros entry. A request that names a
// remote already in the entry changes nothing.
func (t *fdb) update(mac tcpip.LinkAddress, state uint16, flags uint8, r Remote, mode UpdateMode, now time.Time, ageing time.Duration, limit uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.entries == nil {
		t.entries = make(map[tcpip.LinkAddress]*fdbEntry)
	}
	f := t.entries[mac]
	if f == nil {
		if !mode.Create {
			return ErrNotFound
		}
		t.expiredLocked(now, ageing)
		if full(len(t.entries), limit) {
			return ErrNoSpace
		}
		f = &fdbEntry{mac: mac, state: state, flags: flags, remotes: []Remote{r}, updated: now, used: now}
		t.entries[mac] = f
		t.noteDynamicLocked(f, ageing)
		return nil
	}
	if mode.Excl {
		return ErrExists
	}
	if f.state != state || f.flags != flags {
		f.state, f.flags, f.updated = state, flags, now
		t.noteDynamicLocked(f, ageing)
	}
	if mode.Replace {
		if isMulticastOrZero(mac) {
			return ErrNotSupported
		}
		if len(f.remotes) != 1 || f.remotes[0] != r {
			f.remotes = []Remote{r}
			f.updated = now
		}
	}
	if mode.Append && isMulticastOrZero(mac) && !slices.Contains(f.remotes, r) {
		f.remotes = append(f.remotes, r)
		f.updated = now
	}
	return nil
}

// remove deletes the remote from the entry of mac. A remote with the
// unspecified address deletes the whole entry. The last remote of an entry
// deletes the entry too.
func (t *fdb) remove(mac tcpip.LinkAddress, r Remote) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.entries[mac]
	if f == nil {
		return ErrNotFound
	}
	if !r.IP.Unspecified() {
		i := slices.Index(f.remotes, r)
		if i < 0 {
			return ErrNotFound
		}
		if len(f.remotes) > 1 {
			f.remotes = slices.Delete(f.remotes, i, i+1)
			return nil
		}
	}
	delete(t.entries, mac)
	return nil
}

// snapshot returns copies of the entries, sorted by address.
func (t *fdb) snapshot(now time.Time, ageing time.Duration) []FDBEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.expiredLocked(now, ageing)
	out := make([]FDBEntry, 0, len(t.entries))
	for _, f := range t.entries {
		out = append(out, FDBEntry{
			MAC: f.mac, State: f.state, Flags: f.flags,
			Remotes: slices.Clone(f.remotes), Updated: f.updated, Used: f.used,
		})
	}
	slices.SortFunc(out, func(a, b FDBEntry) int {
		switch {
		case a.MAC < b.MAC:
			return -1
		case a.MAC > b.MAC:
			return 1
		}
		return 0
	})
	return out
}

// learn records that a frame from mac arrived from the outer address src. It
// follows vxlan_snoop. It reports false when the frame must be dropped, which
// holds for a static entry that names another remote. A full table learns
// nothing and drops no frame.
func (t *fdb) learn(mac tcpip.LinkAddress, src Remote, limit uint32, now time.Time, ageing time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.entries == nil {
		t.entries = make(map[tcpip.LinkAddress]*fdbEntry)
	}
	t.expiredLocked(now, ageing)
	if f := t.entries[mac]; f != nil {
		f.used = now
		if len(f.remotes) > 0 && f.remotes[0].IP == src.IP {
			f.updated = now
			return true
		}
		if f.static() {
			return false
		}
		f.remotes = []Remote{src}
		f.updated = now
		return true
	}
	if full(len(t.entries), limit) {
		return true
	}
	f := &fdbEntry{
		mac: mac, state: NUDReachable, flags: NTFSelf,
		remotes: []Remote{src}, updated: now, used: now,
	}
	t.entries[mac] = f
	t.noteDynamicLocked(f, ageing)
	return true
}
