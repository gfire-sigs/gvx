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

package ext4lite

// The audit suite (files audit_*_test.go) checks ext4lite against the ext4
// on-disk format and against crash semantics. It shares no helper and no
// parser with the engine tests. The oracle in audit_oracle_test.go reads raw
// bytes with its own offsets, so a wrong constant in ondisk.go fails a test.
//
// This file holds the host file double. auFile keeps the image in memory as
// sparse 4 KiB pages and logs every write, so a test can rebuild the image
// that any crash point leaves.
//
// Environment variables:
//
//	EXT4LITE_AUDIT_SAMPLES=N    power-loss images for each sync epoch (default 10)
//	EXT4LITE_AUDIT_MUTANTS=N    damaged images of the hostile test (default 800)

import (
	"errors"
	"maps"
	"math/rand/v2"
	"sync"
	"testing"
)

const auPage = 4096

// auPages is a sparse image. A missing page reads as zeros. A page is never
// changed in place, so clone only copies the map.
type auPages struct {
	pages map[int64]*[auPage]byte
	size  int64
}

func newAuPages() *auPages { return &auPages{pages: make(map[int64]*[auPage]byte)} }

func (p *auPages) clone() *auPages {
	c := &auPages{pages: make(map[int64]*[auPage]byte, len(p.pages)), size: p.size}
	maps.Copy(c.pages, p.pages)
	return c
}

// readAt fills b from the image. Bytes beyond the size read as zeros.
func (p *auPages) readAt(b []byte, off int64) {
	for len(b) > 0 {
		idx, in := off/auPage, int(off%auPage)
		n := min(len(b), auPage-in)
		if pg := p.pages[idx]; pg != nil && off < p.size {
			copy(b[:n], pg[in:in+n])
			if off+int64(n) > p.size {
				clear(b[max(0, int(p.size-off)):n])
			}
		} else {
			clear(b[:n])
		}
		b, off = b[n:], off+int64(n)
	}
}

// writeAt copies b into the image and extends the size.
func (p *auPages) writeAt(b []byte, off int64) {
	if end := off + int64(len(b)); end > p.size {
		p.size = end
	}
	for len(b) > 0 {
		idx, in := off/auPage, int(off%auPage)
		n := min(len(b), auPage-in)
		pg := new([auPage]byte)
		if old := p.pages[idx]; old != nil {
			*pg = *old
		}
		copy(pg[in:], b[:n])
		p.pages[idx] = pg
		b, off = b[n:], off+int64(n)
	}
}

func (p *auPages) truncate(size int64) {
	for idx := range p.pages {
		if idx*auPage >= size {
			delete(p.pages, idx)
		}
	}
	if pg := p.pages[size/auPage]; pg != nil && size%auPage != 0 {
		c := *pg
		clear(c[size%auPage:])
		p.pages[size/auPage] = &c
	}
	p.size = size
}

func (p *auPages) ensure(size int64) {
	if size > p.size {
		p.size = size
	}
}

// bytes returns the whole image.
func (p *auPages) bytes() []byte {
	b := make([]byte, p.size)
	p.readAt(b, 0)
	return b
}

type auOpKind int

const (
	auWrite auOpKind = iota
	auSync
	auEnsure
	auTrunc
)

// auOp is one call that reached the host file.
type auOp struct {
	kind auOpKind
	off  int64
	data []byte
	size int64
}

// apply performs op on p.
func (op *auOp) apply(p *auPages) {
	switch op.kind {
	case auWrite:
		p.writeAt(op.data, op.off)
	case auEnsure:
		p.ensure(op.size)
	case auTrunc:
		p.truncate(op.size)
	}
}

// auFile is a hostFile that lives in memory and logs every call.
type auFile struct {
	mu   sync.Mutex
	cur  *auPages
	log  []auOp
	tier storageTier

	// avail is the value of AvailBytes. A negative value means no limit.
	avail int64
	// fail runs before every logged call. A non-nil result fails the call and
	// leaves the image and the log unchanged.
	fail func(kind auOpKind, idx int) error
	// failWrite runs before every write with its offset and length.
	failWrite func(off int64, n int) error
	nCalls    int
	closed    bool
	// maxSize is the largest size that the host file ever had. The capacity
	// tests compare it with the size that the volume needs.
	maxSize int64
}

// peak records the size after a call that can grow the file.
func (f *auFile) peak() { f.maxSize = max(f.maxSize, f.cur.size) }

var _ hostFile = (*auFile)(nil)

func newAuFile(base *auPages) *auFile {
	if base == nil {
		base = newAuPages()
	}
	return &auFile{cur: base, tier: tierNative, avail: -1}
}

var errAuInjected = errors.New("audit: injected host failure")

func (f *auFile) check(kind auOpKind) error {
	if f.fail == nil {
		return nil
	}
	idx := f.nCalls
	f.nCalls++
	return f.fail(kind, idx)
}

func (f *auFile) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cur.readAt(p, off)
	return len(p), nil
}

func (f *auFile) WriteAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(auWrite); err != nil {
		return 0, err
	}
	if f.failWrite != nil {
		if err := f.failWrite(off, len(p)); err != nil {
			return 0, err
		}
	}
	op := auOp{kind: auWrite, off: off, data: append([]byte(nil), p...)}
	op.apply(f.cur)
	f.log = append(f.log, op)
	f.peak()
	return len(p), nil
}

func (f *auFile) Sync() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(auSync); err != nil {
		return err
	}
	f.log = append(f.log, auOp{kind: auSync})
	return nil
}

func (f *auFile) Size() (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cur.size, nil
}

func (f *auFile) EnsureSize(size int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(auEnsure); err != nil {
		return err
	}
	if f.tier == tierFallback {
		// The fallback tier grows the file in steps, as the real host file does.
		size = (size + fallbackStep - 1) &^ (fallbackStep - 1)
	}
	op := auOp{kind: auEnsure, size: size}
	op.apply(f.cur)
	f.log = append(f.log, op)
	f.peak()
	return nil
}

func (f *auFile) Truncate(size int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(auTrunc); err != nil {
		return err
	}
	op := auOp{kind: auTrunc, size: size}
	op.apply(f.cur)
	f.log = append(f.log, op)
	return nil
}

func (f *auFile) AvailBytes() (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.avail < 0 {
		return 1 << 50, nil
	}
	if cur := f.cur.size; f.avail > cur {
		return uint64(f.avail - cur), nil
	}
	return 0, nil
}

func (f *auFile) Tier() storageTier { return f.tier }

func (f *auFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// snapshot returns the image as it is now. A SIGKILL of the process leaves
// exactly this image, because the host page cache keeps every finished write.
func (f *auFile) snapshot() *auPages {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cur.clone()
}

// syncsSince returns the number of host flush calls since mark.
func (f *auFile) syncsSince(mark int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, op := range f.log[mark:] {
		if op.kind == auSync {
			n++
		}
	}
	return n
}

// mark returns the length of the log. Pass it to window later.
func (f *auFile) mark() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.log)
}

// window returns the log entries from mark on, together with the image at
// mark.
type auWindow struct {
	base *auPages
	ops  []auOp
}

// beginWindow starts to record. It returns the image now and a function that
// ends the window.
func (f *auFile) beginWindow() (base *auPages, end func() auWindow) {
	f.mu.Lock()
	base = f.cur.clone()
	start := len(f.log)
	f.mu.Unlock()
	return base, func() auWindow {
		f.mu.Lock()
		defer f.mu.Unlock()
		return auWindow{base: base, ops: append([]auOp(nil), f.log[start:]...)}
	}
}

// prefix returns the image after the first n operations of the window. This is
// the process-crash model: the host page cache holds every finished write, and
// no write is torn.
func (w auWindow) prefix(n int) *auPages {
	p := w.base.clone()
	for i := range n {
		w.ops[i].apply(p)
	}
	return p
}

// epochs returns the half-open ranges [lo, hi) of the writes between two
// syncs.
func (w auWindow) epochs() [][2]int {
	var out [][2]int
	lo := 0
	for i, op := range w.ops {
		if op.kind == auSync {
			out = append(out, [2]int{lo, i})
			lo = i + 1
		}
	}
	return append(out, [2]int{lo, len(w.ops)})
}

// powerLoss returns an image that a host crash can leave inside the epoch
// [lo, hi). Everything before lo is durable, because a sync ended the epoch
// before. Each write of the epoch survives with probability keep. When
// sectors is true, each 512-byte sector of a write survives on its own, which
// models a torn write. Size changes of the host file are always durable.
func (w auWindow) powerLoss(lo, hi int, rng *rand.Rand, keep float64, sectors bool) *auPages {
	p := w.prefix(lo)
	for _, op := range w.ops[lo:hi] {
		switch op.kind {
		case auEnsure, auTrunc:
			op.apply(p)
		case auWrite:
			if !sectors {
				if rng.Float64() < keep {
					op.apply(p)
				}
				continue
			}
			for s := 0; s < len(op.data); s += 512 {
				if rng.Float64() < keep {
					e := min(s+512, len(op.data))
					p.writeAt(op.data[s:e], op.off+int64(s))
				}
			}
		}
	}
	return p
}

// auOpen mounts the image p with the engine and returns the volume. The
// caller owns the volume. The background flusher is off.
func auOpen(p *auPages, opts VolumeOptions) (*Volume, *auFile, error) {
	f := newAuFile(p)
	v, err := mountHostFile(f, opts)
	if err != nil {
		return nil, f, err
	}
	return &Volume{v: v}, f, nil
}

// auNoFlusher stops the background flush for the test, so that the log holds
// only the writes that the test asks for.
func auNoFlusher(t testing.TB) {
	t.Helper()
	old := flushIntervalNanos.Load()
	flushIntervalNanos.Store(int64(1 << 60))
	t.Cleanup(func() { flushIntervalNanos.Store(old) })
}
