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

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const (
	mib = 1 << 20
)

// openTestFile opens a new file in a temporary directory. The test closes the
// file if the caller does not hand it to a hostFile.
func openTestFile(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("os.OpenFile(%q) failed: %v", path, err)
	}
	return f
}

// newTestHostFile opens a hostFile on a new temporary file. The tier is the
// native tier of the host when native is true, and tierFallback otherwise.
func newTestHostFile(t *testing.T, native bool) hostFile {
	t.Helper()
	f := openTestFile(t, filepath.Join(t.TempDir(), "volume.ext4"))
	var (
		h   hostFile
		err error
	)
	if native {
		h, err = newHostFile(f)
	} else {
		h, err = newHostFileForTier(f, tierFallback)
	}
	if err != nil {
		f.Close()
		t.Fatalf("opening the host file failed: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

// forEachTier runs fn for the native tier of the host and for tierFallback.
func forEachTier(t *testing.T, fn func(t *testing.T, h hostFile)) {
	t.Helper()
	for _, native := range []bool{true, false} {
		name := "fallback"
		if native {
			name = "platform"
		}
		t.Run(name, func(t *testing.T) {
			fn(t, newTestHostFile(t, native))
		})
	}
}

func mustSize(t *testing.T, h hostFile) int64 {
	t.Helper()
	size, err := h.Size()
	if err != nil {
		t.Fatalf("Size() failed: %v", err)
	}
	return size
}

func filled(n int, b byte) []byte {
	return bytes.Repeat([]byte{b}, n)
}

func TestHostFileReadAtZeroFillsPastEOF(t *testing.T) {
	forEachTier(t, func(t *testing.T, h hostFile) {
		if _, err := h.WriteAt([]byte("abcd"), 0); err != nil {
			t.Fatalf("WriteAt() failed: %v", err)
		}
		buf := filled(8, 0xFF)
		n, err := h.ReadAt(buf, 0)
		if n != len(buf) || err != nil {
			t.Fatalf("ReadAt() = (%d, %v), want (%d, nil)", n, err, len(buf))
		}
		want := []byte("abcd\x00\x00\x00\x00")
		if !bytes.Equal(buf, want) {
			t.Errorf("ReadAt() data = %q, want %q", buf, want)
		}
	})
}

func TestHostFileReadAtBeyondEOFReturnsZeros(t *testing.T) {
	forEachTier(t, func(t *testing.T, h hostFile) {
		if _, err := h.WriteAt([]byte("abcd"), 0); err != nil {
			t.Fatalf("WriteAt() failed: %v", err)
		}
		for _, off := range []int64{4, 5, 4096, 64 * mib} {
			buf := filled(16, 0xFF)
			n, err := h.ReadAt(buf, off)
			if n != len(buf) || err != nil {
				t.Fatalf("ReadAt(off=%d) = (%d, %v), want (%d, nil)", off, n, err, len(buf))
			}
			if !bytes.Equal(buf, make([]byte, len(buf))) {
				t.Errorf("ReadAt(off=%d) data = %x, want zeros", off, buf)
			}
		}
		if got := mustSize(t, h); got != 4 {
			t.Errorf("Size() = %d after reads, want 4", got)
		}
	})
}

func TestHostFileReadAtEmptyBuffer(t *testing.T) {
	forEachTier(t, func(t *testing.T, h hostFile) {
		n, err := h.ReadAt(nil, 100)
		if n != 0 || err != nil {
			t.Errorf("ReadAt(nil) = (%d, %v), want (0, nil)", n, err)
		}
	})
}

func TestHostFileReadAtNegativeOffset(t *testing.T) {
	forEachTier(t, func(t *testing.T, h hostFile) {
		if _, err := h.ReadAt(make([]byte, 1), -1); err == nil {
			t.Error("ReadAt(off=-1) succeeded, want an error")
		}
	})
}

func TestHostFileWriteAtBeyondEOF(t *testing.T) {
	forEachTier(t, func(t *testing.T, h hostFile) {
		const off = 8192
		if n, err := h.WriteAt([]byte("xyz"), off); n != 3 || err != nil {
			t.Fatalf("WriteAt() = (%d, %v), want (3, nil)", n, err)
		}
		if got := mustSize(t, h); got != off+3 {
			t.Errorf("Size() = %d, want %d", got, off+3)
		}
		gap := filled(off, 0xFF)
		if n, err := h.ReadAt(gap, 0); n != off || err != nil {
			t.Fatalf("ReadAt(gap) = (%d, %v), want (%d, nil)", n, err, off)
		}
		if !bytes.Equal(gap, make([]byte, off)) {
			t.Error("the gap before the write does not read as zeros")
		}
		tail := make([]byte, 3)
		if _, err := h.ReadAt(tail, off); err != nil || string(tail) != "xyz" {
			t.Errorf("ReadAt(tail) = (%q, %v), want (\"xyz\", nil)", tail, err)
		}
	})
}

func TestStorageEnsureSizeNeverShrinks(t *testing.T) {
	forEachTier(t, func(t *testing.T, h hostFile) {
		if err := h.EnsureSize(16 * mib); err != nil {
			t.Fatalf("EnsureSize(16 MiB) failed: %v", err)
		}
		got := mustSize(t, h)
		if got < 16*mib {
			t.Fatalf("Size() = %d after EnsureSize(16 MiB), want at least %d", got, 16*mib)
		}
		for _, size := range []int64{0, 1, mib, 16*mib - 1, 16 * mib} {
			if err := h.EnsureSize(size); err != nil {
				t.Fatalf("EnsureSize(%d) failed: %v", size, err)
			}
			if now := mustSize(t, h); now != got {
				t.Fatalf("Size() = %d after EnsureSize(%d), want %d", now, size, got)
			}
		}
	})
}

func TestStorageEnsureSizeRejectsInvalidSize(t *testing.T) {
	forEachTier(t, func(t *testing.T, h hostFile) {
		for _, size := range []int64{-1, 1<<63 - 1} {
			if err := h.EnsureSize(size); err == nil {
				t.Errorf("EnsureSize(%d) succeeded, want an error", size)
			}
		}
		if got := mustSize(t, h); got != 0 {
			t.Errorf("Size() = %d after rejected calls, want 0", got)
		}
	})
}

func TestStorageFallbackRoundsUpToStep(t *testing.T) {
	h := newTestHostFile(t, false)
	const step = 4 * mib
	steps := []struct {
		ask, want int64
	}{
		{0, 0},
		{1, step},
		{step, step},
		{step + 1, 2 * step},
		{3 * step, 3 * step},
		{3*step + 4095, 4 * step},
		{16 * mib, 16 * mib},
	}
	for _, s := range steps {
		if err := h.EnsureSize(s.ask); err != nil {
			t.Fatalf("EnsureSize(%d) failed: %v", s.ask, err)
		}
		if got := mustSize(t, h); got != s.want {
			t.Fatalf("Size() = %d after EnsureSize(%d), want %d", got, s.ask, s.want)
		}
	}
	if got := h.Tier(); got != tierFallback {
		t.Errorf("Tier() = %v, want %v", got, tierFallback)
	}
}

func TestStorageNativeGrowsToExactSize(t *testing.T) {
	if platformTier == tierFallback {
		t.Skip("this operating system has no native tier")
	}
	h := newTestHostFile(t, true)
	if got := h.Tier(); got != platformTier {
		t.Fatalf("Tier() = %v before growth, want %v", got, platformTier)
	}
	if err := h.EnsureSize(16 * mib); err != nil {
		t.Fatalf("EnsureSize(16 MiB) failed: %v", err)
	}
	if h.Tier() == tierFallback {
		t.Skip("the temporary volume does not support preallocation")
	}
	if got := mustSize(t, h); got != 16*mib {
		t.Errorf("Size() = %d, want %d", got, 16*mib)
	}
	if err := h.EnsureSize(32 * mib); err != nil {
		t.Fatalf("EnsureSize(32 MiB) failed: %v", err)
	}
	if got := mustSize(t, h); got != 32*mib {
		t.Errorf("Size() = %d, want %d", got, 32*mib)
	}
}

func TestStorageTruncateShrinksAndRegrowsWithZeros(t *testing.T) {
	forEachTier(t, func(t *testing.T, h hostFile) {
		data := filled(mib, 0xA5)
		if _, err := h.WriteAt(data, 0); err != nil {
			t.Fatalf("WriteAt() failed: %v", err)
		}
		if err := h.Truncate(4096); err != nil {
			t.Fatalf("Truncate(4096) failed: %v", err)
		}
		if got := mustSize(t, h); got != 4096 {
			t.Fatalf("Size() = %d after Truncate(4096), want 4096", got)
		}
		if err := h.EnsureSize(mib); err != nil {
			t.Fatalf("EnsureSize(1 MiB) failed: %v", err)
		}
		if got := mustSize(t, h); got < mib {
			t.Fatalf("Size() = %d after EnsureSize(1 MiB), want at least %d", got, mib)
		}
		got := make([]byte, mib)
		if n, err := h.ReadAt(got, 0); n != mib || err != nil {
			t.Fatalf("ReadAt() = (%d, %v), want (%d, nil)", n, err, mib)
		}
		if !bytes.Equal(got[:4096], data[:4096]) {
			t.Error("the kept head of the file changed")
		}
		if !bytes.Equal(got[4096:], make([]byte, mib-4096)) {
			t.Error("the regrown tail does not read as zeros")
		}
	})
}

func TestStorageTruncateGrows(t *testing.T) {
	forEachTier(t, func(t *testing.T, h hostFile) {
		if err := h.Truncate(12345); err != nil {
			t.Fatalf("Truncate(12345) failed: %v", err)
		}
		if got := mustSize(t, h); got != 12345 {
			t.Errorf("Size() = %d, want 12345", got)
		}
	})
}

func TestStorageSync(t *testing.T) {
	forEachTier(t, func(t *testing.T, h hostFile) {
		if _, err := h.WriteAt([]byte("data"), 0); err != nil {
			t.Fatalf("WriteAt() failed: %v", err)
		}
		if err := h.Sync(); err != nil {
			t.Errorf("Sync() failed: %v", err)
		}
	})
}

func TestStorageAvailBytes(t *testing.T) {
	forEachTier(t, func(t *testing.T, h hostFile) {
		avail, err := h.AvailBytes()
		if errors.Is(err, errors.ErrUnsupported) {
			t.Skip("this operating system has no free-space call")
		}
		if err != nil {
			t.Fatalf("AvailBytes() failed: %v", err)
		}
		if avail == 0 {
			t.Error("AvailBytes() = 0 on a temporary directory, want a positive number")
		}
	})
}

func TestStorageLockExcludesSecondHandle(t *testing.T) {
	if platformTier == tierFallback {
		t.Skip("this operating system has no lock call")
	}
	path := filepath.Join(t.TempDir(), "volume.ext4")
	first, err := newHostFile(openTestFile(t, path))
	if err != nil {
		t.Fatalf("first newHostFile() failed: %v", err)
	}
	defer first.Close()

	type result struct {
		h   hostFile
		err error
	}
	second := openTestFile(t, path)
	defer second.Close()
	done := make(chan result, 1)
	go func() {
		h, err := newHostFile(second)
		done <- result{h, err}
	}()
	select {
	case r := <-done:
		if !errors.Is(r.err, errVolumeInUse) {
			if r.h != nil {
				r.h.Close()
			}
			t.Fatalf("second newHostFile() error = %v, want %v", r.err, errVolumeInUse)
		}
		if r.h != nil {
			t.Error("second newHostFile() returned a hostFile together with an error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("second newHostFile() blocked on a held lock")
	}

	// A forced tier takes the lock too.
	if _, err := newHostFileForTier(second, tierFallback); !errors.Is(err, errVolumeInUse) {
		t.Errorf("second newHostFileForTier() error = %v, want %v", err, errVolumeInUse)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("first Close() failed: %v", err)
	}
	third, err := newHostFile(second)
	if err != nil {
		t.Fatalf("newHostFile() after Close of the holder failed: %v", err)
	}
	if err := third.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}
}

func TestStorageCloseIsIdempotent(t *testing.T) {
	f := openTestFile(t, filepath.Join(t.TempDir(), "volume.ext4"))
	h, err := newHostFile(f)
	if err != nil {
		f.Close()
		t.Fatalf("newHostFile() failed: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("first Close() failed: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Errorf("second Close() failed: %v", err)
	}
	if _, err := h.ReadAt(make([]byte, 1), 0); err == nil {
		t.Error("ReadAt() after Close succeeded, want an error")
	}
	if err := f.Close(); err == nil {
		t.Error("the os.File is still open after Close, want it closed")
	}
}

func TestStorageForcedTier(t *testing.T) {
	path := filepath.Join(t.TempDir(), "volume.ext4")
	f := openTestFile(t, path)
	defer f.Close()

	h, err := newHostFileForTier(f, tierFallback)
	if err != nil {
		t.Fatalf("newHostFileForTier(tierFallback) failed: %v", err)
	}
	if got := h.Tier(); got != tierFallback {
		t.Errorf("Tier() = %v, want %v", got, tierFallback)
	}
	if err := h.EnsureSize(1); err != nil {
		t.Fatalf("EnsureSize(1) failed: %v", err)
	}
	if got := mustSize(t, h); got != fallbackStep {
		t.Errorf("Size() = %d, want %d", got, fallbackStep)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
}

func TestStorageForcedTierRefusesUnsupportedTier(t *testing.T) {
	tiers := []storageTier{tierNative, tierWindows, storageTier(99)}
	for _, tier := range tiers {
		if tier == platformTier {
			continue
		}
		t.Run(fmt.Sprint(int(tier)), func(t *testing.T) {
			f := openTestFile(t, filepath.Join(t.TempDir(), "volume.ext4"))
			defer f.Close()
			h, err := newHostFileForTier(f, tier)
			if err == nil {
				h.Close()
				t.Fatalf("newHostFileForTier(%v) succeeded, want an error", tier)
			}
			// A refused call must not take the lock.
			h, err = newHostFile(f)
			if err != nil {
				t.Fatalf("newHostFile() after a refused call failed: %v", err)
			}
			h.Close()
		})
	}
}

func TestStorageForcedPlatformTier(t *testing.T) {
	f := openTestFile(t, filepath.Join(t.TempDir(), "volume.ext4"))
	defer f.Close()
	h, err := newHostFileForTier(f, platformTier)
	if err != nil {
		t.Fatalf("newHostFileForTier(%v) failed: %v", platformTier, err)
	}
	defer h.Close()
	if got := h.Tier(); got != platformTier {
		t.Errorf("Tier() = %v, want %v", got, platformTier)
	}
}

func replaceNativeGrow(t *testing.T, fn func(f *os.File, off, n int64) error) {
	t.Helper()
	old := nativeGrow
	nativeGrow = fn
	t.Cleanup(func() { nativeGrow = old })
}

func TestStorageDowngradesWhenNativeGrowIsUnsupported(t *testing.T) {
	if platformTier == tierFallback {
		t.Skip("this operating system has no native tier")
	}
	var calls int
	replaceNativeGrow(t, func(f *os.File, off, n int64) error {
		calls++
		return testUnsupportedErrors[0]
	})
	h := newTestHostFile(t, true)
	if got := h.Tier(); got != platformTier {
		t.Fatalf("Tier() = %v before growth, want %v", got, platformTier)
	}
	if err := h.EnsureSize(5 * mib); err != nil {
		t.Fatalf("EnsureSize(5 MiB) failed: %v", err)
	}
	if calls != 1 {
		t.Errorf("native grow ran %d times, want 1", calls)
	}
	if got := h.Tier(); got != tierFallback {
		t.Errorf("Tier() = %v after the downgrade, want %v", got, tierFallback)
	}
	if got := mustSize(t, h); got != 8*mib {
		t.Errorf("Size() = %d after the downgrade, want %d", got, 8*mib)
	}
	if err := h.EnsureSize(9 * mib); err != nil {
		t.Fatalf("EnsureSize(9 MiB) failed: %v", err)
	}
	if calls != 1 {
		t.Errorf("native grow ran %d times after the downgrade, want 1", calls)
	}
	if got := mustSize(t, h); got != 12*mib {
		t.Errorf("Size() = %d, want %d", got, 12*mib)
	}
}

func TestStorageReturnsOtherNativeGrowErrors(t *testing.T) {
	if platformTier == tierFallback {
		t.Skip("this operating system has no native tier")
	}
	errFull := errors.New("test: the volume is full")
	replaceNativeGrow(t, func(f *os.File, off, n int64) error {
		return errFull
	})
	h := newTestHostFile(t, true)
	if err := h.EnsureSize(16 * mib); err != errFull {
		t.Fatalf("EnsureSize() error = %v, want %v", err, errFull)
	}
	if got := h.Tier(); got != platformTier {
		t.Errorf("Tier() = %v after another error, want %v", got, platformTier)
	}
	if got := mustSize(t, h); got != 0 {
		t.Errorf("Size() = %d after a failed grow, want 0", got)
	}
}

func TestStorageNativeGrowReceivesCurrentSizeAndDelta(t *testing.T) {
	if platformTier == tierFallback {
		t.Skip("this operating system has no native tier")
	}
	type call struct{ off, n int64 }
	var calls []call
	replaceNativeGrow(t, func(f *os.File, off, n int64) error {
		calls = append(calls, call{off, n})
		return f.Truncate(off + n)
	})
	h := newTestHostFile(t, true)
	for _, size := range []int64{16 * mib, 8 * mib, 32 * mib} {
		if err := h.EnsureSize(size); err != nil {
			t.Fatalf("EnsureSize(%d) failed: %v", size, err)
		}
	}
	want := []call{{0, 16 * mib}, {16 * mib, 16 * mib}}
	if len(calls) != len(want) {
		t.Fatalf("native grow calls = %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Errorf("native grow call %d = %v, want %v", i, calls[i], want[i])
		}
	}
}

func TestStorageNativeUnsupportedClassifier(t *testing.T) {
	for _, err := range testUnsupportedErrors {
		if !nativeUnsupported(err) {
			t.Errorf("nativeUnsupported(%v) = false, want true", err)
		}
		wrapped := &os.PathError{Op: "fallocate", Path: "volume", Err: err}
		if !nativeUnsupported(wrapped) {
			t.Errorf("nativeUnsupported(%v) = false, want true", wrapped)
		}
	}
	for _, err := range testFatalErrors {
		if nativeUnsupported(err) {
			t.Errorf("nativeUnsupported(%v) = true, want false", err)
		}
	}
	if nativeUnsupported(errors.New("test: other")) {
		t.Error("nativeUnsupported(other) = true, want false")
	}
}

func TestStorageConcurrentUse(t *testing.T) {
	forEachTier(t, func(t *testing.T, h hostFile) {
		var wg sync.WaitGroup
		for i := range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range 8 {
					if err := h.EnsureSize(int64(i*8+j+1) * mib); err != nil {
						t.Errorf("EnsureSize() failed: %v", err)
						return
					}
				}
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				buf := make([]byte, 4096)
				for j := range 64 {
					off := int64(j) * 4096
					if _, err := h.WriteAt(filled(4096, byte(i+1)), off+int64(i)*mib); err != nil {
						t.Errorf("WriteAt() failed: %v", err)
						return
					}
					if _, err := h.ReadAt(buf, off); err != nil {
						t.Errorf("ReadAt() failed: %v", err)
						return
					}
				}
			}()
		}
		wg.Wait()
		if got := mustSize(t, h); got < 32*mib {
			t.Errorf("Size() = %d, want at least %d", got, 32*mib)
		}
	})
}
