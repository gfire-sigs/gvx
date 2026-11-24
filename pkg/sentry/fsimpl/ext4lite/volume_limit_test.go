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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

func newAuDrvCapped(t *testing.T, tier storageTier, maxBytes int64) *auDrv {
	t.Helper()
	auNoFlusher(t)
	f := newAuFile(nil)
	f.tier = tier
	v, err := mountHostFile(f, VolumeOptions{MaxBytes: maxBytes})
	if err != nil {
		t.Fatalf("mountHostFile(MaxBytes=%d): %v", maxBytes, err)
	}
	e := mountVolume(t, &Volume{v: v}, "capped.ext4", vfs.MountOptions{})
	return &auDrv{t: t, e: e, f: f, m: newAuModel()}
}

func TestValidateMaxBytesAndOpenVolumeValidation(t *testing.T) {
	for _, valid := range []int64{0, MinVolumeBytes, 2 * MinVolumeBytes, 64 << 20, MaxVolumeBytes} {
		if err := ValidateMaxBytes(valid); err != nil {
			t.Fatalf("ValidateMaxBytes(%d) = %v, want nil", valid, err)
		}
	}
	for _, invalid := range []int64{
		-1,
		-MinVolumeBytes,
		1,
		4096,
		MinVolumeBytes - 1,
		MinVolumeBytes + 4096,
		20 << 20,
		MaxVolumeBytes + MinVolumeBytes,
	} {
		if err := ValidateMaxBytes(invalid); !errors.Is(err, ErrInvalidVolumeSize) {
			t.Fatalf("ValidateMaxBytes(%d) = %v, want ErrInvalidVolumeSize", invalid, err)
		}
	}

	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.ext4")
	f, err := os.OpenFile(badPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenVolume(f, VolumeOptions{MaxBytes: 20 << 20}); !errors.Is(err, ErrInvalidVolumeSize) {
		t.Fatalf("OpenVolume(20 MiB) = %v, want ErrInvalidVolumeSize", err)
	}
	if _, err := f.Write([]byte("x")); err == nil {
		t.Fatal("OpenVolume did not close file descriptor on invalid MaxBytes")
	}
	info, err := os.Stat(badPath)
	if err != nil || info.Size() != 0 {
		t.Fatalf("bad.ext4 after rejected OpenVolume = (%v, %v), want size 0", info, err)
	}

	thinPath := filepath.Join(dir, "thin.ext4")
	tf, err := os.OpenFile(thinPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	vol, err := OpenVolume(tf, VolumeOptions{MaxBytes: 64 << 20})
	if err != nil {
		t.Fatalf("OpenVolume(64 MiB): %v", err)
	}
	if got := vol.MaxBytes(); got != 64<<20 {
		t.Fatalf("vol.MaxBytes() = %d, want %d", got, 64<<20)
	}
	if got := vol.v.numGroups(); got != 1 {
		t.Fatalf("fresh capped volume groups = %d, want 1", got)
	}
	if err := vol.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	info, err = os.Stat(thinPath)
	if err != nil || info.Size() != groupBytes {
		t.Fatalf("thin.ext4 size after Close = (%v, %v), want %d", info, err, groupBytes)
	}

	// Verify MaxVolumeBytes (64 TiB) remains distinct from uncapped zero in MaxBytes().
	maxCapPath := filepath.Join(dir, "maxcap.ext4")
	mf, err := os.OpenFile(maxCapPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	maxVol, err := OpenVolume(mf, VolumeOptions{MaxBytes: MaxVolumeBytes})
	if err != nil {
		t.Fatalf("OpenVolume(MaxVolumeBytes): %v", err)
	}
	if got := maxVol.MaxBytes(); got != MaxVolumeBytes {
		t.Fatalf("maxVol.MaxBytes() = %d, want %d", got, MaxVolumeBytes)
	}
	if err := maxVol.Close(); err != nil {
		t.Fatalf("maxVol.Close: %v", err)
	}

	uncappedF, err := os.OpenFile(maxCapPath, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	uncappedVol, err := OpenVolume(uncappedF, VolumeOptions{MaxBytes: 0})
	if err != nil {
		t.Fatalf("OpenVolume(0): %v", err)
	}
	if got := uncappedVol.MaxBytes(); got != 0 {
		t.Fatalf("uncappedVol.MaxBytes() = %d, want 0", got)
	}
	if err := uncappedVol.Close(); err != nil {
		t.Fatalf("uncappedVol.Close: %v", err)
	}
}

func TestVolumeMaxBytesGrowthFallocateAndStatfsAcrossTiers(t *testing.T) {
	const capBytes = 32 << 20
	for _, tier := range auTiers {
		t.Run(tier.String(), func(t *testing.T) {
			d := newAuDrvCapped(t, tier, capBytes)
			st, err := d.e.vfsObj.StatFSAt(d.e.ctx, d.e.creds, d.e.pop("/"))
			if err != nil {
				t.Fatalf("StatFSAt: %v", err)
			}
			if st.Blocks > 2*blocksPerGroup || st.Blocks <= blocksPerGroup {
				t.Fatalf("StatFSAt Blocks = %d, want within (4096, 8192] for 32 MiB cap", st.Blocks)
			}
			if st.Files > 2*inodesPerGroup || st.Files <= inodesPerGroup {
				t.Fatalf("StatFSAt Files = %d, want within (4096, 8192] for 32 MiB cap", st.Files)
			}

			// Sparse file length alone does not allocate image blocks.
			sparseFD, err := d.e.open("/sparse", linux.O_CREAT|linux.O_EXCL|linux.O_RDWR, 0o644)
			if err != nil {
				t.Fatalf("open /sparse: %v", err)
			}
			if err := d.e.setStat("/sparse", linux.Statx{Mask: linux.STATX_SIZE, Size: 128 << 20}); err != nil {
				t.Fatalf("truncate /sparse to 128 MiB: %v", err)
			}
			sparseFD.DecRef(d.e.ctx)
			if err := d.e.unlink("/sparse"); err != nil {
				t.Fatalf("unlink /sparse: %v", err)
			}

			const chunk = 1 << 20
			var names []string
			var failure error
			for i := 0; failure == nil; i++ {
				if i > 64 {
					t.Fatal("32 MiB capped volume accepted over 64 MiB of data")
				}
				p := fmt.Sprintf("/f%03d", i)
				fd, oErr := d.e.open(p, linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644)
				if oErr != nil {
					failure = oErr
					break
				}
				names = append(names, p)
				if _, wErr := fd.PWrite(d.e.ctx, usermem.BytesIOSequence(auFill(uint32(i+1), 0, chunk)), 0, vfsWriteOpts); wErr != nil {
					failure = wErr
				}
				fd.DecRef(d.e.ctx)
			}
			if !errors.Is(failure, linuxerr.ENOSPC) {
				t.Fatalf("write past 32 MiB cap = %v, want ENOSPC", failure)
			}
			if d.f.maxSize > capBytes {
				t.Fatalf("host file peak size = %d, want <= %d", d.f.maxSize, capBytes)
			}

			fallocFD, err := d.e.open(names[0], linux.O_RDWR, 0)
			if err != nil {
				t.Fatalf("open %s: %v", names[0], err)
			}
			if err := fallocFD.Allocate(d.e.ctx, 0, 0, 16<<20); !errors.Is(err, linuxerr.ENOSPC) {
				t.Fatalf("fallocate past 32 MiB cap = %v, want ENOSPC", err)
			}
			fallocFD.DecRef(d.e.ctx)

			// Deleting files and flushing reclaims blocks within the cap.
			for _, p := range names[1:] {
				if err := d.e.unlink(p); err != nil {
					t.Fatalf("unlink %s: %v", p, err)
				}
			}
			d.syncAll()
			reuseFD, err := d.e.open("/reused", linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644)
			if err != nil {
				t.Fatalf("open /reused: %v", err)
			}
			if _, err := reuseFD.PWrite(d.e.ctx, usermem.BytesIOSequence(auFill(99, 0, 4<<20)), 0, vfsWriteOpts); err != nil {
				t.Fatalf("write /reused after delete: %v", err)
			}
			reuseFD.DecRef(d.e.ctx)

			d.e.unmount()
			if d.f.maxSize > capBytes {
				t.Fatalf("final peak host file size = %d, want <= %d", d.f.maxSize, capBytes)
			}
			if res := auFsck(d.f.snapshot(), true); !res.OK() {
				t.Fatalf("fsck after capped workload:\n%s", res)
			}
		})
	}
}

func TestVolumeMaxBytesInodePressure(t *testing.T) {
	d := newAuDrvCapped(t, tierNative, MinVolumeBytes)
	d.f.avail = 1 << 30
	var failure error
	count := 0
	for ; count < 5000 && failure == nil; count++ {
		fd, err := d.e.open(fmt.Sprintf("/ino%05d", count), linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644)
		if err != nil {
			failure = err
			break
		}
		fd.DecRef(d.e.ctx)
	}
	if !errors.Is(failure, linuxerr.ENOSPC) {
		t.Fatalf("inode exhaustion on 16 MiB cap = %v, want ENOSPC", failure)
	}
	if count != 4086 {
		t.Fatalf("allocated %d inodes before ENOSPC, want 4086", count)
	}
	if d.f.maxSize > MinVolumeBytes {
		t.Fatalf("host file grew to %d bytes, want <= %d", d.f.maxSize, MinVolumeBytes)
	}
	d.e.unmount()
}

func TestVolumeMaxBytesMappedWritebackENOSPC(t *testing.T) {
	d := newAuDrvCapped(t, tierNative, MinVolumeBytes)
	// Fill almost all data blocks of group 0 first.
	const chunk = 256 << 10
	for i := range 64 {
		fd, err := d.e.open(fmt.Sprintf("/fill%02d", i), linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644)
		if err != nil {
			break
		}
		_, wErr := fd.PWrite(d.e.ctx, usermem.BytesIOSequence(auFill(uint32(i+1), 0, chunk)), 0, vfsWriteOpts)
		fd.DecRef(d.e.ctx)
		if wErr != nil {
			break
		}
	}

	mfd, err := d.e.open("/mapped", linux.O_CREAT|linux.O_EXCL|linux.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open /mapped: %v", err)
	}
	defer mfd.DecRef(d.e.ctx)
	const mapLen = 2 << 20
	if err := d.e.setStat("/mapped", linux.Statx{Mask: linux.STATX_SIZE, Size: mapLen}); err != nil {
		t.Fatalf("truncate /mapped: %v", err)
	}
	mp := d.e.mapFile(mfd, mapLen, true)
	defer mp.remove()
	for off := uint64(0); off < mapLen; off += uint64(hostarch.PageSize) {
		mp.store(off, []byte("MAPPED-OVERFLOW!"))
	}
	syncErr := mfd.Sync(d.e.ctx)
	if !errors.Is(syncErr, linuxerr.ENOSPC) {
		t.Fatalf("mapped Sync past 16 MiB cap = %v, want ENOSPC", syncErr)
	}
	if d.f.maxSize > MinVolumeBytes {
		t.Fatalf("host file grew past cap during mapped write-back: %d > %d", d.f.maxSize, MinVolumeBytes)
	}
	d.e.unmount()
}

type writeCountingHostFile struct {
	hostFile
	writes    int
	truncates int
}

func (w *writeCountingHostFile) WriteAt(p []byte, off int64) (int, error) {
	w.writes++
	return w.hostFile.WriteAt(p, off)
}

func (w *writeCountingHostFile) Truncate(size int64) error {
	w.truncates++
	return w.hostFile.Truncate(size)
}

func (w *writeCountingHostFile) EnsureSize(size int64) error {
	w.writes++
	return w.hostFile.EnsureSize(size)
}

func TestOpenVolumeRefusesOversizedImageAndJournalWithoutWrites(t *testing.T) {
	// 1. Build a clean 2-group (32 MiB) image and verify opening with 16 MiB cap fails without writes.
	d := newAuDrvOn(t, tierNative)
	d.create("/big", 14<<20)
	d.syncAll()
	d.e.unmount()
	cleanSnap := d.f.snapshot()
	if cleanSnap.size != 2*groupBytes {
		t.Fatalf("clean 2-group snapshot size = %d, want %d", cleanSnap.size, 2*groupBytes)
	}

	wfClean := &writeCountingHostFile{hostFile: newAuFile(cleanSnap.clone())}
	if _, err := mountHostFile(wfClean, VolumeOptions{MaxBytes: MinVolumeBytes}); !errors.Is(err, ErrVolumeExceedsMaxBytes) {
		t.Fatalf("mountHostFile(32 MiB image with 16 MiB cap) = %v, want ErrVolumeExceedsMaxBytes", err)
	}
	if wfClean.writes != 0 || wfClean.truncates != 0 {
		t.Fatalf("rejected clean open performed writes=%d truncates=%d, want 0", wfClean.writes, wfClean.truncates)
	}

	// 2. Build a crash image whose block-0 superblock still reports 1 group (16 MiB)
	// while a committed journal transaction grew the volume to 2 groups (32 MiB).
	d1 := newAuDrvOn(t, tierNative)
	d1.syncAll()
	var oldBlock0 [blockSize]byte
	if _, err := d1.f.ReadAt(oldBlock0[:], 0); err != nil {
		t.Fatal(err)
	}
	d1.create("/grow", 14<<20)
	d1.syncAll()
	crashPages := d1.f.snapshot()
	d1.e.unmount()

	// Restore the pre-growth 1-group superblock in block 0 while keeping the committed journal transaction,
	// and clamp the host file length to 16 MiB so only the committed journal reveals the 2-group final size.
	crashPages.writeAt(oldBlock0[:], 0)
	crashPages.size = MinVolumeBytes

	wfJournal := &writeCountingHostFile{hostFile: newAuFile(crashPages.clone())}
	if _, err := mountHostFile(wfJournal, VolumeOptions{MaxBytes: MinVolumeBytes}); !errors.Is(err, ErrVolumeExceedsMaxBytes) {
		t.Fatalf("mountHostFile(journal grows to 32 MiB with 16 MiB cap) = %v, want ErrVolumeExceedsMaxBytes", err)
	}
	if wfJournal.writes != 0 || wfJournal.truncates != 0 {
		t.Fatalf("rejected journal replay performed writes=%d truncates=%d, want 0", wfJournal.writes, wfJournal.truncates)
	}
}
