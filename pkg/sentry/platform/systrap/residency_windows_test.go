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

//go:build windows

package systrap

import (
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

func newAccountedRig(t *testing.T) (*rig, *usage.MemoryLocked) {
	t.Helper()
	acct := usage.NewMemoryLocked()
	mf, err := pgalloc.NewDefaultMemoryFile(pgalloc.MemoryFileOpts{
		SharedSection: true,
		Accounting:    acct,
	})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)
	return newRigOn(t, newPlatform(t), mf), acct
}

func TestStubResidencyAccounting(t *testing.T) {
	t.Run("counts_only_guest_touched_pages", func(t *testing.T) {
		r, acct := newAccountedRig(t)
		const cgID = uint32(7)
		fr, err := r.mf.Allocate(2*blockSize, pgalloc.AllocOpts{Kind: usage.Anonymous, MemCgID: cgID})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		defer r.mf.DecRef(fr)

		// Map into the stub without reading or writing via Sentry MapInternal.
		r.mapRange(dataVA, fr, hostarch.ReadWrite)
		r.mf.FlushCommitScan()
		if got := acct.TotalPerCg(cgID); got != 0 {
			t.Fatalf("TotalPerCg before guest touch = %d, want 0", got)
		}

		r.program(gStoreTo(dataVA, 0x1122334455667788), gSyscall(93))
		si, _, err := r.run()
		mustSyscall(t, si, err, 93, r.ac)

		r.mf.FlushCommitScan()
		if got := acct.TotalPerCg(cgID); got != blockSize {
			t.Fatalf("TotalPerCg after touching page 0 = %d, want %d", got, blockSize)
		}

		r.program(gStoreTo(dataVA+blockSize, 0x8877665544332211), gSyscall(94))
		si, _, err = r.run()
		mustSyscall(t, si, err, 94, r.ac)

		r.mf.FlushCommitScan()
		if got := acct.TotalPerCg(cgID); got != 2*blockSize {
			t.Fatalf("TotalPerCg after touching page 1 = %d, want %d", got, 2*blockSize)
		}
	})

	t.Run("survives_unmap_before_scan", func(t *testing.T) {
		r, acct := newAccountedRig(t)
		const cgID = uint32(8)
		fr, err := r.mf.Allocate(blockSize, pgalloc.AllocOpts{Kind: usage.Anonymous, MemCgID: cgID})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		defer r.mf.DecRef(fr)

		r.mapRange(dataVA, fr, hostarch.ReadWrite)
		r.program(gStoreTo(dataVA, 0x42), gSyscall(93))
		si, _, err := r.run()
		mustSyscall(t, si, err, 93, r.ac)

		r.as.Unmap(dataVA, blockSize)
		r.mf.FlushCommitScan()
		if got := acct.TotalPerCg(cgID); got != blockSize {
			t.Fatalf("TotalPerCg after Unmap = %d, want %d", got, blockSize)
		}
	})

	t.Run("survives_release_before_scan", func(t *testing.T) {
		r, acct := newAccountedRig(t)
		const cgID = uint32(9)
		fr, err := r.mf.Allocate(blockSize, pgalloc.AllocOpts{Kind: usage.Anonymous, MemCgID: cgID})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		defer r.mf.DecRef(fr)

		r.mapRange(dataVA, fr, hostarch.ReadWrite)
		r.program(gStoreTo(dataVA, 0x43), gSyscall(93))
		si, _, err := r.run()
		mustSyscall(t, si, err, 93, r.ac)

		r.ctx.Release()
		r.as.Release()
		r.mf.FlushCommitScan()
		if got := acct.TotalPerCg(cgID); got != blockSize {
			t.Fatalf("TotalPerCg after Release = %d, want %d", got, blockSize)
		}
	})

	t.Run("unmap_decommit_decref_resets_residency", func(t *testing.T) {
		r, acct := newAccountedRig(t)
		const cgID = uint32(10)
		fr, err := r.mf.Allocate(4*blockSize, pgalloc.AllocOpts{Kind: usage.Anonymous, MemCgID: cgID})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}

		r.mapRange(dataVA, fr, hostarch.ReadWrite)
		r.program(gStoreTo(dataVA, 0x44), gSyscall(93))
		si, _, err := r.run()
		mustSyscall(t, si, err, 93, r.ac)

		r.mf.FlushCommitScan()
		if got := acct.TotalPerCg(cgID); got != blockSize {
			t.Fatalf("TotalPerCg before release = %d, want %d", got, blockSize)
		}

		r.as.Unmap(dataVA, 4*blockSize)
		r.mf.Decommit(fr)
		r.mf.DecRef(fr)
		if got := acct.TotalPerCg(cgID); got != 0 {
			t.Fatalf("TotalPerCg after Decommit+DecRef = %d, want 0", got)
		}

		fr2, err := r.mf.Allocate(blockSize, pgalloc.AllocOpts{Kind: usage.Anonymous, MemCgID: cgID})
		if err != nil {
			t.Fatalf("second Allocate: %v", err)
		}
		defer r.mf.DecRef(fr2)
		r.mapRange(dataVA, fr2, hostarch.ReadWrite)
		r.mf.FlushCommitScan()
		if got := acct.TotalPerCg(cgID); got != 0 {
			t.Fatalf("TotalPerCg for untouched reallocation = %d, want 0", got)
		}
	})

	t.Run("partial_unmap_splits_view", func(t *testing.T) {
		r, acct := newAccountedRig(t)
		const cgID = uint32(11)
		fr, err := r.mf.Allocate(4*blockSize, pgalloc.AllocOpts{Kind: usage.Anonymous, MemCgID: cgID})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		defer r.mf.DecRef(fr)

		r.mapRange(dataVA, fr, hostarch.ReadWrite)
		r.as.Unmap(dataVA+blockSize, 2*blockSize)

		r.program(
			gStoreTo(dataVA, 0x55),
			gStoreTo(dataVA+3*blockSize, 0x66),
			gSyscall(93),
		)
		si, _, err := r.run()
		mustSyscall(t, si, err, 93, r.ac)

		r.mf.FlushCommitScan()
		if got := acct.TotalPerCg(cgID); got != 2*blockSize {
			t.Fatalf("TotalPerCg after split view stores = %d, want %d", got, 2*blockSize)
		}
	})
}
