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

package whpx

import (
	"errors"
	"runtime"
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
)

func TestNewPlatformFailsClosed(t *testing.T) {
	t.Run("capability query fails", func(t *testing.T) {
		fb := newFakeBackend()
		fb.featErr = errors.New("capability boom")
		if _, err := newPlatform(fb, Options{}); !errors.Is(err, fb.featErr) {
			t.Errorf("error is %v", err)
		}
		if fb.partitionOpen {
			t.Error("a partition exists")
		}
	})
	t.Run("hypervisor missing", func(t *testing.T) {
		fb := newFakeBackend()
		fb.feats.hypervisorPresent = false
		if _, err := newPlatform(fb, Options{}); !errors.Is(err, ErrUnsupported) {
			t.Errorf("error is %v", err)
		}
		if fb.partitionOpen {
			t.Error("a partition exists")
		}
	})
	t.Run("partition creation fails", func(t *testing.T) {
		fb := newFakeBackend()
		fb.createErr = errors.New("create boom")
		if _, err := newPlatform(fb, Options{}); !errors.Is(err, fb.createErr) {
			t.Errorf("error is %v", err)
		}
	})
	t.Run("kernel mapping fails", func(t *testing.T) {
		fb := newFakeBackend()
		boom := errors.New("map boom")
		calls := 0
		fb.mapErr = func(uint64) error {
			calls++
			if calls == 3 {
				return boom
			}
			return nil
		}
		if _, err := newPlatform(fb, Options{}); !errors.Is(err, boom) {
			t.Fatalf("error is %v", err)
		}
		if fb.partitionOpen {
			t.Error("the partition stays open after a failed start")
		}
		if len(fb.mapped) != 0 || len(fb.hosts) != 0 {
			t.Errorf("a failed start leaks %d mappings and %d host arenas", len(fb.mapped), len(fb.hosts))
		}
	})
}

func TestNewPlatformMapsTheKernelRegion(t *testing.T) {
	requireGuestPageSize(t)
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	if p.ConcurrencyCount() != p.vpCount || p.vpCount < 1 || p.vpCount > maxVPs {
		t.Fatalf("concurrency count is %d for %d processors", p.ConcurrencyCount(), p.vpCount)
	}
	if p.MapUnit() != 2<<20 || p.MinUserAddress() != minUserAddr || p.SupportsAddressSpaceIO() {
		t.Error("platform constants are wrong")
	}
	wantMax := uint64(maxUserAddrX64)
	if runtime.GOARCH == "arm64" {
		wantMax = maxUserAddrA64
	}
	if uint64(p.MaxUserAddress()) != wantMax {
		t.Errorf("max user address is %#x, want %#x", p.MaxUserAddress(), wantMax)
	}

	k := p.kernel
	check := func(name string, va uint64, gpa uint64, want hostarch.AccessType) {
		t.Helper()
		_, phys, size, opts := k.pt.Lookup(hostarch.Addr(va), false)
		if size == 0 || uint64(phys) != gpa {
			t.Errorf("%s at %#x translates to %#x (size %d), want %#x", name, va, phys, size, gpa)
			return
		}
		if opts.User {
			t.Errorf("%s is reachable from user mode", name)
		}
		if opts.AccessType.Write != want.Write || opts.AccessType.Execute != want.Execute {
			t.Errorf("%s has permissions %+v, want %+v", name, opts.AccessType, want)
		}
	}
	check("stub code", k.layout.code(), k.codeGPA, hostarch.AccessType{Read: true, Execute: true})
	if !p.arm64 {
		check("descriptor tables", k.layout.sys(), k.sysGPA, hostarch.Read)
	}
	for i := range p.vpCount {
		check("CommPage", k.layout.comm(i), k.commGPA+uint64(i)*pageSize, hostarch.ReadWrite)
	}

	// The partition maps the stub code without write permission and the
	// CommPages without execute permission.
	if f := fb.mapped[k.codeGPA].flags; f != mapFlagRead|mapFlagExecute {
		t.Errorf("stub code maps with flags %#x", f)
	}
	if f := fb.mapped[k.commGPA].flags; f != mapFlagRead|mapFlagWrite {
		t.Errorf("CommPages map with flags %#x", f)
	}
	for _, m := range fb.mapped {
		if m.flags&mapFlagWrite != 0 && m.flags&mapFlagExecute != 0 {
			t.Errorf("a mapping is writable and executable: %#x", m.flags)
		}
	}
	for gpa := range fb.mapped {
		if gpa < gpaWindowBase || gpa >= gpaWindowEnd {
			t.Errorf("mapping at %#x is outside the guest physical window", gpa)
		}
	}
}

func TestCloseReleasesEverything(t *testing.T) {
	fb := newFakeBackend()
	p, err := newPlatform(fb, Options{})
	if err != nil {
		t.Fatal(err)
	}
	c := newContext(p)
	v, err := p.acquire(c)
	if err != nil {
		t.Fatal(err)
	}
	p.release(v)
	as, err := p.NewAddressSpace(platformASOptions)
	if err != nil {
		t.Fatal(err)
	}
	guestMem := mustHost(t, fb, 2)
	if err := as.(*AddressSpace).mapHost(0x400000, guestMem, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if len(fb.mapped) != 0 {
		t.Errorf("Close leaves %d mappings in the partition", len(fb.mapped))
	}
	if err := as.(*AddressSpace).mapHost(0x500000, guestMem, hostarch.ReadWrite); !errors.Is(err, errClosed) {
		t.Errorf("mapping after Close returned %v, want errClosed", err)
	}
	if len(fb.vps) != 0 || len(fb.deleted) != 1 {
		t.Errorf("%d virtual processors remain, %d deleted", len(fb.vps), len(fb.deleted))
	}
	if fb.partitionOpen {
		t.Error("the partition stays open")
	}
	if len(fb.hosts) != 1 {
		t.Errorf("%d host arenas remain, want only the test arena", len(fb.hosts))
	}
	if err := p.Close(); err != nil {
		t.Errorf("second Close returned %v", err)
	}
	if _, err := p.acquire(newContext(p)); !errors.Is(err, errClosed) {
		t.Errorf("acquire after Close returned %v", err)
	}
}

func TestCloseReportsBackendErrors(t *testing.T) {
	fb := newFakeBackend()
	p, err := newPlatform(fb, Options{})
	if err != nil {
		t.Fatal(err)
	}
	fb.closeErr = errors.New("delete partition boom")
	if err := p.Close(); !errors.Is(err, fb.closeErr) {
		t.Errorf("Close returned %v", err)
	}
}

// requireGuestPageSize skips a test that reads 4KB entries from the shared
// page table package. Under a larger page build tag that package builds
// larger entries, and NewWithOptions refuses the configuration.
func requireGuestPageSize(t *testing.T) {
	t.Helper()
	if hostarch.PageSize != pageSize {
		t.Skipf("the Sentry page size is %d bytes and whpx maps %d-byte pages", hostarch.PageSize, pageSize)
	}
}

func TestCheckPageSizeRejectsOtherSizes(t *testing.T) {
	if err := checkPageSize(pageSize); err != nil {
		t.Fatalf("checkPageSize(%d) = %v, want nil", pageSize, err)
	}
	for _, size := range []int{1024, 16384, 65536} {
		err := checkPageSize(size)
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("checkPageSize(%d) = %v, want ErrUnsupported", size, err)
		}
	}
}
