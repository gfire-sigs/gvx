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

//go:build darwin

package hostfs

import (
	"errors"
	"testing"
)

// fakeFstatfs answers with a file system type for each device and counts the
// calls. The descriptor number names the device in these tests.
type fakeFstatfs struct {
	types map[int]string
	err   error
	calls int
}

func (f *fakeFstatfs) fsType(fd int) (string, error) {
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	return f.types[fd], nil
}

func newFakeTrust(f *fakeFstatfs) *volumeTrust {
	return &volumeTrust{rootDev: 1, fsType: f.fsType, apfs: make(map[uint64]bool)}
}

func TestVolumeTrustSameDeviceNeedsNoFstatfs(t *testing.T) {
	f := &fakeFstatfs{err: errors.New("must not run")}
	v := newFakeTrust(f)
	if !v.trusts(1, -1) {
		t.Fatal("an entry of the root device lost its identity")
	}
	if f.calls != 0 {
		t.Fatalf("the root device made %d fstatfs calls, want 0", f.calls)
	}
}

func TestVolumeTrustOfOtherDevices(t *testing.T) {
	f := &fakeFstatfs{types: map[int]string{10: "apfs", 11: "msdos", 12: "hfs", 13: "nfs"}}
	v := newFakeTrust(f)
	for _, tc := range []struct {
		dev  uint64
		fd   int
		want bool
	}{
		{dev: 2, fd: 10, want: true},
		{dev: 3, fd: 11, want: false},
		{dev: 4, fd: 12, want: false},
		{dev: 5, fd: 13, want: false},
	} {
		if got := v.trusts(tc.dev, tc.fd); got != tc.want {
			t.Errorf("trusts(dev %d, %s) = %v, want %v", tc.dev, f.types[tc.fd], got, tc.want)
		}
	}
}

func TestVolumeTrustAsksOncePerDevice(t *testing.T) {
	f := &fakeFstatfs{types: map[int]string{10: "apfs", 11: "msdos"}}
	v := newFakeTrust(f)
	for range 3 {
		if !v.trusts(2, 10) || v.trusts(3, 11) {
			t.Fatal("the verdict changed between calls")
		}
	}
	if f.calls != 2 {
		t.Fatalf("fstatfs ran %d times for two devices, want 2", f.calls)
	}
	// A cached verdict needs no descriptor.
	if !v.trusts(2, -1) || v.trusts(3, -1) {
		t.Fatal("a call without a descriptor ignored the cached verdict")
	}
	if f.calls != 2 {
		t.Fatalf("a cached verdict made an fstatfs call: %d calls", f.calls)
	}
}

func TestVolumeTrustDistrustsAnFstatfsError(t *testing.T) {
	f := &fakeFstatfs{err: errors.New("EIO")}
	v := newFakeTrust(f)
	if v.trusts(2, 10) {
		t.Fatal("a device whose fstatfs failed kept its identity")
	}
	// The failure leaves no verdict, so a later call that works decides.
	f.err = nil
	f.types = map[int]string{10: "apfs"}
	if !v.trusts(2, 10) {
		t.Fatal("an error stayed as the verdict of the device")
	}
	if got := v.trusts(7, -1); got {
		t.Fatal("a device without a verdict and without a descriptor kept its identity")
	}
}
