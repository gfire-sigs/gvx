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

package virtgpu

import (
	"encoding/binary"
	"path"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/sys"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/ktime"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/uniqueid"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

type fixedSysfsClock struct{ ktime.Clock }

func (fixedSysfsClock) Now() ktime.Time { return ktime.FromNanoseconds(1) }

func TestSysfsTopologyLibdrmDiscovery(t *testing.T) {
	topo, err := SysfsTopology()
	if err != nil {
		t.Fatalf("SysfsTopology: %v", err)
	}
	if err := sys.ValidateTopologyAdditions([]sys.TopologyAddition{topo}); err != nil {
		t.Fatalf("ValidateTopologyAdditions: %v", err)
	}

	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	ctx := gvcontext.WithValues(gvcontext.Background(), map[any]any{
		kernel.CtxKernel:          &kernel.Kernel{},
		ktime.CtxRealtimeClock:    fixedSysfsClock{},
		auth.CtxCredentials:       creds,
		limits.CtxLimits:          limits.NewLimitSet(),
		uniqueid.CtxInotifyCookie: uint32(1),
	})
	v := &vfs.VirtualFilesystem{}
	if err := v.Init(ctx); err != nil {
		t.Fatalf("VirtualFilesystem.Init: %v", err)
	}
	v.MustRegisterFilesystemType(sys.Name, sys.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	opts := &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: &sys.InternalData{Topologies: []sys.TopologyAddition{topo}},
		},
	}
	mntns, err := v.NewMountNamespace(ctx, creds, "", sys.Name, opts, nil)
	if err != nil {
		t.Fatalf("NewMountNamespace(sysfs): %v", err)
	}
	root := mntns.Root(ctx)
	ctx = vfs.WithMountNamespace(ctx, mntns)
	defer func() {
		root.DecRef(ctx)
		mntns.DecRef(ctx)
	}()

	readFile := func(p string) string {
		t.Helper()
		pop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(p), FollowFinalSymlink: true}
		fd, err := v.OpenAt(ctx, creds, pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
		if err != nil {
			t.Fatalf("open %s: %v", p, err)
		}
		defer fd.DecRef(ctx)
		buf := make([]byte, 4096)
		n, err := fd.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		return string(buf[:n])
	}
	realpath := func(p string) string {
		t.Helper()
		pop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(p), FollowFinalSymlink: true}
		vd, err := v.GetDentryAt(ctx, creds, pop, &vfs.GetDentryOptions{})
		if err != nil {
			t.Fatalf("resolve %s: %v", p, err)
		}
		defer vd.DecRef(ctx)
		name, err := v.PathnameWithDeleted(ctx, root, vd)
		if err != nil {
			t.Fatalf("pathname %s: %v", p, err)
		}
		return name
	}

	// Trace libdrm's exact discovery walk starting at /sys/dev/char/226:128.
	node := "/dev/char/226:128"
	if got := readFile(node + "/dev"); got != "226:128\n" {
		t.Fatalf("dev = %q, want 226:128\\n", got)
	}
	if got := realpath(node + "/subsystem"); got != "/class/drm" {
		t.Fatalf("node subsystem = %q, want /class/drm", got)
	}
	if got := readFile("/class/drm/version"); got != drmClassVersion {
		t.Fatalf("drm version = %q, want %q", got, drmClassVersion)
	}
	virtioDev := realpath(node + "/device")
	if virtioDev != "/devices/pci0000:00/0000:00:01.0/virtio0" {
		t.Fatalf("node/device = %q", virtioDev)
	}
	if got := realpath(virtioDev + "/subsystem"); got != "/bus/virtio" {
		t.Fatalf("virtio subsystem = %q, want /bus/virtio", got)
	}
	if got := realpath("/bus/virtio/devices/virtio0"); got != virtioDev {
		t.Fatalf("/bus/virtio/devices/virtio0 = %q, want %q", got, virtioDev)
	}
	pciDev := path.Dir(virtioDev)
	if got := realpath(pciDev + "/subsystem"); got != "/bus/pci" {
		t.Fatalf("pci subsystem = %q, want /bus/pci", got)
	}
	if got := realpath("/bus/pci/devices/0000:00:01.0"); got != pciDev {
		t.Fatalf("/bus/pci/devices/0000:00:01.0 = %q, want %q", got, pciDev)
	}
	if got := readFile(pciDev + "/vendor"); got != "0x1af4\n" {
		t.Fatalf("pci vendor = %q, want 0x1af4\\n", got)
	}
	if got := readFile(pciDev + "/device"); got != "0x1050\n" {
		t.Fatalf("pci device = %q, want 0x1050\\n", got)
	}
	if got := readFile(pciDev + "/revision"); got != "0x01\n" {
		t.Fatalf("pci revision = %q, want 0x01\\n", got)
	}
	cfg := []byte(readFile(pciDev + "/config"))
	if len(cfg) != 64 || binary.LittleEndian.Uint16(cfg[0:2]) != 0x1af4 || binary.LittleEndian.Uint16(cfg[2:4]) != 0x1050 || cfg[8] != 0x01 {
		t.Fatalf("unexpected 64-byte PCI config header (len=%d)", len(cfg))
	}
	if got := readFile(node + "/uevent"); !strings.Contains(got, "DEVNAME=dri/renderD128") || !strings.Contains(got, "DEVTYPE=drm_minor") {
		t.Fatalf("node uevent = %q", got)
	}
}
