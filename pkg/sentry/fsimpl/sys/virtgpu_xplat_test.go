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

package sys_test

import (
	"errors"
	"path"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
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

const (
	testDRMMajor    = 226
	testRenderMinor = 128
	testNodeLink    = "/dev/char/226:128"
)

func newVirtGPUSysfsEnv(t *testing.T, idata *sys.InternalData) *sysfsEnv {
	t.Helper()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	ctx := gvcontext.WithValues(gvcontext.Background(), map[any]any{
		kernel.CtxKernel:          &kernel.Kernel{},
		ktime.CtxRealtimeClock:    fixedClock{},
		auth.CtxCredentials:       creds,
		limits.CtxLimits:          limits.NewLimitSet(),
		uniqueid.CtxInotifyCookie: uint32(1),
	})
	v := &vfs.VirtualFilesystem{}
	if err := v.Init(ctx); err != nil {
		t.Fatalf("VirtualFilesystem.Init: %v", err)
	}
	v.MustRegisterFilesystemType(sys.Name, sys.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	opts := &vfs.MountOptions{}
	if idata != nil {
		opts.GetFilesystemOptions.InternalData = idata
	}
	mntns, err := v.NewMountNamespace(ctx, creds, "", sys.Name, opts, nil)
	if err != nil {
		t.Fatalf("NewMountNamespace(sysfs): %v", err)
	}
	e := &sysfsEnv{t: t, ctx: vfs.WithMountNamespace(ctx, mntns), creds: creds, vfs: v, root: mntns.Root(ctx)}
	t.Cleanup(func() {
		e.root.DecRef(ctx)
		mntns.DecRef(ctx)
	})
	return e
}

func virtGPUData() *sys.InternalData {
	return &sys.InternalData{VirtGPU: &sys.VirtGPUSysfs{DevMajor: testDRMMajor, DevMinor: testRenderMinor}}
}

func (e *sysfsEnv) readFile(p string) string {
	e.t.Helper()
	pop := e.pop(p)
	pop.FollowFinalSymlink = true
	fd, err := e.vfs.OpenAt(e.ctx, e.creds, pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		e.t.Fatalf("open %s: %v", p, err)
	}
	defer fd.DecRef(e.ctx)
	buf := make([]byte, 4096)
	n, err := fd.Read(e.ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if err != nil {
		e.t.Fatalf("read %s: %v", p, err)
	}
	return string(buf[:n])
}

func (e *sysfsEnv) readlink(p string) string {
	e.t.Helper()
	target, err := e.vfs.ReadlinkAt(e.ctx, e.creds, e.pop(p))
	if err != nil {
		e.t.Fatalf("readlink %s: %v", p, err)
	}
	return target
}

// realpath resolves every link in p and returns the absolute path of the
// result, as realpath(3) does in the guest.
func (e *sysfsEnv) realpath(p string) string {
	e.t.Helper()
	pop := &vfs.PathOperation{Root: e.root, Start: e.root, Path: fspath.Parse(p), FollowFinalSymlink: true}
	vd, err := e.vfs.GetDentryAt(e.ctx, e.creds, pop, &vfs.GetDentryOptions{})
	if err != nil {
		e.t.Fatalf("resolve %s: %v", p, err)
	}
	defer vd.DecRef(e.ctx)
	name, err := e.vfs.PathnameWithDeleted(e.ctx, e.root, vd)
	if err != nil {
		e.t.Fatalf("pathname of %s: %v", p, err)
	}
	return name
}

func TestVirtGPUSysfsAbsentByDefault(t *testing.T) {
	for _, tc := range []struct {
		name  string
		idata *sys.InternalData
	}{
		{"no internal data", nil},
		{"nil VirtGPU", &sys.InternalData{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newVirtGPUSysfsEnv(t, tc.idata)
			for _, p := range []string{"/class/drm", testNodeLink, "/bus/virtio", "/bus/pci", "/devices/pci0000:00"} {
				if _, err := e.stat(p); !errors.Is(err, linuxerr.ENOENT) {
					t.Errorf("stat %s = %v, want ENOENT", p, err)
				}
			}
			if _, err := e.stat("/dev/char"); err != nil {
				t.Errorf("stat /dev/char: %v", err)
			}
		})
	}
}

func TestVirtGPUSysfsLinks(t *testing.T) {
	e := newVirtGPUSysfsEnv(t, virtGPUData())
	const pciDir = "/devices/pci0000:00/0000:00:01.0"
	const nodeDir = pciDir + "/virtio0/drm/renderD128"
	for _, tc := range []struct{ link, target, resolved string }{
		{pciDir + "/subsystem", "../../../bus/pci", "/bus/pci"},
		{pciDir + "/virtio0/subsystem", "../../../../bus/virtio", "/bus/virtio"},
		{nodeDir + "/device", "../..", pciDir + "/virtio0"},
		{nodeDir + "/subsystem", "../../../../../../class/drm", "/class/drm"},
		{"/bus/pci/devices/0000:00:01.0", "../../../devices/pci0000:00/0000:00:01.0", pciDir},
		{"/bus/virtio/devices/virtio0", "../../../devices/pci0000:00/0000:00:01.0/virtio0", pciDir + "/virtio0"},
		{"/class/drm/renderD128", "../../devices/pci0000:00/0000:00:01.0/virtio0/drm/renderD128", nodeDir},
		{testNodeLink, "../../devices/pci0000:00/0000:00:01.0/virtio0/drm/renderD128", nodeDir},
	} {
		if got := e.readlink(tc.link); got != tc.target {
			t.Errorf("readlink %s = %q, want %q", tc.link, got, tc.target)
		}
		if got := e.realpath(tc.link); got != tc.resolved {
			t.Errorf("realpath %s = %q, want %q", tc.link, got, tc.resolved)
		}
	}
}

// TestVirtGPUSysfsLibdrmWalk reads the tree in the order of libdrm 2.4.12x
// drmGetDevices2 (xf86drm.c: drmNodeIsDRM, drmParseSubsystemType,
// get_pci_path, drmParsePciBusInfo, parse_separate_sysfs_files,
// parse_config_sysfs_file).
func TestVirtGPUSysfsLibdrmWalk(t *testing.T) {
	e := newVirtGPUSysfsEnv(t, virtGPUData())
	dev := testNodeLink + "/device"

	if st, err := e.stat(dev + "/drm"); err != nil || st.Mode&linux.S_IFMT != linux.S_IFDIR {
		t.Fatalf("drmNodeIsDRM: stat %s/drm = (%#o, %v), want a directory", dev, st.Mode, err)
	}
	if got := path.Base(e.readlink(dev + "/subsystem")); got != "virtio" {
		t.Errorf("subsystem of the DRM device = %q, want virtio", got)
	}
	if got := path.Base(e.readlink(dev + "/../subsystem")); got != "pci" {
		t.Errorf("subsystem of the parent device = %q, want pci (Mesa venus refuses a pure virtio bus)", got)
	}
	real := e.realpath(dev)
	if !strings.HasSuffix(real, "/virtio0") {
		t.Fatalf("realpath %s = %q, want a /virtio0 suffix", dev, real)
	}
	pci := strings.TrimSuffix(real, "/virtio0")

	if !strings.Contains(e.readFile(pci+"/uevent"), "\nPCI_SLOT_NAME=0000:00:01.0\n") {
		t.Errorf("uevent has no PCI_SLOT_NAME=0000:00:01.0 line")
	}
	for name, want := range map[string]string{
		"vendor": "0x1af4\n", "device": "0x1050\n", "subsystem_vendor": "0x1af4\n",
		"subsystem_device": "0x1100\n", "revision": "0x01\n", "class": "0x038000\n",
	} {
		if got := e.readFile(pci + "/" + name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	// Offsets of xf86drm.c parse_config_sysfs_file.
	config := []byte(e.readFile(pci + "/config"))
	if len(config) != 64 {
		t.Fatalf("config has %d bytes, want 64", len(config))
	}
	le16 := func(off int) int { return int(config[off]) | int(config[off+1])<<8 }
	if le16(0) != 0x1af4 || le16(2) != 0x1050 || config[8] != 0x01 || le16(44) != 0x1af4 || le16(46) != 0x1100 {
		t.Errorf("config = % x, disagrees with the separate files", config[:48])
	}
	if config[9] != 0x00 || config[10] != 0x80 || config[11] != 0x03 {
		t.Errorf("config class bytes = % x, want 00 80 03", config[9:12])
	}
}

func TestVirtGPUSysfsNodeFiles(t *testing.T) {
	e := newVirtGPUSysfsEnv(t, virtGPUData())
	for p, want := range map[string]string{
		testNodeLink + "/dev":                             "226:128\n",
		testNodeLink + "/uevent":                          "MAJOR=226\nMINOR=128\nDEVNAME=dri/renderD128\nDEVTYPE=drm_minor\n",
		"/class/drm/version":                              "drm 1.1.0 20060810\n",
		"/devices/pci0000:00/0000:00:01.0/virtio0/vendor": "0x1af4\n",
		"/devices/pci0000:00/0000:00:01.0/virtio0/device": "0x0010\n",
		"/devices/pci0000:00/0000:00:01.0/virtio0/uevent": "DRIVER=virtio_gpu\nMODALIAS=virtio:d00000010v00001AF4\n",
		"/devices/pci0000:00/0000:00:01.0/uevent":         "DRIVER=virtio-pci\nPCI_CLASS=38000\nPCI_ID=1AF4:1050\nPCI_SUBSYS_ID=1AF4:1100\nPCI_SLOT_NAME=0000:00:01.0\nMODALIAS=pci:v00001AF4d00001050sv00001AF4sd00001100bc03sc80i00\n",
	} {
		if got := e.readFile(p); got != want {
			t.Errorf("%s = %q, want %q", p, got, want)
		}
	}
	st, err := e.stat("/devices/pci0000:00/0000:00:01.0/config")
	if err != nil || st.Mode&07777 != 0444 {
		t.Errorf("config mode = %#o (%v), want 0444", st.Mode&07777, err)
	}
}

func TestVirtGPUSysfsRejectsZeroDeviceNumbers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		major uint32
		minor uint32
	}{
		{"both zero", 0, 0},
		{"zero major", 0, testRenderMinor},
		{"zero minor", testDRMMajor, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
			ctx := gvcontext.WithValues(gvcontext.Background(), map[any]any{
				kernel.CtxKernel:          &kernel.Kernel{},
				ktime.CtxRealtimeClock:    fixedClock{},
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
					InternalData: &sys.InternalData{
						VirtGPU: &sys.VirtGPUSysfs{DevMajor: tc.major, DevMinor: tc.minor},
					},
				},
			}
			mntns, err := v.NewMountNamespace(ctx, creds, "", sys.Name, opts, nil)
			if err == nil {
				mntns.DecRef(ctx)
				t.Fatalf("NewMountNamespace(sysfs) with %d:%d = nil error, want an error", tc.major, tc.minor)
			}
		})
	}
}
