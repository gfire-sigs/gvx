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

package gvx

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/ext4lite"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/tmpfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/ktime"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// TestCustomVFSSecurityParityWithTmpfs checks that custom gvx filesystems
// (hostfs and ext4lite) match upstream tmpfs on security-sensitive VFS options:
// RawCapability in GetXattrOptions, trusted.* xattr namespace isolation,
// ClearPrivs SUID/SGID stripping, and read-only mount write rejection.
func TestCustomVFSSecurityParityWithTmpfs(t *testing.T) {
	t.Parallel()

	type fsHarness struct {
		vfsObj     *vfs.VirtualFilesystem
		mntns      *vfs.MountNamespace
		root       vfs.VirtualDentry
		rootCreds  *auth.Credentials
		userCreds  *auth.Credentials
		childCreds *auth.Credentials
		sctx       gvcontext.Context
		cleanup    func()
	}

	newHarness := func(t *testing.T, kind string, readOnly bool) *fsHarness {
		t.Helper()
		mf := newTestMemoryFile(t, "vfs-parity-"+kind)
		clock := &ktime.SyntheticClock{}
		clock.Store(ktime.FromNanoseconds(1_700_000_000_000_000_000))
		rootNS := auth.NewRootUserNamespace()
		rootCreds := auth.NewRootCredentials(rootNS)
		userCreds := auth.NewUserCredentials(1000, 1000, nil, nil, rootNS)
		sctx := newTestSentryContext(t, mf, clock, rootCreds)

		childNS, err := rootCreds.NewChildUserNamespace()
		if err != nil {
			t.Fatalf("NewChildUserNamespace: %v", err)
		}
		if err := childNS.SetUIDMap(sctx, []auth.IDMapEntry{
			{FirstID: 0, FirstParentID: 1000, Length: 100},
		}); err != nil {
			t.Fatalf("SetUIDMap: %v", err)
		}
		childCreds := auth.NewRootCredentials(childNS)

		vfsObj := &vfs.VirtualFilesystem{}
		if err := vfsObj.Init(sctx); err != nil {
			t.Fatalf("vfs.Init: %v", err)
		}

		mopts := &vfs.MountOptions{ReadOnly: readOnly}
		var closeExtra func()
		var fsName string
		switch kind {
		case "tmpfs":
			fsName = tmpfs.Name
			vfsObj.MustRegisterFilesystemType(tmpfs.Name, tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
		case "hostfs":
			fsName = hostfs.Name
			ws, err := hostfs.OpenWorkspace(t.TempDir(), false)
			if err != nil {
				vfsObj.Release(sctx)
				t.Fatalf("OpenWorkspace: %v", err)
			}
			closeExtra = func() { _ = ws.Close() }
			vfsObj.MustRegisterFilesystemType(hostfs.Name, hostfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
			mopts.GetFilesystemOptions.InternalData = hostfs.InternalFilesystemOptions{Workspace: ws}
		case "ext4lite":
			fsName = ext4lite.Name
			imgPath := filepath.Join(t.TempDir(), "parity.ext4")
			f, err := os.OpenFile(imgPath, os.O_RDWR|os.O_CREATE, 0o600)
			if err != nil {
				vfsObj.Release(sctx)
				t.Fatalf("OpenFile(%s): %v", imgPath, err)
			}
			vol, err := ext4lite.OpenVolume(f, ext4lite.VolumeOptions{})
			if err != nil {
				_ = f.Close()
				vfsObj.Release(sctx)
				t.Fatalf("OpenVolume: %v", err)
			}
			closeExtra = func() { _ = vol.Close() }
			vfsObj.MustRegisterFilesystemType(ext4lite.Name, ext4lite.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
			mopts.GetFilesystemOptions.InternalData = ext4lite.InternalFilesystemOptions{Volume: vol}
		default:
			t.Fatalf("unknown kind %q", kind)
		}

		mntns, err := vfsObj.NewMountNamespace(sctx, rootCreds, "", fsName, mopts, nil)
		if err != nil {
			if closeExtra != nil {
				closeExtra()
			}
			vfsObj.Release(sctx)
			t.Fatalf("NewMountNamespace(%s): %v", kind, err)
		}
		root := mntns.Root(sctx)
		return &fsHarness{
			vfsObj:     vfsObj,
			mntns:      mntns,
			root:       root,
			rootCreds:  rootCreds,
			userCreds:  userCreds,
			childCreds: childCreds,
			sctx:       sctx,
			cleanup: func() {
				root.DecRef(sctx)
				mntns.DecRef(sctx)
				vfsObj.Release(sctx)
				if closeExtra != nil {
					closeExtra()
				}
			},
		}
	}

	type parityOutcome struct {
		rawCapFalseErr error
		rawCapTrueVal  string
		rootList       []string
		userList       []string
		userGetTrusted error
		userSetTrusted error
		modeAfterClear uint16
		roCreateErr    error
	}

	runContract := func(t *testing.T, kind string) parityOutcome {
		t.Helper()
		h := newHarness(t, kind, false)
		defer h.cleanup()

		// Create target file owned by uid/gid 1000 with SUID|SGID|0755.
		pop := &vfs.PathOperation{
			Root:  h.root,
			Start: h.root,
			Path:  fspath.Parse("probe"),
		}
		fd, err := h.vfsObj.OpenAt(h.sctx, h.rootCreds, pop, &vfs.OpenOptions{
			Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
			Mode:  0o755,
		})
		if err != nil {
			t.Fatalf("%s: create probe: %v", kind, err)
		}
		fd.DecRef(h.sctx)

		if err := h.vfsObj.SetStatAt(h.sctx, h.rootCreds, pop, &vfs.SetStatOptions{
			Stat: linux.Statx{
				Mask: linux.STATX_UID | linux.STATX_GID | linux.STATX_MODE,
				UID:  1000,
				GID:  1000,
				Mode: linux.S_ISUID | linux.S_ISGID | 0o755,
			},
		}); err != nil {
			t.Fatalf("%s: chown/chmod probe: %v", kind, err)
		}

		// Store user.*, trusted.*, and a v3 security.capability with RootID 5000.
		if err := h.vfsObj.SetXattrAt(h.sctx, h.rootCreds, pop, &vfs.SetXattrOptions{
			Name:  "user.public",
			Value: "hello",
		}); err != nil {
			t.Fatalf("%s: set user.public: %v", kind, err)
		}
		if err := h.vfsObj.SetXattrAt(h.sctx, h.rootCreds, pop, &vfs.SetXattrOptions{
			Name:  "trusted.secret",
			Value: "hidden",
		}); err != nil {
			t.Fatalf("%s: set trusted.secret: %v", kind, err)
		}

		capData := linux.VfsNsCapData{
			VfsCapData: linux.VfsCapData{
				MagicEtc:    linux.VFS_CAP_REVISION_3 | linux.VFS_CAP_FLAGS_EFFECTIVE,
				PermittedLo: 1 << linux.CAP_NET_BIND_SERVICE,
			},
			RootID: 5000,
		}
		rawCap := capData.ToString()
		if err := h.vfsObj.SetXattrAt(h.sctx, h.rootCreds, pop, &vfs.SetXattrOptions{
			Name:  linux.XATTR_SECURITY_CAPABILITY,
			Value: rawCap,
		}); err != nil {
			t.Fatalf("%s: set security.capability: %v", kind, err)
		}

		var out parityOutcome
		_, out.rawCapFalseErr = h.vfsObj.GetXattrAt(h.sctx, h.childCreds, pop, &vfs.GetXattrOptions{
			Name: linux.XATTR_SECURITY_CAPABILITY,
		})
		out.rawCapTrueVal, err = h.vfsObj.GetXattrAt(h.sctx, h.childCreds, pop, &vfs.GetXattrOptions{
			Name:          linux.XATTR_SECURITY_CAPABILITY,
			RawCapability: true,
		})
		if err != nil {
			t.Fatalf("%s: GetXattrAt(RawCapability=true): %v", kind, err)
		}
		if out.rawCapTrueVal != rawCap {
			t.Fatalf("%s: GetXattrAt(RawCapability=true) = %x, want %x", kind, out.rawCapTrueVal, rawCap)
		}

		out.rootList, err = h.vfsObj.ListXattrAt(h.sctx, h.rootCreds, pop, 0)
		if err != nil {
			t.Fatalf("%s: root ListXattrAt: %v", kind, err)
		}
		slices.Sort(out.rootList)

		out.userList, err = h.vfsObj.ListXattrAt(h.sctx, h.userCreds, pop, 0)
		if err != nil {
			t.Fatalf("%s: user ListXattrAt: %v", kind, err)
		}
		slices.Sort(out.userList)

		_, out.userGetTrusted = h.vfsObj.GetXattrAt(h.sctx, h.userCreds, pop, &vfs.GetXattrOptions{
			Name: "trusted.secret",
		})
		out.userSetTrusted = h.vfsObj.SetXattrAt(h.sctx, h.userCreds, pop, &vfs.SetXattrOptions{
			Name:  "trusted.other",
			Value: "x",
		})

		// ClearPrivs via SetStatAt as unprivileged owner must clear SUID and SGID.
		if err := h.vfsObj.SetStatAt(h.sctx, h.userCreds, pop, &vfs.SetStatOptions{
			Stat:       linux.Statx{Mask: linux.STATX_SIZE, Size: 0},
			ClearPrivs: true,
		}); err != nil {
			t.Fatalf("%s: SetStatAt(ClearPrivs=true): %v", kind, err)
		}
		st, err := h.vfsObj.StatAt(h.sctx, h.rootCreds, pop, &vfs.StatOptions{Mask: linux.STATX_MODE})
		if err != nil {
			t.Fatalf("%s: StatAt: %v", kind, err)
		}
		out.modeAfterClear = st.Mode & 0o7777

		// Read-only mount rejects file creation with EROFS.
		ro := newHarness(t, kind, true)
		defer ro.cleanup()
		roPop := &vfs.PathOperation{
			Root:  ro.root,
			Start: ro.root,
			Path:  fspath.Parse("denied"),
		}
		roFD, roErr := ro.vfsObj.OpenAt(ro.sctx, ro.rootCreds, roPop, &vfs.OpenOptions{
			Flags: linux.O_WRONLY | linux.O_CREAT,
			Mode:  0o644,
		})
		if roFD != nil {
			roFD.DecRef(ro.sctx)
		}
		out.roCreateErr = roErr
		return out
	}

	oracle := runContract(t, "tmpfs")
	if !linuxerr.Equals(linuxerr.EOVERFLOW, oracle.rawCapFalseErr) {
		t.Fatalf("tmpfs oracle RawCapability=false = %v, want EOVERFLOW", oracle.rawCapFalseErr)
	}
	if oracle.modeAfterClear != 0o755 {
		t.Fatalf("tmpfs oracle modeAfterClear = %#o, want 0755", oracle.modeAfterClear)
	}
	if !linuxerr.Equals(linuxerr.EROFS, oracle.roCreateErr) {
		t.Fatalf("tmpfs oracle read-only create = %v, want EROFS", oracle.roCreateErr)
	}

	for _, kind := range []string{"hostfs", "ext4lite"} {
		t.Run(kind, func(t *testing.T) {
			got := runContract(t, kind)
			if !errors.Is(got.rawCapFalseErr, oracle.rawCapFalseErr) {
				t.Errorf("RawCapability=false err = %v, tmpfs oracle = %v", got.rawCapFalseErr, oracle.rawCapFalseErr)
			}
			if got.rawCapTrueVal != oracle.rawCapTrueVal {
				t.Errorf("RawCapability=true payload mismatch with tmpfs oracle")
			}
			if !slices.Equal(got.rootList, oracle.rootList) {
				t.Errorf("root ListXattrAt = %v, tmpfs oracle = %v", got.rootList, oracle.rootList)
			}
			if !slices.Equal(got.userList, oracle.userList) {
				t.Errorf("user ListXattrAt = %v, tmpfs oracle = %v", got.userList, oracle.userList)
			}
			if !errors.Is(got.userGetTrusted, oracle.userGetTrusted) {
				t.Errorf("user GetXattrAt(trusted.*) = %v, tmpfs oracle = %v", got.userGetTrusted, oracle.userGetTrusted)
			}
			if !errors.Is(got.userSetTrusted, oracle.userSetTrusted) {
				t.Errorf("user SetXattrAt(trusted.*) = %v, tmpfs oracle = %v", got.userSetTrusted, oracle.userSetTrusted)
			}
			if got.modeAfterClear != oracle.modeAfterClear {
				t.Errorf("ClearPrivs mode = %#o, tmpfs oracle = %#o", got.modeAfterClear, oracle.modeAfterClear)
			}
			if !errors.Is(got.roCreateErr, oracle.roCreateErr) {
				t.Errorf("read-only create err = %v, tmpfs oracle = %v", got.roCreateErr, oracle.roCreateErr)
			}
		})
	}
}
