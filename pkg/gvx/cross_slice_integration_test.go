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
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/ext4lite"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

func TestCrossSliceMultiSandboxOverlayLockSHAndCompactVolume(t *testing.T) {
	requireCheckpointGuestBackend(t)
	cacheDir := filepath.Join(t.TempDir(), "cache")
	seedBaseExt4Volume(t, cacheDir, "base-vol")

	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	layer, err := testimage.Tar(testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755})
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}

	startCatSandbox := func(mounts []Mount) (*Sandbox, net.Conn, *notifyBuffer, <-chan error) {
		stdinR, stdinW := net.Pipe()
		stdout := newNotifyBuffer()
		var stderr syncBuffer
		cfg := newCheckpointTestConfig(t, cacheDir)
		cfg.OCILayerTars = [][]byte{layer}
		cfg.Mounts = mounts
		cfg.Argv = []string{"/bin/cat", "/mnt/keep.txt", "/proc/self/fd/0"}
		cfg.Stdin = stdinR
		cfg.Stdout = stdout
		cfg.Stderr = &stderr
		sb, nErr := New(context.Background(), cfg)
		if nErr != nil {
			_ = stdinR.Close()
			_ = stdinW.Close()
			t.Fatalf("New: %v", nErr)
		}
		errCh := make(chan error, 1)
		go func() {
			defer func() { _ = stdinR.Close() }()
			code, rErr := sb.Run(context.Background())
			if rErr != nil {
				errCh <- rErr
				return
			}
			if code != 0 {
				errCh <- errors.New("non-zero exit: " + stderr.String())
				return
			}
			errCh <- nil
		}()
		stdout.waitForSubstring(t, "base-keep-v1\n", 15*time.Second)
		return sb, stdinW, stdout, errCh
	}

	// Boot two concurrent sandboxes sharing base-vol via MountOverlay (LOCK_SH).
	sbA, inA, _, errA := startCatSandbox([]Mount{
		{Kind: MountOverlay, VolumeName: "base-vol", UpperVolumeName: "branch-a", GuestPath: "/mnt"},
	})
	defer sbA.Close()
	sbB, inB, _, errB := startCatSandbox([]Mount{
		{Kind: MountOverlay, VolumeName: "base-vol", UpperVolumeName: "branch-b", GuestPath: "/mnt"},
	})
	defer sbB.Close()

	// Both InspectVolume and ext4lite.ProbeVolumeLock must report "shared".
	vi, err := InspectVolume(cacheDir, "base-vol")
	if err != nil {
		t.Fatalf("InspectVolume(base-vol): %v", err)
	}
	if vi.LockMode != "shared" || !vi.InUse {
		t.Fatalf("InspectVolume(base-vol) = (%q, %v), want (\"shared\", true)", vi.LockMode, vi.InUse)
	}
	if mode, pErr := ext4lite.ProbeVolumeLock(vi.Mountpoint); pErr != nil || mode != ext4lite.VolumeLockShared {
		t.Fatalf("ext4lite.ProbeVolumeLock = (%v, %v), want (shared, nil)", mode, pErr)
	}

	// CompactVolume, RemoveVolume, and RW mount on base-vol must fail with ErrVolumeInUse.
	if _, cErr := CompactVolume(cacheDir, "base-vol"); !errors.Is(cErr, ErrVolumeInUse) {
		t.Fatalf("CompactVolume while shared = %v, want ErrVolumeInUse", cErr)
	}
	if rErr := RemoveVolume(cacheDir, "base-vol"); !errors.Is(rErr, ErrVolumeInUse) {
		t.Fatalf("RemoveVolume while shared = %v, want ErrVolumeInUse", rErr)
	}
	rwCfg := newCheckpointTestConfig(t, cacheDir)
	rwCfg.OCILayerTars = [][]byte{layer}
	rwCfg.Mounts = []Mount{{Kind: MountVolume, VolumeName: "base-vol", GuestPath: "/rw", ReadOnly: false}}
	rwCfg.Argv = []string{"/bin/cat", "/rw/keep.txt"}
	if badSB, rwErr := New(context.Background(), rwCfg); !errors.Is(rwErr, ErrVolumeInUse) {
		if badSB != nil {
			_ = badSB.Close()
		}
		t.Fatalf("New(RW on shared base-vol) = %v, want ErrVolumeInUse", rwErr)
	}

	// A 3rd concurrent RO mount succeeds alongside sbA and sbB.
	sbC, inC, _, errC := startCatSandbox([]Mount{
		{Kind: MountVolume, VolumeName: "base-vol", GuestPath: "/mnt", ReadOnly: true},
	})
	defer sbC.Close()

	for _, w := range []net.Conn{inA, inB, inC} {
		_ = w.Close()
	}
	for _, ch := range []<-chan error{errA, errB, errC} {
		if rErr := <-ch; rErr != nil {
			t.Fatalf("concurrent sandbox Run: %v", rErr)
		}
	}
	_ = sbA.Close()
	_ = sbB.Close()
	_ = sbC.Close()

	viAfter, err := InspectVolume(cacheDir, "base-vol")
	if err != nil {
		t.Fatalf("InspectVolume after close: %v", err)
	}
	if viAfter.LockMode != "none" || viAfter.InUse {
		t.Fatalf("InspectVolume after close = (%q, %v), want (\"none\", false)", viAfter.LockMode, viAfter.InUse)
	}

	// Verify CompactVolume invokes ext4lite.Volume.Trim and shrinks interior sparse holes.
	trimVol, err := CreateVolume(cacheDir, "trim-interior", DriverExt4lite)
	if err != nil {
		t.Fatalf("CreateVolume(trim-interior): %v", err)
	}
	tf, err := os.OpenFile(trimVol.Mountpoint, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	extVol, err := ext4lite.OpenVolume(tf, ext4lite.VolumeOptions{})
	if err != nil {
		_ = tf.Close()
		t.Fatalf("OpenVolume(trim-interior): %v", err)
	}
	vfsObj := &vfs.VirtualFilesystem{}
	sctx := gvcontext.Background()
	if err := vfsObj.Init(sctx); err != nil {
		t.Fatal(err)
	}
	if err := registerKernelVFS(vfsObj, nil); err != nil {
		t.Fatal(err)
	}
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	mntns, err := vfsObj.NewMountNamespace(sctx, creds, "", ext4lite.Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: ext4lite.InternalFilesystemOptions{Volume: extVol, UniqueID: "trim-interior"},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sctx = vfs.WithMountNamespace(sctx, mntns)
	root := mntns.Root(sctx)
	payload := bytes.Repeat([]byte{0x5A}, 32<<20)
	if err := vfsWriteFile(sctx, vfsObj, creds, root, "/big.bin", payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := extVol.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := vfsObj.UnlinkAt(sctx, creds, &vfs.PathOperation{Root: root, Start: root, Path: makeFPath("/big.bin")}); err != nil {
		t.Fatal(err)
	}
	root.DecRef(sctx)
	mntns.DecRef(sctx)
	vfsObj.Release(sctx)
	if err := extVol.Close(); err != nil {
		t.Fatal(err)
	}

	compacted, err := CompactVolume(cacheDir, "trim-interior")
	if err != nil {
		t.Fatalf("CompactVolume(trim-interior): %v", err)
	}
	if compacted.AllocatedBytes > 16<<20 {
		t.Fatalf("CompactVolume(trim-interior) AllocatedBytes = %d, want <= 16 MiB", compacted.AllocatedBytes)
	}
}

func TestCrossSliceTwoSandboxesSharedHostfsBareGitRepo(t *testing.T) {
	requireCheckpointGuestBackend(t)
	cacheDir := filepath.Join(t.TempDir(), "cache")
	gitHub := filepath.Join(t.TempDir(), "proj.git")
	for _, sub := range []string{"refs/heads", "objects/info", "hooks", "worktrees"} {
		if err := os.MkdirAll(filepath.Join(gitHub, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(gitHub, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	w1, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/git/proj.git/refs/heads/wt-a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	if err != nil {
		t.Fatal(err)
	}
	w2, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/git/proj.git/refs/heads/wt-b", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n")
	if err != nil {
		t.Fatal(err)
	}
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	layer, err := testimage.Tar(
		testimage.File{Name: "bin/w1", Data: w1, Mode: 0o755},
		testimage.File{Name: "bin/w2", Data: w2, Mode: 0o755},
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
	)
	if err != nil {
		t.Fatal(err)
	}

	runWriter := func(bin string) error {
		cfg := newCheckpointTestConfig(t, cacheDir)
		cfg.OCILayerTars = [][]byte{layer}
		cfg.Mounts = []Mount{{Kind: MountBind, HostPath: gitHub, GuestPath: "/git/proj.git"}}
		cfg.Argv = []string{bin}
		sb, nErr := New(context.Background(), cfg)
		if nErr != nil {
			return nErr
		}
		defer sb.Close()
		code, rErr := sb.Run(context.Background())
		if rErr != nil {
			return rErr
		}
		if code != 0 {
			return errors.New("non-zero guest exit")
		}
		return sb.Close()
	}

	errCh := make(chan error, 2)
	go func() { errCh <- runWriter("/bin/w1") }()
	go func() { errCh <- runWriter("/bin/w2") }()
	for range 2 {
		if rErr := <-errCh; rErr != nil {
			t.Fatalf("concurrent hostfs writer sandbox: %v", rErr)
		}
	}

	// Verify both refs survived and .gvx_meta.lock is invisible to guest cat.
	var out, errBuf bytes.Buffer
	cfg := newCheckpointTestConfig(t, cacheDir)
	cfg.OCILayerTars = [][]byte{layer}
	cfg.Mounts = []Mount{{Kind: MountBind, HostPath: gitHub, GuestPath: "/git/proj.git", ReadOnly: true}}
	cfg.Argv = []string{"/bin/cat", "/git/proj.git/refs/heads/wt-a", "/git/proj.git/refs/heads/wt-b"}
	cfg.Stdout = &out
	cfg.Stderr = &errBuf
	sbRead, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	code, rErr := sbRead.Run(context.Background())
	_ = sbRead.Close()
	if rErr != nil || code != 0 {
		t.Fatalf("read sandbox = (%d, %v) stderr=%q", code, rErr, errBuf.String())
	}
	want := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
	if out.String() != want {
		t.Fatalf("read sandbox stdout = %q, want %q", out.String(), want)
	}

	// Guest attempting to open .gvx_meta or .gvx_meta.lock must fail (ENOENT).
	var errMeta bytes.Buffer
	cfgMeta := newCheckpointTestConfig(t, cacheDir)
	cfgMeta.OCILayerTars = [][]byte{layer}
	cfgMeta.Mounts = []Mount{{Kind: MountBind, HostPath: gitHub, GuestPath: "/git/proj.git", ReadOnly: true}}
	cfgMeta.Argv = []string{"/bin/cat", "/git/proj.git/.gvx_meta.lock"}
	cfgMeta.Stderr = &errMeta
	sbMeta, err := New(context.Background(), cfgMeta)
	if err != nil {
		t.Fatal(err)
	}
	metaCode, _ := sbMeta.Run(context.Background())
	_ = sbMeta.Close()
	if metaCode == 0 {
		t.Fatal("guest reading /git/proj.git/.gvx_meta.lock unexpectedly succeeded")
	}
}
