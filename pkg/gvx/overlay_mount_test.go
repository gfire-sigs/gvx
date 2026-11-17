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
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/ext4lite"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/ktime"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

func seedBaseExt4Volume(t *testing.T, cacheDir, name string) (imgPath string, digest [32]byte) {
	t.Helper()
	vi, err := CreateVolume(cacheDir, name, DriverExt4lite)
	if err != nil {
		t.Fatalf("CreateVolume(%s): %v", name, err)
	}
	f, err := os.OpenFile(vi.Mountpoint, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	vol, err := ext4lite.OpenVolume(f, ext4lite.VolumeOptions{ReadOnly: false})
	if err != nil {
		_ = f.Close()
		t.Fatalf("OpenVolume(%s): %v", name, err)
	}

	vfsObj := &vfs.VirtualFilesystem{}
	sctx := gvcontext.Background()
	if err := vfsObj.Init(sctx); err != nil {
		_ = vol.Close()
		t.Fatalf("vfs.Init: %v", err)
	}
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	fs, rootDentry, err := ext4lite.FilesystemType{}.GetFilesystem(sctx, vfsObj, creds, "", vfs.GetFilesystemOptions{
		InternalData: ext4lite.InternalFilesystemOptions{Volume: vol, UniqueID: "seed"},
	})
	if err != nil {
		_ = vol.Close()
		t.Fatalf("GetFilesystem: %v", err)
	}
	mnt := vfsObj.NewDisconnectedMount(fs, rootDentry, &vfs.MountOptions{})
	fs.DecRef(sctx)
	root := vfs.MakeVirtualDentry(mnt, rootDentry)

	mustWrite := func(p, body string, mode linux.FileMode) {
		if wErr := vfsWriteFile(sctx, vfsObj, creds, root, p, []byte(body), mode); wErr != nil {
			t.Fatalf("write %s: %v", p, wErr)
		}
		pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(p)}
		if sErr := vfsObj.SetStatAt(sctx, creds, &pop, &vfs.SetStatOptions{
			Stat: linux.Statx{Mask: linux.STATX_MODE, Mode: uint16(mode)},
		}); sErr != nil {
			t.Fatalf("chmod %s: %v", p, sErr)
		}
	}

	mustWrite("/keep.txt", "base-keep-v1\n", 0o640)
	mustWrite("/mutate.txt", "base-mutate-v1\n", 0o644)
	mustWrite("/delete-me.txt", "base-delete-v1\n", 0o600)
	mustWrite("/dir/nested.txt", "nested-v1\n", 0o644)
	mustWrite("/hard1.txt", "shared-hardlink-v1\n", 0o644)
	mustWrite("/bin/run.sh", "#!/bin/cat\nscript-ran-from-overlay\n", 0o755)

	oldPop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath("/hard1.txt")}
	newPop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath("/hard2.txt")}
	if err := vfsObj.LinkAt(sctx, creds, &oldPop, &newPop); err != nil {
		root.DecRef(sctx)
		_ = vol.Close()
		t.Fatalf("LinkAt: %v", err)
	}
	symPop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath("/sym.txt")}
	if err := vfsObj.SymlinkAt(sctx, creds, &symPop, "keep.txt"); err != nil {
		root.DecRef(sctx)
		_ = vol.Close()
		t.Fatalf("SymlinkAt: %v", err)
	}

	root.DecRef(sctx)
	vfsObj.Release(sctx)
	if err := vol.Close(); err != nil {
		t.Fatalf("vol.Close: %v", err)
	}
	assertExt4SuperblockClean(t, vi.Mountpoint)

	raw, err := os.ReadFile(vi.Mountpoint)
	if err != nil {
		t.Fatal(err)
	}
	return vi.Mountpoint, sha256.Sum256(raw)
}

func vfsReadAll(t *testing.T, sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, guestPath string) string {
	t.Helper()
	pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(guestPath), FollowFinalSymlink: true}
	fd, err := vfsObj.OpenAt(sctx, creds, &pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("OpenAt(%s): %v", guestPath, err)
	}
	defer fd.DecRef(sctx)
	buf := make([]byte, 4096)
	n, err := fd.Read(sctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if err != nil && n == 0 {
		t.Fatalf("Read(%s): %v", guestPath, err)
	}
	return string(buf[:n])
}

func TestOverlayMountVFS2BranchIsolationWhiteoutsLinksAndPersistence(t *testing.T) {
	// Property: MountOverlay mounts a lower ext4lite volume read-only beneath either a persistent
	// ext4lite upper volume (/upper + cleaned /work) or an ephemeral tmpfs upper layer, isolating
	// mutations, whiteouts, symlink/hardlink copy-ups, and permissions per branch without mutating
	// the lower base image, and persisting branch-a across restarts.
	cacheDir := filepath.Join(t.TempDir(), "cache")
	baseImg, baseDigest := seedBaseExt4Volume(t, cacheDir, "base-vol")

	withMountedVFS := func(mounts []Mount, fn func(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry)) {
		t.Helper()
		cfg := Config{
			OCICacheDir: cacheDir,
			Mounts:      mounts,
		}
		if err := cfg.normalizeWithMode(true); err != nil {
			t.Fatalf("normalizeWithMode: %v", err)
		}
		sb := &Sandbox{cfg: cfg}
		if err := sb.openMounts(); err != nil {
			t.Fatalf("openMounts: %v", err)
		}
		defer func() {
			if cErr := sb.closeMounts(); cErr != nil {
				t.Fatalf("closeMounts: %v", cErr)
			}
		}()

		mf := newTestMemoryFile(t, "overlay-vfs-test")
		sb.memFile = mf
		sb.attachChunkMemory()

		clock := &ktime.SyntheticClock{}
		clock.Store(ktime.FromNanoseconds(1_700_000_000_000_000_000))
		creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
		sctx := newTestSentryContext(t, mf, clock, creds)
		vfsObj := &vfs.VirtualFilesystem{}
		if err := vfsObj.Init(sctx); err != nil {
			t.Fatalf("vfs.Init: %v", err)
		}
		if err := registerKernelVFS(vfsObj, nil); err != nil {
			t.Fatalf("registerKernelVFS: %v", err)
		}
		mntns, err := vfsObj.NewMountNamespace(sctx, creds, "", "tmpfs", &vfs.MountOptions{}, nil)
		if err != nil {
			t.Fatalf("NewMountNamespace: %v", err)
		}
		sctx = vfs.WithMountNamespace(sctx, mntns)
		nsRoot := mntns.Root(sctx)
		mountSubfs := func(target, fsName string, opts *vfs.MountOptions) error {
			pop := vfs.PathOperation{Root: nsRoot, Start: nsRoot, Path: makeFPath(target)}
			_, mErr := vfsObj.MountAt(sctx, creds, "", &pop, fsName, opts)
			return mErr
		}
		sharedRO := make(map[*ext4lite.Volume]sharedExt4FS)
		for _, m := range sb.mounts {
			if err := sb.mountUserMount(sctx, vfsObj, creds, nsRoot, m, mountSubfs, sharedRO); err != nil {
				releaseSharedExt4FS(sctx, sharedRO)
				nsRoot.DecRef(sctx)
				mntns.DecRef(sctx)
				vfsObj.Release(sctx)
				t.Fatalf("mountUserMount(%s): %v", m.GuestPath, err)
			}
		}
		releaseSharedExt4FS(sctx, sharedRO)
		fn(sctx, vfsObj, creds, nsRoot)
		nsRoot.DecRef(sctx)
		mntns.DecRef(sctx)
		vfsObj.Release(sctx)
	}

	// Boot Sandbox A (persistent upper=branch-a).
	withMountedVFS([]Mount{
		{Kind: MountOverlay, VolumeName: "base-vol", UpperVolumeName: "branch-a", GuestPath: "/data"},
	}, func(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry) {
		if got := vfsReadAll(t, sctx, vfsObj, creds, root, "/data/keep.txt"); got != "base-keep-v1\n" {
			t.Fatalf("branch-a keep.txt = %q", got)
		}
		if got := vfsReadAll(t, sctx, vfsObj, creds, root, "/data/sym.txt"); got != "base-keep-v1\n" {
			t.Fatalf("branch-a sym.txt = %q", got)
		}
		popKeep := vfs.PathOperation{Root: root, Start: root, Path: makeFPath("/data/keep.txt")}
		stKeep, err := vfsObj.StatAt(sctx, creds, &popKeep, &vfs.StatOptions{Mask: linux.STATX_MODE})
		if err != nil || stKeep.Mode&0o777 != 0o640 {
			t.Fatalf("branch-a keep.txt mode = %#o, err = %v; want 0640", stKeep.Mode&0o777, err)
		}

		// Mutate regular file, delete base file (whiteout), break hardlink via copy-up, replace symlink, add new file.
		if err := vfsWriteFile(sctx, vfsObj, creds, root, "/data/mutate.txt", []byte("branch-a-mutated\n"), 0o644); err != nil {
			t.Fatalf("write mutate.txt: %v", err)
		}
		delPop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath("/data/delete-me.txt")}
		if err := vfsObj.UnlinkAt(sctx, creds, &delPop); err != nil {
			t.Fatalf("unlink delete-me.txt: %v", err)
		}
		if err := vfsWriteFile(sctx, vfsObj, creds, root, "/data/hard1.txt", []byte("branch-a-hard1\n"), 0o644); err != nil {
			t.Fatalf("write hard1.txt: %v", err)
		}
		if got := vfsReadAll(t, sctx, vfsObj, creds, root, "/data/hard2.txt"); got != "shared-hardlink-v1\n" {
			t.Fatalf("hard2.txt after hard1 overwrite = %q, want shared-hardlink-v1", got)
		}
		symPop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath("/data/sym.txt")}
		if err := vfsObj.UnlinkAt(sctx, creds, &symPop); err != nil {
			t.Fatalf("unlink sym.txt: %v", err)
		}
		if err := vfsObj.SymlinkAt(sctx, creds, &symPop, "mutate.txt"); err != nil {
			t.Fatalf("recreate sym.txt: %v", err)
		}
		if err := vfsWriteFile(sctx, vfsObj, creds, root, "/data/only-a.txt", []byte("from-a\n"), 0o600); err != nil {
			t.Fatalf("write only-a.txt: %v", err)
		}
	})

	// Boot Sandbox B (persistent upper=branch-b) AND Sandbox C (ephemeral tmpfs upper) simultaneously in one VFS check, or sequentially:
	// Verify zero leakage from branch-a!
	withMountedVFS([]Mount{
		{Kind: MountOverlay, VolumeName: "base-vol", UpperVolumeName: "branch-b", GuestPath: "/b"},
		{Kind: MountOverlay, VolumeName: "base-vol", GuestPath: "/c", TmpfsSizeBytes: 16 << 20},
		{Kind: MountVolume, VolumeName: "base-vol", GuestPath: "/ro", ReadOnly: true},
	}, func(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry) {
		for _, prefix := range []string{"/b", "/c", "/ro"} {
			if got := vfsReadAll(t, sctx, vfsObj, creds, root, prefix+"/mutate.txt"); got != "base-mutate-v1\n" {
				t.Fatalf("%s/mutate.txt = %q, want original base-mutate-v1", prefix, got)
			}
			if got := vfsReadAll(t, sctx, vfsObj, creds, root, prefix+"/delete-me.txt"); got != "base-delete-v1\n" {
				t.Fatalf("%s/delete-me.txt = %q, want original base-delete-v1", prefix, got)
			}
			onlyAPop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(prefix + "/only-a.txt")}
			if _, err := vfsObj.StatAt(sctx, creds, &onlyAPop, &vfs.StatOptions{}); !linuxerr.Equals(linuxerr.ENOENT, err) {
				t.Fatalf("StatAt(%s/only-a.txt) = %v, want ENOENT", prefix, err)
			}
		}
		// Write to /b and /c; verify /ro rejects writes with EROFS.
		if err := vfsWriteFile(sctx, vfsObj, creds, root, "/b/only-b.txt", []byte("from-b\n"), 0o644); err != nil {
			t.Fatalf("write /b/only-b.txt: %v", err)
		}
		if err := vfsWriteFile(sctx, vfsObj, creds, root, "/c/only-c.txt", []byte("from-c\n"), 0o644); err != nil {
			t.Fatalf("write /c/only-c.txt: %v", err)
		}
		if err := vfsWriteFile(sctx, vfsObj, creds, root, "/ro/forbid.txt", []byte("no"), 0o644); !linuxerr.Equals(linuxerr.EROFS, err) {
			t.Fatalf("write to /ro = %v, want EROFS", err)
		}
	})

	// Restart Sandbox A (upper=branch-a) and Sandbox C (ephemeral tmpfs upper):
	// branch-a MUST retain mutations + whiteouts + updated symlink, while Sandbox C resets clean!
	withMountedVFS([]Mount{
		{Kind: MountOverlay, VolumeName: "base-vol", UpperVolumeName: "branch-a", GuestPath: "/a"},
		{Kind: MountOverlay, VolumeName: "base-vol", GuestPath: "/c", TmpfsSizeBytes: 16 << 20},
	}, func(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry) {
		if got := vfsReadAll(t, sctx, vfsObj, creds, root, "/a/mutate.txt"); got != "branch-a-mutated\n" {
			t.Fatalf("restarted branch-a mutate.txt = %q", got)
		}
		if got := vfsReadAll(t, sctx, vfsObj, creds, root, "/a/sym.txt"); got != "branch-a-mutated\n" {
			t.Fatalf("restarted branch-a sym.txt -> mutate.txt = %q", got)
		}
		if got := vfsReadAll(t, sctx, vfsObj, creds, root, "/a/only-a.txt"); got != "from-a\n" {
			t.Fatalf("restarted branch-a only-a.txt = %q", got)
		}
		delPop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath("/a/delete-me.txt")}
		if _, err := vfsObj.StatAt(sctx, creds, &delPop, &vfs.StatOptions{}); !linuxerr.Equals(linuxerr.ENOENT, err) {
			t.Fatalf("restarted branch-a delete-me.txt err = %v, want ENOENT whiteout preserved", err)
		}
		onlyCPop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath("/c/only-c.txt")}
		if _, err := vfsObj.StatAt(sctx, creds, &onlyCPop, &vfs.StatOptions{}); !linuxerr.Equals(linuxerr.ENOENT, err) {
			t.Fatalf("restarted ephemeral /c/only-c.txt err = %v, want ENOENT", err)
		}
	})

	// Verify base-vol on disk is 100% byte-for-byte identical to before all overlay mounts!
	rawAfter, err := os.ReadFile(baseImg)
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest := sha256.Sum256(rawAfter); gotDigest != baseDigest {
		t.Fatalf("base-vol.ext4 was mutated on disk: sha256 %x != original %x", gotDigest, baseDigest)
	}
}

func TestOverlayMountSandboxExecScriptAndCheckpointRestore(t *testing.T) {
	// Property: Real guest execution can run executable scripts from a MountOverlay, and
	// Sandbox.Checkpoint + Restore preserves both persistent ext4lite-upper and ephemeral
	// tmpfs-upper MountOverlay mounts (including shared base-vol in the same sandbox) without
	// mutating base-vol.
	requireCheckpointGuestBackend(t)
	cacheDir := filepath.Join(t.TempDir(), "cache")
	baseImg, baseDigest := seedBaseExt4Volume(t, cacheDir, "base-vol")

	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	writeBranchELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/mnt/persist/branch-note.txt", "persisted-in-branch\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64(branch): %v", err)
	}
	writeScratchELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/mnt/scratch/scratch-note.txt", "ephemeral-in-tmpfs\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64(scratch): %v", err)
	}
	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "bin/write-branch", Data: writeBranchELF, Mode: 0o755},
		testimage.File{Name: "bin/write-scratch", Data: writeScratchELF, Mode: 0o755},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}

	mounts := []Mount{
		{Kind: MountOverlay, VolumeName: "base-vol", UpperVolumeName: "branch-ckpt", GuestPath: "/mnt/persist"},
		{Kind: MountOverlay, VolumeName: "base-vol", GuestPath: "/mnt/scratch", TmpfsSizeBytes: 16 << 20},
		{Kind: MountVolume, VolumeName: "base-vol", GuestPath: "/mnt/ro", ReadOnly: true},
	}

	// Step 1: Execute the shebang script directly from /mnt/persist/bin/run.sh inside the guest!
	{
		var out, errBuf bytes.Buffer
		cfg := newCheckpointTestConfig(t, cacheDir)
		cfg.OCILayerTars = [][]byte{layer}
		cfg.Mounts = mounts
		cfg.Argv = []string{"/mnt/persist/bin/run.sh"}
		cfg.Stdout = &out
		cfg.Stderr = &errBuf
		sb, nErr := New(context.Background(), cfg)
		if nErr != nil {
			t.Fatalf("New(exec script): %v", nErr)
		}
		code, rErr := sb.Run(context.Background())
		cErr := sb.Close()
		if rErr != nil || cErr != nil || code != 0 || !strings.Contains(out.String(), "script-ran-from-overlay\n") {
			t.Fatalf("Run(script) = (%d, %v) Close=%v stdout=%q stderr=%q", code, rErr, cErr, out.String(), errBuf.String())
		}
	}

	// Step 2: Seed persistent upper branch-ckpt with /mnt/persist/branch-note.txt.
	{
		cfg := newCheckpointTestConfig(t, cacheDir)
		cfg.OCILayerTars = [][]byte{layer}
		cfg.Mounts = mounts
		cfg.Argv = []string{"/bin/write-branch"}
		sb, nErr := New(context.Background(), cfg)
		if nErr != nil {
			t.Fatalf("New(write-branch): %v", nErr)
		}
		code, rErr := sb.Run(context.Background())
		cErr := sb.Close()
		if rErr != nil || cErr != nil || code != 0 {
			t.Fatalf("Run(write-branch) = (%d, %v) Close=%v", code, rErr, cErr)
		}
	}

	// Step 3: Boot a long-running cat across /mnt/persist, stdin, /mnt/scratch, and /mnt/ro;
	// Checkpoint while blocked on stdin; Restore and verify full output!
	ckptDir := filepath.Join(t.TempDir(), "ckpt-overlay")
	stdinR, stdinW := net.Pipe()
	defer stdinR.Close()
	defer stdinW.Close()

	stdout1 := newNotifyBuffer()
	var stderr1 syncBuffer
	cfgCkpt := newCheckpointTestConfig(t, cacheDir)
	cfgCkpt.OCILayerTars = [][]byte{layer}
	cfgCkpt.CheckpointDir = ckptDir
	cfgCkpt.Mounts = mounts
	cfgCkpt.Argv = []string{
		"/bin/cat",
		"/mnt/persist/branch-note.txt",
		"/proc/self/fd/0",
		"/mnt/persist/keep.txt",
		"/mnt/scratch/scratch-note.txt",
		"/mnt/ro/hard2.txt",
	}
	cfgCkpt.Stdin = stdinR
	cfgCkpt.Stdout = stdout1
	cfgCkpt.Stderr = &stderr1

	sbCkpt, err := New(context.Background(), cfgCkpt)
	if err != nil {
		t.Fatalf("New(ckpt): %v", err)
	}
	defer sbCkpt.Close()

	runCh := make(chan error, 1)
	go func() {
		code, rErr := sbCkpt.Run(context.Background())
		if rErr != nil {
			runCh <- rErr
			return
		}
		if code != 0 {
			runCh <- errors.New("non-zero checkpoint run exit")
			return
		}
		runCh <- nil
	}()

	stdout1.waitForSubstring(t, "persisted-in-branch\n", 15*time.Second)

	// Mutate the live ephemeral tmpfs upper before Checkpoint so Restore must preserve tmpfs upper pages!
	sbCkpt.mu.Lock()
	liveK := sbCkpt.activeKernel
	sbCkpt.mu.Unlock()
	if liveK == nil {
		t.Fatal("activeKernel is nil while running")
	}
	kCtx := liveK.SupervisorContext()
	liveCreds := auth.NewRootCredentials(liveK.RootUserNamespace())
	liveRoot := liveK.GlobalInit().Leader().MountNamespace().Root(kCtx)
	if wErr := vfsWriteFile(kCtx, liveK.VFS(), liveCreds, liveRoot, "/mnt/scratch/scratch-note.txt", []byte("ephemeral-in-tmpfs\n"), 0o644); wErr != nil {
		liveRoot.DecRef(kCtx)
		t.Fatalf("write live /mnt/scratch/scratch-note.txt: %v", wErr)
	}
	liveRoot.DecRef(kCtx)

	if err := sbCkpt.Checkpoint(context.Background(), CheckpointOptions{LeaveRunning: false}); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if err := <-runCh; err != nil {
		t.Fatalf("Run before checkpoint: %v (stderr=%q)", err, stderr1.String())
	}
	if err := sbCkpt.Close(); err != nil {
		t.Fatalf("Close after checkpoint: %v", err)
	}

	// Mismatched upper backing (switching persistent upper to tmpfs upper) on Restore must fail manifest check!
	badRestoreCfg := newCheckpointTestConfig(t, cacheDir)
	badRestoreCfg.OCILayerTars = [][]byte{layer}
	badRestoreCfg.Mounts = []Mount{
		{Kind: MountOverlay, VolumeName: "base-vol", GuestPath: "/mnt/persist"},
		{Kind: MountOverlay, VolumeName: "base-vol", GuestPath: "/mnt/scratch", TmpfsSizeBytes: 16 << 20},
		{Kind: MountVolume, VolumeName: "base-vol", GuestPath: "/mnt/ro", ReadOnly: true},
	}
	if badSB, badErr := Restore(context.Background(), badRestoreCfg, RestoreOptions{Dir: ckptDir}); !errors.Is(badErr, ErrCheckpointManifest) {
		if badSB != nil {
			_ = badSB.Close()
		}
		t.Fatalf("Restore with mismatched overlay upper = %v, want ErrCheckpointManifest", badErr)
	}

	// Valid Restore with matching MountOverlay configuration.
	var stdout2, stderr2 bytes.Buffer
	restoreCfg := newCheckpointTestConfig(t, cacheDir)
	restoreCfg.OCILayerTars = [][]byte{layer}
	restoreCfg.Mounts = mounts
	restoreCfg.Stdin = strings.NewReader("resumed-overlay-ok\n")
	restoreCfg.Stdout = &stdout2
	restoreCfg.Stderr = &stderr2

	restoredSB, err := Restore(context.Background(), restoreCfg, RestoreOptions{Dir: ckptDir})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	code2, rErr2 := restoredSB.Run(context.Background())
	cErr2 := restoredSB.Close()
	if rErr2 != nil || cErr2 != nil || code2 != 0 {
		t.Fatalf("restored Run = (%d, %v) Close=%v stdout=%q stderr=%q", code2, rErr2, cErr2, stdout2.String(), stderr2.String())
	}
	wantRestored := "resumed-overlay-ok\nbase-keep-v1\nephemeral-in-tmpfs\nshared-hardlink-v1\n"
	if stdout2.String() != wantRestored {
		t.Fatalf("restored stdout = %q, want %q", stdout2.String(), wantRestored)
	}

	rawAfter, err := os.ReadFile(baseImg)
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest := sha256.Sum256(rawAfter); gotDigest != baseDigest {
		t.Fatalf("base-vol.ext4 mutated across sandbox & checkpoint/restore: %x != %x", gotDigest, baseDigest)
	}
}
