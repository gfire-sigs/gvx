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

package hostfs

import (
	"bytes"
	goContext "context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/checkpoint"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/usermem"
)

func newEnvInDirWithOptions(t *testing.T, dir string, opts workspaceOptions) *env {
	t.Helper()
	ws, err := openWorkspace(dir, false, opts)
	if err != nil {
		t.Fatalf("openWorkspace(%q): %v", dir, err)
	}
	e := mountEnv(t, ws, dir)
	t.Cleanup(func() {
		e.root.DecRef(e.ctx)
		if err := ws.Close(); err != nil {
			t.Errorf("Workspace.Close: %v", err)
		}
	})
	return e
}

// TestReservedMetadataLockAndTempNamesAreIsolated verifies that guest VFS and
// Workspace operations cannot list, stat, open, create, unlink, or rename
// .gvx_meta, .gvx_meta.lock, or .gvx_meta.tmp* in the workspace root, while
// permitting those names inside subdirectories.
func TestReservedMetadataLockAndTempNamesAreIsolated(t *testing.T) {
	e := newEnv(t)
	e.writeFile("visible.txt", []byte("ok"))
	if err := e.ws.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	// Seed lock and per-workspace temp artifacts on the host root to prove
	// existing host files under reserved names stay invisible and untouchable.
	for _, hostReserved := range []string{
		".gvx_meta.lock",
		".gvx_meta.tmp",
		".gvx_meta.tmp.0123456789abcdef",
	} {
		p := e.host(hostReserved)
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(p, []byte("internal"), 0o600); err != nil {
				t.Fatalf("seed %s: %v", hostReserved, err)
			}
		}
	}

	reserved := []string{
		MetaFileName,
		".GVX_META",
		".gvx_meta.lock",
		".GVX_META.LOCK",
		".gvx_meta.tmp",
		".gvx_meta.tmp.",
		".gvx_meta.tmp.0123456789abcdef",
		".GVX_META.TMP.DEADBEEF",
	}
	for _, name := range reserved {
		// VFS seam checks.
		wantErrno(t, "vfs stat "+name, func() error { _, err := e.stat(name); return err }(), linuxerr.ENOENT)
		_, openROErr := e.open(name, linux.O_RDONLY, 0)
		wantErrno(t, "vfs open rdonly "+name, openROErr, linuxerr.ENOENT)
		_, openCreatErr := e.open(name, linux.O_CREAT|linux.O_WRONLY, 0o644)
		wantErrno(t, "vfs open creat "+name, openCreatErr, linuxerr.EPERM)
		wantErrno(t, "vfs mkdir "+name, e.mkdir(name), linuxerr.EPERM)
		wantErrno(t, "vfs symlink "+name, e.symlink(name, "visible.txt"), linuxerr.EPERM)
		wantErrno(t, "vfs unlink "+name, e.unlink(name), linuxerr.ENOENT)
		wantErrno(t, "vfs rename onto "+name, e.rename("visible.txt", name), linuxerr.EPERM)
		wantErrno(t, "vfs rename from "+name, e.rename(name, "stolen.txt"), linuxerr.ENOENT)

		// Direct Workspace seam checks.
		if _, _, err := e.ws.Stat(name); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Workspace.Stat(%q) = %v, want fs.ErrNotExist", name, err)
		}
		if _, err := e.ws.OpenFile(name, os.O_RDONLY, 0); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("Workspace.OpenFile(%q, O_RDONLY) = %v, want fs.ErrNotExist", name, err)
		}
		if _, err := e.ws.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0o644); !errors.Is(err, errReservedName) {
			t.Fatalf("Workspace.OpenFile(%q, O_CREATE) = %v, want errReservedName", name, err)
		}
		if err := e.ws.Unlink(name); !errors.Is(err, errReservedName) {
			t.Fatalf("Workspace.Unlink(%q) = %v, want errReservedName", name, err)
		}
		if err := e.ws.Rename("visible.txt", name); !errors.Is(err, errReservedName) {
			t.Fatalf("Workspace.Rename(visible.txt, %q) = %v, want errReservedName", name, err)
		}
		if err := e.ws.Rename(name, "stolen.txt"); !errors.Is(err, errReservedName) {
			t.Fatalf("Workspace.Rename(%q, stolen.txt) = %v, want errReservedName", name, err)
		}
	}

	if got := e.readdir("."); !slices.Equal(got, []string{"visible.txt"}) {
		t.Fatalf("vfs readdir(.) = %v, want [visible.txt]", got)
	}
	entries, err := e.ws.ListEntries()
	if err != nil {
		t.Fatalf("ListEntries: %v", err)
	}
	if !slices.Equal(entries, []string{"visible.txt"}) {
		t.Fatalf("Workspace.ListEntries() = %v, want [visible.txt]", entries)
	}

	// Host files must remain intact on disk after blocked guest unlink/rename attempts.
	for _, keep := range []string{MetaFileName, ".gvx_meta.lock", ".gvx_meta.tmp.0123456789abcdef"} {
		if _, err := os.Stat(e.host(keep)); err != nil {
			t.Fatalf("host %s vanished after guest tampering attempts: %v", keep, err)
		}
	}

	// Identical names inside a subdirectory are ordinary guest files, not root metadata.
	e.mustMkdir("sub")
	for _, subName := range []string{"sub/.gvx_meta", "sub/.gvx_meta.lock", "sub/.gvx_meta.tmp.1234"} {
		e.writeFile(subName, []byte("guest-data"))
		if got := e.readFile(subName); string(got) != "guest-data" {
			t.Fatalf("read %s = %q, want guest-data", subName, got)
		}
	}
}

// TestMultiWorkspaceConcurrentMetaTorture opens four writable Workspaces and
// one read-only Workspace on the same directory, forces frequent compactions
// alongside journal appends, and verifies zero lost disjoint records, clean
// CRC-32C journal integrity, zero resurrected deletes, and live cross-workspace
// visibility of chmod, xattr, and virtual symlinks.
func TestMultiWorkspaceConcurrentMetaTorture(t *testing.T) {
	dir := resolvedTempDir(t)
	const (
		numWorkers = 4
		filesPerW  = 16
		sharedCnt  = 4
	)

	// Pre-open a read-only observer BEFORE any writable workspace creates
	// .gvx_meta or .gvx_meta.lock to test the RO-from-empty refresh path too.
	roEarly, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatalf("OpenWorkspace(RO early): %v", err)
	}
	defer func() { _ = roEarly.Close() }()

	envs := make([]*env, numWorkers)
	for i := range numWorkers {
		envs[i] = newEnvInDirWithOptions(t, dir, workspaceOptions{
			coalesce:     defaultCoalesceWindow,
			journalSlack: 4, // Force frequent compactions interleaved with appends.
			noOrphanGC:   true,
		})
	}

	roPeer, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatalf("OpenWorkspace(RO peer): %v", err)
	}
	defer func() { _ = roPeer.Close() }()

	if err := envs[0].ws.MkdirAll("shared", 0o755); err != nil {
		t.Fatalf("MkdirAll(shared): %v", err)
	}
	for k := range sharedCnt {
		p := fmt.Sprintf("shared/hook_%d.sh", k)
		if err := envs[0].ws.WriteFile(p, []byte("#!/bin/sh\n"), 0o644); err != nil {
			t.Fatalf("WriteFile(%s): %v", p, err)
		}
	}
	if err := envs[0].ws.Sync(); err != nil {
		t.Fatalf("initial Sync: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, numWorkers*8)
	for wIdx := range numWorkers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ev := envs[id]
			ws := ev.ws
			wDir := fmt.Sprintf("w%d", id)
			if err := ws.MkdirAll(wDir, 0o750); err != nil {
				errCh <- fmt.Errorf("w%d MkdirAll: %w", id, err)
				return
			}
			for j := range filesPerW {
				execRel := fmt.Sprintf("%s/exec_%02d.sh", wDir, j)
				wantMode := uint32(0o700 | ((id*7 + j) & 0o77))
				wantUID := uint32(1000 + id*100 + j)
				wantGID := uint32(2000 + id*100 + j)
				if err := ws.WriteFile(execRel, []byte("#!/bin/sh\necho ok\n"), 0o600); err != nil {
					errCh <- fmt.Errorf("w%d WriteFile(%s): %w", id, execRel, err)
					return
				}
				if err := ws.Chmod(execRel, wantMode); err != nil {
					errCh <- fmt.Errorf("w%d Chmod(%s): %w", id, execRel, err)
					return
				}
				if err := ws.Chown(execRel, wantUID, wantGID); err != nil {
					errCh <- fmt.Errorf("w%d Chown(%s): %w", id, execRel, err)
					return
				}
				xval := fmt.Sprintf("worker-%d-item-%d", id, j)
				if err := ev.vfsObj.SetXattrAt(ev.ctx, ev.creds, ev.pop(execRel), &vfs.SetXattrOptions{
					Name:  "trusted.owner",
					Value: xval,
				}); err != nil {
					errCh <- fmt.Errorf("w%d SetXattrAt(%s): %w", id, execRel, err)
					return
				}

				symRel := fmt.Sprintf("%s/sym_%02d", wDir, j)
				symTarget := fmt.Sprintf("../target_%d_%02d", id, j)
				if err := ws.Symlink(symTarget, symRel); err != nil {
					errCh <- fmt.Errorf("w%d Symlink(%s): %w", id, symRel, err)
					return
				}

				// Create and unlink a transient file across Syncs to attack
				// peer compaction resurrection of deleted records.
				ephemRel := fmt.Sprintf("%s/transient_%02d", wDir, j)
				if err := ws.WriteFile(ephemRel, []byte("temp"), 0o755); err != nil {
					errCh <- fmt.Errorf("w%d WriteFile(%s): %w", id, ephemRel, err)
					return
				}
				if j%2 == 0 {
					if err := ws.Sync(); err != nil {
						errCh <- fmt.Errorf("w%d mid Sync(%d): %w", id, j, err)
						return
					}
				}
				if err := ws.Unlink(ephemRel); err != nil {
					errCh <- fmt.Errorf("w%d Unlink(%s): %w", id, ephemRel, err)
					return
				}

				// Overlapping mutation on shared hook files.
				sharedRel := fmt.Sprintf("shared/hook_%d.sh", j%sharedCnt)
				_ = ws.Chmod(sharedRel, 0o755)
				_ = ws.Chown(sharedRel, uint32(3000+id), uint32(4000+j))

				if err := ws.Sync(); err != nil {
					errCh <- fmt.Errorf("w%d Sync(%d): %w", id, j, err)
					return
				}
			}
		}(wIdx)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent worker error: %v", err)
	}

	// Verify on-disk .gvx_meta parses cleanly with zero leftover .gvx_meta.tmp* files.
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, de := range dirEntries {
		if strings.HasPrefix(strings.ToLower(de.Name()), ".gvx_meta.tmp") {
			t.Fatalf("leftover compaction temp file on disk: %q", de.Name())
		}
	}

	metaMap, err := ReadMeta(filepath.Join(dir, MetaFileName))
	if err != nil {
		t.Fatalf("ReadMeta(.gvx_meta) failed CRC/parse integrity: %v", err)
	}

	for id := range numWorkers {
		wDir := fmt.Sprintf("w%d", id)
		for j := range filesPerW {
			execRel := fmt.Sprintf("%s/exec_%02d.sh", wDir, j)
			wantMode := uint32(0o700 | ((id*7 + j) & 0o77))
			wantUID := uint32(1000 + id*100 + j)
			wantGID := uint32(2000 + id*100 + j)
			wantXattr := fmt.Sprintf("worker-%d-item-%d", id, j)

			attr, ok := metaMap[execRel]
			if !ok {
				t.Fatalf("missing disjoint record %q in .gvx_meta", execRel)
			}
			if got := attr.Mode & 0o7777; got != wantMode {
				t.Fatalf("%s mode = %04o, want %04o", execRel, got, wantMode)
			}
			if attr.UID != wantUID || attr.GID != wantGID {
				t.Fatalf("%s owner = %d:%d, want %d:%d", execRel, attr.UID, attr.GID, wantUID, wantGID)
			}
			if got := string(attr.Xattrs["trusted.owner"]); got != wantXattr {
				t.Fatalf("%s trusted.owner = %q, want %q", execRel, got, wantXattr)
			}

			symRel := fmt.Sprintf("%s/sym_%02d", wDir, j)
			wantTarget := fmt.Sprintf("../target_%d_%02d", id, j)
			symAttr, ok := metaMap[symRel]
			if !ok || symAttr.Symlink != wantTarget {
				t.Fatalf("%s symlink = (%+v, %v), want target %q", symRel, symAttr, ok, wantTarget)
			}

			ephemRel := fmt.Sprintf("%s/transient_%02d", wDir, j)
			if ghost, leaked := metaMap[ephemRel]; leaked {
				t.Fatalf("deleted record %s resurrected in .gvx_meta: %+v", ephemRel, ghost)
			}
		}
	}

	// Verify live cross-workspace visibility (including negative-cache & warm-stat invalidation)
	// WITHOUT remounting any peer workspace.
	if err := envs[0].ws.MkdirAll("live", 0o755); err != nil {
		t.Fatalf("MkdirAll(live): %v", err)
	}
	if err := envs[0].ws.WriteFile("live/deploy.sh", []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(live/deploy.sh): %v", err)
	}
	if err := envs[0].ws.Sync(); err != nil {
		t.Fatalf("Sync(live seed): %v", err)
	}

	// Warm Peer 1's VFS dentry cache on live/deploy.sh (0644) and negative cache on live/current.
	if st := envs[1].mustStat("live/deploy.sh"); st.Mode&0o7777 != 0o644 {
		t.Fatalf("peer 1 initial VFS stat mode = %04o, want 0644", st.Mode&0o7777)
	}
	if _, err := envs[1].stat("live/current"); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Fatalf("peer 1 initial stat(live/current) = %v, want ENOENT", err)
	}

	// Peer 0 upgrades deploy.sh to 0755, attaches xattr, and creates virtual symlink live/current to deploy.sh.
	if err := envs[0].ws.Chmod("live/deploy.sh", 0o755); err != nil {
		t.Fatalf("Chmod(live/deploy.sh): %v", err)
	}
	if err := envs[0].vfsObj.SetXattrAt(envs[0].ctx, envs[0].creds, envs[0].pop("live/deploy.sh"), &vfs.SetXattrOptions{
		Name:  "trusted.stage",
		Value: "ready",
	}); err != nil {
		t.Fatalf("SetXattrAt(live/deploy.sh): %v", err)
	}
	if err := envs[0].ws.Symlink("deploy.sh", "live/current"); err != nil {
		t.Fatalf("Symlink(live/current): %v", err)
	}
	if err := envs[0].ws.Sync(); err != nil {
		t.Fatalf("Sync(live update): %v", err)
	}

	// Peer 1..3 (RW), roPeer, and roEarly must all see 0755 + symlink immediately.
	for idx, observer := range []*Workspace{envs[1].ws, envs[2].ws, envs[3].ws, roPeer, roEarly} {
		attr, _, err := observer.Stat("live/deploy.sh")
		if err != nil || attr.Mode&0o7777 != 0o755 {
			t.Fatalf("observer[%d] Stat(live/deploy.sh) = (%+v, %v), want mode 0755", idx, attr, err)
		}
		target, err := observer.Readlink("live/current")
		if err != nil || target != "deploy.sh" {
			t.Fatalf("observer[%d] Readlink(live/current) = (%q, %v), want deploy.sh", idx, target, err)
		}
	}
	// Peer 1 VFS must also see updated mode, xattr, and symlink despite prior warm/negative cache!
	if got := envs[1].mustGetXattr("live/deploy.sh", "trusted.stage"); got != "ready" {
		t.Fatalf("peer 1 VFS GetXattr(trusted.stage) = %q, want ready", got)
	}
	noFollowLive := &vfs.PathOperation{Root: envs[1].root, Start: envs[1].root, Path: fspath.Parse("live/current")}
	if st, err := envs[1].vfsObj.StatAt(envs[1].ctx, envs[1].creds, noFollowLive, &vfs.StatOptions{Mask: linux.STATX_BASIC_STATS}); err != nil || st.Mode&linux.S_IFMT != linux.S_IFLNK {
		t.Fatalf("peer 1 VFS lstat(live/current) = (%+v, %v), want S_IFLNK", st, err)
	}
	if st := envs[1].mustStat("live/deploy.sh"); st.Mode&0o7777 != 0o755 {
		t.Fatalf("peer 1 VFS stat(live/deploy.sh) mode = %04o, want 0755", st.Mode&0o7777)
	}
}

// TestCheckpointRestorePreservesMultiWorkspaceMetaSync verifies that
// OpenWorkspaceForRestore opens .gvx_meta.lock identically, observes peer
// mutations made while the container was checkpointed, and merges post-restore
// flushes without clobbering peer records.
func TestCheckpointRestorePreservesMultiWorkspaceMetaSync(t *testing.T) {
	dir := resolvedTempDir(t)
	ws1, err := OpenWorkspace(dir, false)
	if err != nil {
		t.Fatalf("OpenWorkspace(ws1): %v", err)
	}
	ws2, err := OpenWorkspace(dir, false)
	if err != nil {
		_ = ws1.Close()
		t.Fatalf("OpenWorkspace(ws2): %v", err)
	}
	defer func() { _ = ws2.Close() }()

	baseCtx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(baseCtx); err != nil {
		t.Fatalf("vfsObj.Init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})

	mountID := checkpoint.ResourceID{ContainerName: "sandbox-mp-sr", Path: "/workspace"}
	mntns, err := vfsObj.NewMountNamespace(baseCtx, creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: InternalFilesystemOptions{
				Workspace: ws1,
				UniqueID:  mountID,
			},
		},
	}, testNSFS{})
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}
	root := mntns.Root(baseCtx)
	ctx := cookieContext{vfs.WithMountNamespace(baseCtx, mntns)}
	pop := func(p string) *vfs.PathOperation {
		return &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(p), FollowFinalSymlink: true}
	}

	fd, err := vfsObj.OpenAt(ctx, creds, pop("saved.sh"), &vfs.OpenOptions{
		Flags: linux.O_CREAT | linux.O_RDWR | linux.O_TRUNC,
		Mode:  0o750,
	})
	if err != nil {
		t.Fatalf("OpenAt(saved.sh): %v", err)
	}
	if _, err := fd.Write(ctx, usermem.BytesIOSequence([]byte("#!/bin/sh\necho saved\n")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("Write(saved.sh): %v", err)
	}

	if err := vfsObj.PrepareSave(ctx, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("PrepareSave: %v", err)
	}
	var stateBuf bytes.Buffer
	origBundle := &checkpointBundle{
		vfsObj: vfsObj,
		mntns:  mntns,
		root:   root,
		regFD:  fd,
	}
	if _, err := state.Save(goContext.Background(), &stateBuf, origBundle); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	fd.DecRef(ctx)
	root.DecRef(ctx)
	mntns.DecRef(baseCtx)
	vfsObj.Release(baseCtx)
	if err := ws1.Close(); err != nil {
		t.Fatalf("ws1.Close: %v", err)
	}

	// While ws1 is checkpointed, ws2 writes new executable and symlink records.
	if err := ws2.WriteFile("peer_frozen.sh", []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("ws2 WriteFile: %v", err)
	}
	if err := ws2.Symlink("saved.sh", "peer_link"); err != nil {
		t.Fatalf("ws2 Symlink: %v", err)
	}
	if err := ws2.Sync(); err != nil {
		t.Fatalf("ws2 Sync: %v", err)
	}

	restoredWS, err := OpenWorkspaceForRestore(dir, false)
	if err != nil {
		t.Fatalf("OpenWorkspaceForRestore: %v", err)
	}
	defer func() {
		if closeErr := restoredWS.Close(); closeErr != nil {
			t.Errorf("restoredWS.Close: %v", closeErr)
		}
	}()

	var restored checkpointBundle
	loadGoCtx := WithRestoreWorkspace(goContext.Background(), mountID, restoredWS)
	if _, err := state.Load(loadGoCtx, bytes.NewReader(stateBuf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	restoreBaseCtx := WithRestoreWorkspaceContext(gvcontext.Background(), mountID, restoredWS)
	restoreCtx := cookieContext{vfs.WithMountNamespace(restoreBaseCtx, restored.mntns)}
	defer func() {
		if restored.regFD != nil {
			restored.regFD.DecRef(restoreCtx)
		}
		restored.root.DecRef(restoreCtx)
		restored.mntns.DecRef(restoreBaseCtx)
		restored.vfsObj.Release(restoreBaseCtx)
	}()
	if err := restored.vfsObj.CompleteRestore(restoreCtx, &vfs.CompleteRestoreOptions{}); err != nil {
		t.Fatalf("CompleteRestore: %v", err)
	}

	// Now ws2 mutates another file AFTER OpenWorkspaceForRestore, and restoredWS
	// also mutates its own file; neither may clobber the other!
	if err := ws2.WriteFile("peer_live.sh", []byte("#!/bin/sh\n"), 0o711); err != nil {
		t.Fatalf("ws2 WriteFile(peer_live.sh): %v", err)
	}
	if err := ws2.Sync(); err != nil {
		t.Fatalf("ws2 Sync(peer_live.sh): %v", err)
	}

	if err := restoredWS.WriteFile("after_restore.sh", []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatalf("restoredWS WriteFile(after_restore.sh): %v", err)
	}
	if err := restoredWS.Sync(); err != nil {
		t.Fatalf("restoredWS Sync: %v", err)
	}

	for name, wantMode := range map[string]uint32{
		"saved.sh":         0o750,
		"peer_frozen.sh":   0o755,
		"peer_live.sh":     0o711,
		"after_restore.sh": 0o700,
	} {
		for label, observer := range map[string]*Workspace{"restoredWS": restoredWS, "ws2": ws2} {
			attr, _, err := observer.Stat(name)
			if err != nil || attr.Mode&0o7777 != wantMode {
				t.Fatalf("%s Stat(%s) = (%+v, %v), want mode %04o", label, name, attr, err, wantMode)
			}
		}
	}
	if target, err := restoredWS.Readlink("peer_link"); err != nil || target != "saved.sh" {
		t.Fatalf("restoredWS Readlink(peer_link) = (%q, %v), want saved.sh", target, err)
	}
}

// TestAdversarialMetaLockSymlinkAndDirectoryRejected verifies that planting a
// host symlink or directory at .gvx_meta.lock causes OpenWorkspace (both RW and
// RO) to fail loudly rather than following the symlink or degrading locklessly.
func TestAdversarialMetaLockSymlinkAndDirectoryRejected(t *testing.T) {
	t.Run("directory at .gvx_meta.lock", func(t *testing.T) {
		dir := resolvedTempDir(t)
		if err := os.Mkdir(filepath.Join(dir, MetaLockFileName), 0o700); err != nil {
			t.Fatalf("Mkdir(.gvx_meta.lock): %v", err)
		}
		if ws, err := OpenWorkspace(dir, false); err == nil {
			_ = ws.Close()
			t.Fatal("OpenWorkspace(RW) succeeded with directory at .gvx_meta.lock")
		}
		if ws, err := OpenWorkspace(dir, true); err == nil {
			_ = ws.Close()
			t.Fatal("OpenWorkspace(RO) succeeded with directory at .gvx_meta.lock")
		}
	})

	t.Run("symlink at .gvx_meta.lock", func(t *testing.T) {
		dir := resolvedTempDir(t)
		outside := filepath.Join(resolvedTempDir(t), "victim.lock")
		if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
			t.Fatalf("WriteFile(outside): %v", err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, MetaLockFileName)); err != nil {
			t.Skipf("host cannot create symlinks: %v", err)
		}
		if ws, err := OpenWorkspace(dir, false); err == nil {
			_ = ws.Close()
			t.Fatal("OpenWorkspace(RW) followed symlink at .gvx_meta.lock")
		}
		if ws, err := OpenWorkspace(dir, true); err == nil {
			_ = ws.Close()
			t.Fatal("OpenWorkspace(RO) followed symlink at .gvx_meta.lock")
		}
		if got, err := os.ReadFile(outside); err != nil || string(got) != "outside" {
			t.Fatalf("outside target altered = (%q, %v), want \"outside\"", got, err)
		}
	})
}

// TestAdversarialPeerTornTailAndOrphanTempRecovery verifies that if Peer A
// crashes mid-append (leaving a torn frame tail in .gvx_meta and an orphaned
// .gvx_meta.tmp.<dead> file), Peer B still reads all prior valid frames,
// replaces the torn file cleanly on its next Sync without losing Peer A's
// committed records, and sweeps the orphaned .gvx_meta.tmp.<dead> file.
func TestAdversarialPeerTornTailAndOrphanTempRecovery(t *testing.T) {
	dir := resolvedTempDir(t)
	wsA, err := OpenWorkspace(dir, false)
	if err != nil {
		t.Fatalf("OpenWorkspace(wsA): %v", err)
	}
	defer func() { _ = wsA.Close() }()

	wsB, err := OpenWorkspace(dir, false)
	if err != nil {
		t.Fatalf("OpenWorkspace(wsB): %v", err)
	}
	defer func() { _ = wsB.Close() }()

	if err := wsA.WriteFile("committed_by_a.sh", []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("wsA WriteFile: %v", err)
	}
	if err := wsA.Sync(); err != nil {
		t.Fatalf("wsA first Sync: %v", err)
	}
	// Second commit from wsA appends a valid frame.
	if err := wsA.Symlink("committed_by_a.sh", "a_sym"); err != nil {
		t.Fatalf("wsA Symlink: %v", err)
	}
	if err := wsA.Sync(); err != nil {
		t.Fatalf("wsA second Sync: %v", err)
	}

	// Simulate a killed third peer that left a torn tail at EOF of .gvx_meta
	// AND an orphaned .gvx_meta.tmp.deadbeef staging file.
	metaPath := filepath.Join(dir, MetaFileName)
	f, err := os.OpenFile(metaPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("OpenFile(.gvx_meta): %v", err)
	}
	if _, err := f.Write([]byte{0xff, 0x00, 0x00, 0x00, 0xde, 0xad}); err != nil {
		_ = f.Close()
		t.Fatalf("append torn tail: %v", err)
	}
	_ = f.Close()

	orphanTmp := filepath.Join(dir, ".gvx_meta.tmp.deadbeefcafe")
	if err := os.WriteFile(orphanTmp, []byte("GVXMETA\x04incomplete"), 0o600); err != nil {
		t.Fatalf("seed orphan tmp: %v", err)
	}

	// wsB refreshes across the torn tail: must see committed_by_a.sh (0755) and a_sym.
	if attr, _, err := wsB.Stat("committed_by_a.sh"); err != nil || attr.Mode&0o7777 != 0o755 {
		t.Fatalf("wsB Stat(committed_by_a.sh) with torn tail = (%+v, %v), want 0755", attr, err)
	}
	if target, err := wsB.Readlink("a_sym"); err != nil || target != "committed_by_a.sh" {
		t.Fatalf("wsB Readlink(a_sym) with torn tail = (%q, %v), want committed_by_a.sh", target, err)
	}

	// wsB now writes its own file and flushes: must compact away the torn tail,
	// preserve wsA's records, and sweep .gvx_meta.tmp.deadbeefcafe.
	if err := wsB.WriteFile("committed_by_b.sh", []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatalf("wsB WriteFile: %v", err)
	}
	if err := wsB.Sync(); err != nil {
		t.Fatalf("wsB Sync over torn tail: %v", err)
	}

	if _, err := os.Stat(orphanTmp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphaned %s survived compaction recovery: %v", orphanTmp, err)
	}
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("ReadFile(.gvx_meta): %v", err)
	}
	img, err := parseMeta(raw)
	if err != nil || img.torn {
		t.Fatalf("parseMeta after wsB compaction = (torn=%v, err=%v), want clean untorn snapshot", img.torn, err)
	}
	metaMap, err := ReadMeta(metaPath)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if metaMap["committed_by_a.sh"].Mode&0o7777 != 0o755 || metaMap["committed_by_b.sh"].Mode&0o7777 != 0o700 || metaMap["a_sym"].Symlink != "committed_by_a.sh" {
		t.Fatalf("ReadMeta after torn-tail recovery = %+v", metaMap)
	}
}

// TestAdversarialNoStableIDsMultiWorkspaceSync verifies that volumes without
// trustworthy file identities (!StableIDs, pathKeys=true) still preserve both
// single-writer appends and multi-workspace read-merge-write safety via the
// mtime + lock-sequence fallback, and survive concurrent Close calls cleanly.
func TestAdversarialNoStableIDsMultiWorkspaceSync(t *testing.T) {
	dir := resolvedTempDir(t)
	noIDCaps := WorkspaceCaps{CaseSensitive: true, StableIDs: false}
	ws1, err := openWorkspace(dir, false, workspaceOptions{
		coalesce:   defaultCoalesceWindow,
		caps:       &noIDCaps,
		pathKeys:   true,
		noOrphanGC: true,
	})
	if err != nil {
		t.Fatalf("openWorkspace(ws1): %v", err)
	}
	ws2, err := openWorkspace(dir, false, workspaceOptions{
		coalesce:   defaultCoalesceWindow,
		caps:       &noIDCaps,
		pathKeys:   true,
		noOrphanGC: true,
	})
	if err != nil {
		_ = ws1.Close()
		t.Fatalf("openWorkspace(ws2): %v", err)
	}

	if err := ws1.WriteFile("p1.sh", []byte("1"), 0o755); err != nil {
		t.Fatalf("ws1 WriteFile: %v", err)
	}
	if err := ws1.Sync(); err != nil {
		t.Fatalf("ws1 Sync 1: %v", err)
	}
	// Second single-writer Sync on !StableIDs must append without unnecessary rewrite error.
	if err := ws1.Chown("p1.sh", 111, 222); err != nil {
		t.Fatalf("ws1 Chown: %v", err)
	}
	if err := ws1.Sync(); err != nil {
		t.Fatalf("ws1 Sync 2: %v", err)
	}

	if err := ws2.WriteFile("p2.sh", []byte("2"), 0o711); err != nil {
		t.Fatalf("ws2 WriteFile: %v", err)
	}
	if err := ws2.Symlink("p1.sh", "p2_sym"); err != nil {
		t.Fatalf("ws2 Symlink: %v", err)
	}
	if err := ws2.Sync(); err != nil {
		t.Fatalf("ws2 Sync: %v", err)
	}

	if attr, _, err := ws1.Stat("p2.sh"); err != nil || attr.Mode&0o7777 != 0o711 {
		t.Fatalf("ws1 Stat(p2.sh) = (%+v, %v), want 0711", attr, err)
	}
	if attr, _, err := ws2.Stat("p1.sh"); err != nil || attr.Mode&0o7777 != 0o755 || attr.UID != 111 || attr.GID != 222 {
		t.Fatalf("ws2 Stat(p1.sh) = (%+v, %v), want mode 0755 owner 111:222", attr, err)
	}
	if target, err := ws1.Readlink("p2_sym"); err != nil || target != "p1.sh" {
		t.Fatalf("ws1 Readlink(p2_sym) = (%q, %v), want p1.sh", target, err)
	}

	// Concurrent double Close on both workspaces must succeed without races or EBADF.
	var wg sync.WaitGroup
	for _, ws := range []*Workspace{ws1, ws2} {
		for range 2 {
			wg.Add(1)
			go func(w *Workspace) {
				defer wg.Done()
				if cerr := w.Close(); cerr != nil {
					t.Errorf("concurrent Close: %v", cerr)
				}
			}(ws)
		}
	}
	wg.Wait()
}
