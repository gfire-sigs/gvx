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

package cgroup2fs

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/blockdev"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	sentrytime "z.gfire.dev/gvx/pkg/sentry/time"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

func readCgroupPath(t *testing.T, ctx *kernel.Task, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, path string) string {
	t.Helper()
	sctx := ctx.AsyncContext()
	fd := openCgroupRead(t, sctx, vfsObj, creds, root, path)
	defer fd.DecRef(sctx)
	buf := make([]byte, 8192)
	n, err := fd.PRead(sctx, usermem.BytesIOSequence(buf), 0, vfs.ReadOptions{})
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("PRead(%s): %v", path, err)
	}
	return string(buf[:n])
}

func writeCgroupFileErr(ctx *kernel.Task, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, path, content string) error {
	sctx := ctx.AsyncContext()
	pop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(path)}
	fd, err := vfsObj.OpenAt(sctx, creds, pop, &vfs.OpenOptions{Flags: linux.O_WRONLY})
	if err != nil {
		return err
	}
	defer fd.DecRef(sctx)
	_, err = fd.Write(sctx, usermem.BytesIOSequence([]byte(content)), vfs.WriteOptions{})
	return err
}

func TestCgroup2IOControllerHierarchyValidationAndSaveRestore(t *testing.T) {
	opts := MemoryEnforcerOptions{
		PollInterval:     25 * time.Millisecond,
		IdlePollInterval: 100 * time.Millisecond,
		ScanRatio:        6,
	}
	kOrig, taskOrig, root := bootTestKernelWithInitTask(t, opts)
	sctx := kOrig.SupervisorContext()
	creds := auth.CredentialsFromContext(sctx)
	vfsObj := kOrig.VFS()
	fs := kOrig.Cgroup2FS().(*filesystem)
	t.Cleanup(fs.releaseXplat)

	// 1. "io" appears in root cgroup.controllers and can be enabled in subtree_control.
	ctrls := readCgroupPath(t, taskOrig, vfsObj, creds, root, "/cgroup/cgroup.controllers")
	if !strings.Contains(ctrls, "io") {
		t.Fatalf("root cgroup.controllers = %q, want io", ctrls)
	}
	// showAtRoot: root exposes io.stat, but not io.weight or io.max.
	for _, absent := range []string{"/cgroup/io.weight", "/cgroup/io.max"} {
		pop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(absent)}
		if fd, err := vfsObj.OpenAt(sctx, creds, pop, &vfs.OpenOptions{Flags: linux.O_RDONLY}); !linuxerr.Equals(linuxerr.ENOENT, err) {
			if fd != nil {
				fd.DecRef(sctx)
			}
			t.Fatalf("root OpenAt(%q) = %v, want ENOENT", absent, err)
		}
	}
	writeCgroupFile(t, sctx, vfsObj, creds, root, "/cgroup/cgroup.subtree_control", "+io\n")
	for _, dir := range []string{"/cgroup/a", "/cgroup/b"} {
		if err := vfsObj.MkdirAt(sctx, creds, &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(dir)}, &vfs.MkdirOptions{Mode: 0o755}); err != nil {
			t.Fatalf("MkdirAt(%q): %v", dir, err)
		}
	}

	// Register two virtual block devices (vda 254:0, vdb 254:16).
	reg := blockdev.Of(vfsObj)
	devA, err := reg.Add(blockdev.Options{Stats: blockdev.NewStats(nil), SectorsCount: 1024})
	if err != nil {
		t.Fatalf("reg.Add(vda): %v", err)
	}
	devB, err := reg.Add(blockdev.Options{Stats: blockdev.NewStats(nil), SectorsCount: 2048})
	if err != nil {
		t.Fatalf("reg.Add(vdb): %v", err)
	}

	// Move taskOrig into /a and account reads/writes/discards on both devices.
	taskCtx := taskOrig.AsyncContext()
	writeCgroupFile(t, taskCtx, vfsObj, creds, root, "/cgroup/a/cgroup.procs", "1\n")
	devB.AccountIO(taskCtx, blockdev.Write, 4096, 1)
	devB.AccountIO(taskCtx, blockdev.Write, 8192, 1)
	devB.AccountIO(taskCtx, blockdev.Read, 2048, 1)
	devB.AccountIO(taskCtx, blockdev.Discard, 4096, 1)
	devA.Stats.AccountIO(taskCtx, blockdev.Read, 1024, 1)

	gotA := readCgroupPath(t, taskOrig, vfsObj, creds, root, "/cgroup/a/io.stat")
	wantA := "254:0 rbytes=1024 wbytes=0 rios=1 wios=0 dbytes=0 dios=0\n254:16 rbytes=2048 wbytes=12288 rios=1 wios=2 dbytes=4096 dios=1\n"
	if gotA != wantA {
		t.Fatalf("/a/io.stat =\n%q\nwant:\n%q", gotA, wantA)
	}

	// Sibling /b must remain empty.
	if gotB := readCgroupPath(t, taskOrig, vfsObj, creds, root, "/cgroup/b/io.stat"); gotB != "" {
		t.Fatalf("/b/io.stat = %q, want empty", gotB)
	}

	// Move taskOrig to /b and charge /b; root must show sum of /a + /b.
	writeCgroupFile(t, taskCtx, vfsObj, creds, root, "/cgroup/b/cgroup.procs", "1\n")
	devB.AccountIO(taskCtx, blockdev.Write, 512, 1)
	gotRoot := readCgroupPath(t, taskOrig, vfsObj, creds, root, "/cgroup/io.stat")
	wantRoot := "254:0 rbytes=1024 wbytes=0 rios=1 wios=0 dbytes=0 dios=0\n254:16 rbytes=2048 wbytes=12800 rios=1 wios=3 dbytes=4096 dios=1\n"
	if gotRoot != wantRoot {
		t.Fatalf("root io.stat =\n%q\nwant:\n%q", gotRoot, wantRoot)
	}

	// 2. io.weight and io.max parse, update, delete, and reject invalid input.
	if got := readCgroupPath(t, taskOrig, vfsObj, creds, root, "/cgroup/a/io.weight"); got != "default 100\n" {
		t.Fatalf("initial io.weight = %q, want default 100", got)
	}
	writeCgroupFile(t, sctx, vfsObj, creds, root, "/cgroup/a/io.weight", "300\n")
	if got := readCgroupPath(t, taskOrig, vfsObj, creds, root, "/cgroup/a/io.weight"); got != "default 300\n" {
		t.Fatalf("bare io.weight = %q, want default 300", got)
	}
	writeCgroupFile(t, sctx, vfsObj, creds, root, "/cgroup/a/io.weight", "default 250\n")
	writeCgroupFile(t, sctx, vfsObj, creds, root, "/cgroup/a/io.weight", "254:16 500\n")
	if got := readCgroupPath(t, taskOrig, vfsObj, creds, root, "/cgroup/a/io.weight"); got != "default 250\n254:16 500\n" {
		t.Fatalf("updated io.weight = %q", got)
	}
	writeCgroupFile(t, sctx, vfsObj, creds, root, "/cgroup/a/io.weight", "254:16 default\n")
	if got := readCgroupPath(t, taskOrig, vfsObj, creds, root, "/cgroup/a/io.weight"); got != "default 250\n" {
		t.Fatalf("reset device io.weight = %q, want default 250", got)
	}
	writeCgroupFile(t, sctx, vfsObj, creds, root, "/cgroup/a/io.weight", "254:16 500\n")
	for _, bad := range []string{"0", "10001", "254:16 0", "bad:dev 100", "a b c"} {
		if err := writeCgroupFileErr(taskOrig, vfsObj, creds, root, "/cgroup/a/io.weight", bad); !linuxerr.Equals(linuxerr.EINVAL, err) {
			t.Fatalf("io.weight(%q) err = %v, want EINVAL", bad, err)
		}
	}

	writeCgroupFile(t, sctx, vfsObj, creds, root, "/cgroup/a/io.max", "254:16 wbps=1048576 riops=100\n")
	writeCgroupFile(t, sctx, vfsObj, creds, root, "/cgroup/a/io.max", "254:16 rbps=2097152\n")
	if got := readCgroupPath(t, taskOrig, vfsObj, creds, root, "/cgroup/a/io.max"); got != "254:16 rbps=2097152 wbps=1048576 riops=100 wiops=max\n" {
		t.Fatalf("updated io.max = %q", got)
	}
	writeCgroupFile(t, sctx, vfsObj, creds, root, "/cgroup/a/io.max", "254:16 rbps=max wbps=max riops=max wiops=max\n")
	if got := readCgroupPath(t, taskOrig, vfsObj, creds, root, "/cgroup/a/io.max"); got != "" {
		t.Fatalf("cleared io.max = %q, want empty", got)
	}
	writeCgroupFile(t, sctx, vfsObj, creds, root, "/cgroup/a/io.max", "254:16 rbps=2097152 wbps=1048576 riops=100\n")
	for _, bad := range []string{"254:16", "bad wbps=1", "254:16 unknown=1", "254:16 wbps=-1"} {
		if err := writeCgroupFileErr(taskOrig, vfsObj, creds, root, "/cgroup/a/io.max", bad); !linuxerr.Equals(linuxerr.EINVAL, err) {
			t.Fatalf("io.max(%q) err = %v, want EINVAL", bad, err)
		}
	}

	// 3. Save and restore kernel, verify io.stat/io.weight/io.max persist and
	// post-restore I/O continues charging restored cgroups.
	var ckpt bytes.Buffer
	if err := kOrig.SaveTo(sctx, nopWriteCloser{Writer: &ckpt}, nil, nil, false, true, nil, vfs.PrepareSaveOptions{}, nil); err != nil {
		t.Fatalf("Kernel.SaveTo: %v", err)
	}
	kOrig.BeforeResume(sctx)

	mfRestored := newTestKernelMemoryFile(t, "cgroup2fs-io-restored")
	kRestored := &kernel.Kernel{Platform: testSRPlatform{}}
	kRestored.SetMemoryFile(mfRestored)
	restoreCtx := kRestored.SupervisorContext()
	if err := kRestored.LoadFrom(restoreCtx, bytes.NewReader(ckpt.Bytes()), nil, nil, nil, sentrytime.NewCalibratedClocks(false), &vfs.CompleteRestoreOptions{}, nil); err != nil {
		t.Fatalf("Kernel.LoadFrom: %v", err)
	}
	t.Cleanup(func() { kRestored.Timekeeper().Destroy() })
	restoredFS := kRestored.Cgroup2FS().(*filesystem)
	t.Cleanup(restoredFS.releaseXplat)

	restoredTasks := kRestored.TaskSet().Root.Tasks()
	if len(restoredTasks) != 1 {
		t.Fatalf("restored task count = %d, want 1", len(restoredTasks))
	}
	restoredTask := restoredTasks[0]

	// Read saved /a io.stat, io.weight, io.max via Cgroup2.ReadControl.
	cgA, err := restoredFS.FindCgroup(restoreCtx, "/a")
	if err != nil {
		t.Fatalf("FindCgroup(/a): %v", err)
	}
	if got, err := cgA.ReadControl(restoreCtx, "io.stat"); err != nil || got != wantA {
		t.Fatalf("restored /a io.stat = (%q, %v), want %q", got, err, wantA)
	}
	if got, err := cgA.ReadControl(restoreCtx, "io.weight"); err != nil || got != "default 250\n254:16 500\n" {
		t.Fatalf("restored /a io.weight = (%q, %v)", got, err)
	}
	if got, err := cgA.ReadControl(restoreCtx, "io.max"); err != nil || got != "254:16 rbps=2097152 wbps=1048576 riops=100 wiops=max\n" {
		t.Fatalf("restored /a io.max = (%q, %v)", got, err)
	}

	// Post-restore I/O on restored blockdev.Device charges restored /b and root.
	restoredDevB := blockdev.Of(kRestored.VFS()).Find("vdb")
	if restoredDevB == nil {
		t.Fatal("restored blockdev vdb missing")
	}
	restoredDevB.AccountIO(restoredTask.AsyncContext(), blockdev.Write, 4096, 1)
	cgB, err := restoredFS.FindCgroup(restoreCtx, "/b")
	if err != nil {
		t.Fatalf("FindCgroup(/b): %v", err)
	}
	if got, err := cgB.ReadControl(restoreCtx, "io.stat"); err != nil || got != "254:16 rbytes=0 wbytes=4608 rios=0 wios=2 dbytes=0 dios=0\n" {
		t.Fatalf("post-restore /b io.stat = (%q, %v)", got, err)
	}
	if got, err := restoredFS.RootCgroup().ReadControl(restoreCtx, "io.stat"); err != nil || !strings.Contains(got, "254:16 rbytes=2048 wbytes=16896 rios=1 wios=4 dbytes=4096 dios=1") {
		t.Fatalf("post-restore root io.stat = (%q, %v)", got, err)
	}

	// 4. Disabling (-io) removes child interface files, causes ENODEV on stale
	// FDs, preserves root historical totals, charges root while disabled, and
	// re-enabling (+io) creates a fresh child controller.
	staleFD := openCgroupRead(t, sctx, vfsObj, creds, root, "/cgroup/b/io.stat")
	writeCgroupFile(t, sctx, vfsObj, creds, root, "/cgroup/cgroup.subtree_control", "-io\n")
	buf := make([]byte, 256)
	if _, err := staleFD.PRead(sctx, usermem.BytesIOSequence(buf), 0, vfs.ReadOptions{}); !linuxerr.Equals(linuxerr.ENODEV, err) {
		staleFD.DecRef(sctx)
		t.Fatalf("stale /b/io.stat PRead after -io = %v, want ENODEV", err)
	}
	staleFD.DecRef(sctx)
	for _, removed := range []string{"/cgroup/b/io.stat", "/cgroup/b/io.weight", "/cgroup/b/io.max"} {
		pop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(removed)}
		if fd, err := vfsObj.OpenAt(sctx, creds, pop, &vfs.OpenOptions{Flags: linux.O_RDONLY}); !linuxerr.Equals(linuxerr.ENOENT, err) {
			if fd != nil {
				fd.DecRef(sctx)
			}
			t.Fatalf("OpenAt(%q) after -io = %v, want ENOENT", removed, err)
		}
	}
	// I/O while -io is disabled still charges root via closestCtrls.
	devB.AccountIO(taskCtx, blockdev.Write, 1024, 1)
	if got := readCgroupPath(t, taskOrig, vfsObj, creds, root, "/cgroup/io.stat"); !strings.Contains(got, "254:16 rbytes=2048 wbytes=13824 rios=1 wios=4") {
		t.Fatalf("root io.stat after disabled-child I/O = %q", got)
	}
	// Re-enabling +io gives /b a fresh counter starting at 0.
	writeCgroupFile(t, sctx, vfsObj, creds, root, "/cgroup/cgroup.subtree_control", "+io\n")
	if got := readCgroupPath(t, taskOrig, vfsObj, creds, root, "/cgroup/b/io.stat"); got != "" {
		t.Fatalf("/b/io.stat right after +io re-enable = %q, want empty", got)
	}
	devB.AccountIO(taskCtx, blockdev.Write, 2048, 1)
	if got := readCgroupPath(t, taskOrig, vfsObj, creds, root, "/cgroup/b/io.stat"); got != "254:16 rbytes=0 wbytes=2048 rios=0 wios=1 dbytes=0 dios=0\n" {
		t.Fatalf("/b/io.stat after +io re-enable write = %q", got)
	}
}
