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

//go:build linux || darwin

package gvx

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
)

const (
	mpLockdownRoleEnv = "GVX_HOSTFS_MP_ROLE"
	mpLockdownDirEnv  = "GVX_HOSTFS_MP_DIR"
	mpLockdownIDEnv   = "GVX_HOSTFS_MP_ID"
)

// TestMultiProcessHostlockdownWorker is invoked only in child OS processes
// spawned by TestMultiProcessConcurrentHostlockdownGitWorktree, because
// hostlockdown.Apply is irreversible for the calling process.
func TestMultiProcessHostlockdownWorker(t *testing.T) {
	role := os.Getenv(mpLockdownRoleEnv)
	if role == "" {
		return
	}
	dir := os.Getenv(mpLockdownDirEnv)
	switch role {
	case "rw-worker":
		id, err := strconv.Atoi(os.Getenv(mpLockdownIDEnv))
		if err != nil {
			t.Fatalf("parse worker id: %v", err)
		}
		runLockedGitWorktreeWorker(t, dir, id)
	case "ro-reader":
		runLockedReadOnlyObserver(t, dir)
	default:
		t.Fatalf("unknown role %q", role)
	}
}

func runLockedGitWorktreeWorker(t *testing.T, dir string, id int) {
	ws, err := hostfs.OpenWorkspace(dir, false)
	if err != nil {
		t.Fatalf("OpenWorkspace: %v", err)
	}
	defer func() {
		if cerr := ws.Close(); cerr != nil {
			t.Fatalf("Workspace.Close: %v", cerr)
		}
	}()

	st, err := applyHostfsTestLockdown(dir, false)
	if err != nil {
		t.Fatalf("applyHostfsTestLockdown: %v", err)
	}
	if !st.SubprocessBlocked || !st.UnboundFileOpenBlocked {
		t.Fatalf("hostlockdown status = %+v, want SubprocessBlocked && UnboundFileOpenBlocked", st)
	}

	// Force fresh OS thread creation after lockdown so missing thread clone
	// flags fail deterministically instead of depending on scheduler timing.
	lockedThreads := min(runtime.GOMAXPROCS(0)+4, 16)
	var threadReady, threadDone sync.WaitGroup
	releaseThreads := make(chan struct{})
	threadReady.Add(lockedThreads)
	threadDone.Add(lockedThreads)
	for range lockedThreads {
		go func() {
			defer threadDone.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			threadReady.Done()
			<-releaseThreads
		}()
	}
	threadReady.Wait()
	close(releaseThreads)
	threadDone.Wait()

	// Signal readiness and wait for parent barrier so both locked child processes
	// hammer .gvx_meta simultaneously.
	fmt.Println("READY")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "GO" {
		t.Fatalf("barrier read = (%q, %v), want GO", line, err)
	}

	wtDir := fmt.Sprintf("worktrees/container-%d", id)
	if err := ws.MkdirAll(wtDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", wtDir, err)
	}
	if err := ws.MkdirAll("refs/heads/wt", 0o755); err != nil {
		t.Fatalf("MkdirAll(refs/heads/wt): %v", err)
	}
	if err := ws.MkdirAll("hooks", 0o755); err != nil {
		t.Fatalf("MkdirAll(hooks): %v", err)
	}
	if err := ws.MkdirAll(fmt.Sprintf("objects/%02x", 0xa0+id), 0o755); err != nil {
		t.Fatalf("MkdirAll(objects): %v", err)
	}

	if err := ws.WriteFile(wtDir+"/commondir", []byte("../..\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(commondir): %v", err)
	}
	if err := ws.WriteFile(wtDir+"/gitdir", []byte("/workspace/.git\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(gitdir): %v", err)
	}
	if err := ws.WriteFile(wtDir+"/HEAD", []byte(fmt.Sprintf("ref: refs/heads/wt/c%d\n", id)), 0o644); err != nil {
		t.Fatalf("WriteFile(HEAD): %v", err)
	}

	const rounds = 18
	for r := range rounds {
		refPath := fmt.Sprintf("refs/heads/wt/c%d-r%02d", id, r)
		sha := fmt.Sprintf("%040x\n", (id+1)*1000+r)
		if err := ws.WriteFile(refPath, []byte(sha), 0o644); err != nil {
			t.Fatalf("WriteFile(%s): %v", refPath, err)
		}

		hookPath := fmt.Sprintf("hooks/post-commit-%d-%02d", id, r)
		if err := ws.WriteFile(hookPath, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
			t.Fatalf("WriteFile(%s): %v", hookPath, err)
		}
		if err := ws.Chmod(hookPath, 0o755); err != nil {
			t.Fatalf("Chmod(%s): %v", hookPath, err)
		}
		if err := ws.Chown(hookPath, uint32(500+id), uint32(600+r)); err != nil {
			t.Fatalf("Chown(%s): %v", hookPath, err)
		}

		objPath := fmt.Sprintf("objects/%02x/blob_%02d", 0xa0+id, r)
		if err := ws.WriteFile(objPath, []byte("git-blob-object"), 0o444); err != nil {
			t.Fatalf("WriteFile(%s): %v", objPath, err)
		}

		symPath := fmt.Sprintf("%s/symref_%02d", wtDir, r)
		if err := ws.Symlink("../../"+refPath, symPath); err != nil {
			t.Fatalf("Symlink(%s): %v", symPath, err)
		}

		lockTmp := fmt.Sprintf("refs/heads/wt/c%d-r%02d.lock", id, r)
		if err := ws.WriteFile(lockTmp, []byte(sha), 0o600); err != nil {
			t.Fatalf("WriteFile(%s): %v", lockTmp, err)
		}
		if err := ws.Sync(); err != nil {
			t.Fatalf("Sync(%d pre-unlink): %v", r, err)
		}
		if err := ws.Unlink(lockTmp); err != nil {
			t.Fatalf("Unlink(%s): %v", lockTmp, err)
		}
		if err := ws.Sync(); err != nil {
			t.Fatalf("Sync(%d): %v", r, err)
		}
	}
	fmt.Println("DONE")
}

func runLockedReadOnlyObserver(t *testing.T, dir string) {
	ws, err := hostfs.OpenWorkspace(dir, true)
	if err != nil {
		t.Fatalf("OpenWorkspace(RO): %v", err)
	}
	defer func() {
		if cerr := ws.Close(); cerr != nil {
			t.Fatalf("RO Workspace.Close: %v", cerr)
		}
	}()

	st, err := applyHostfsTestLockdown(dir, true)
	if err != nil {
		t.Fatalf("applyHostfsTestLockdown(RO): %v", err)
	}
	if !st.SubprocessBlocked || !st.UnboundFileOpenBlocked {
		t.Fatalf("RO hostlockdown status = %+v, want SubprocessBlocked && UnboundFileOpenBlocked", st)
	}

	fmt.Println("READY")
	rd := bufio.NewReader(os.Stdin)
	line, err := rd.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "CHECK" {
		t.Fatalf("observer command = (%q, %v), want CHECK", line, err)
	}

	for id := range 2 {
		for r := range 18 {
			hookPath := fmt.Sprintf("hooks/post-commit-%d-%02d", id, r)
			attr, _, err := ws.Stat(hookPath)
			if err != nil || attr.Mode&0o7777 != 0o755 || attr.UID != uint32(500+id) || attr.GID != uint32(600+r) {
				t.Fatalf("RO observer Stat(%s) = (%+v, %v), want mode 0755 owner %d:%d", hookPath, attr, err, 500+id, 600+r)
			}
			symPath := fmt.Sprintf("worktrees/container-%d/symref_%02d", id, r)
			wantTarget := fmt.Sprintf("../../refs/heads/wt/c%d-r%02d", id, r)
			if got, err := ws.Readlink(symPath); err != nil || got != wantTarget {
				t.Fatalf("RO observer Readlink(%s) = (%q, %v), want %q", symPath, got, err, wantTarget)
			}
		}
	}
	fmt.Println("VERIFIED")
}

// TestMultiProcessConcurrentHostlockdownGitWorktree spawns two locked-down RW
// child processes plus one locked-down RO observer process sharing one bare-repo
// hostfs workspace and verifies zero EPERM/SIGSYS failures and 100% metadata
// preservation across concurrent Git worktree ref/hook/object/symlink flushes.
func TestMultiProcessConcurrentHostlockdownGitWorktree(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	type childProc struct {
		cmd    *exec.Cmd
		stdin  io.WriteCloser
		stdout *bufio.Reader
		stderr *strings.Builder
		mu     sync.Mutex
	}
	spawn := func(role string, extraEnv ...string) *childProc {
		cmd := exec.Command(os.Args[0], "-test.run=^TestMultiProcessHostlockdownWorker$")
		env := append(os.Environ(),
			"GORACE=atexit_sleep_ms=0",
			mpLockdownRoleEnv+"="+role,
			mpLockdownDirEnv+"="+dir,
		)
		cmd.Env = append(env, extraEnv...)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatalf("StdinPipe(%s): %v", role, err)
		}
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatalf("StdoutPipe(%s): %v", role, err)
		}
		cp := &childProc{
			cmd:    cmd,
			stdin:  stdin,
			stdout: bufio.NewReader(stdoutPipe),
			stderr: &strings.Builder{},
		}
		cmd.Stderr = writerFunc(func(p []byte) (int, error) {
			cp.mu.Lock()
			defer cp.mu.Unlock()
			return cp.stderr.Write(p)
		})
		if err := cmd.Start(); err != nil {
			t.Fatalf("start %s: %v", role, err)
		}
		t.Cleanup(func() {
			_ = stdin.Close()
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			_ = cmd.Wait()
		})
		return cp
	}
	errDump := func(cp *childProc) string {
		rest, _ := io.ReadAll(cp.stdout)
		cp.mu.Lock()
		defer cp.mu.Unlock()
		return "stdout-rest:\n" + string(rest) + "\nstderr:\n" + cp.stderr.String()
	}

	w0 := spawn("rw-worker", mpLockdownIDEnv+"=0")
	w1 := spawn("rw-worker", mpLockdownIDEnv+"=1")
	for idx, w := range []*childProc{w0, w1} {
		line, err := w.stdout.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "READY" {
			t.Fatalf("worker %d ready = (%q, %v)\nstderr:\n%s", idx, line, err, errDump(w))
		}
	}

	// Open the RO observer AFTER the RW workers initialized .gvx_meta.lock so
	// the locked-down RO observer exercises LOCK_SH on .gvx_meta.lock post-Apply!
	ro := spawn("ro-reader")
	if line, err := ro.stdout.ReadString('\n'); err != nil || strings.TrimSpace(line) != "READY" {
		t.Fatalf("ro-reader ready = (%q, %v)\nstderr:\n%s", line, err, errDump(ro))
	}

	// Release both locked-down RW workers simultaneously.
	for _, w := range []*childProc{w0, w1} {
		if _, err := io.WriteString(w.stdin, "GO\n"); err != nil {
			t.Fatalf("send GO: %v", err)
		}
	}
	for idx, w := range []*childProc{w0, w1} {
		line, err := w.stdout.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "DONE" {
			t.Fatalf("worker %d done = (%q, %v)\nstderr:\n%s", idx, line, err, errDump(w))
		}
		_ = w.stdin.Close()
		if err := w.cmd.Wait(); err != nil {
			t.Fatalf("worker %d exit = %v\nstderr:\n%s", idx, err, errDump(w))
		}
	}

	// Trigger the locked-down RO observer to refresh .gvx_meta under LOCK_SH!
	if _, err := io.WriteString(ro.stdin, "CHECK\n"); err != nil {
		t.Fatalf("send CHECK to ro-reader: %v", err)
	}
	if line, err := ro.stdout.ReadString('\n'); err != nil || strings.TrimSpace(line) != "VERIFIED" {
		t.Fatalf("ro-reader verify = (%q, %v)\nstderr:\n%s", line, err, errDump(ro))
	}
	_ = ro.stdin.Close()
	if err := ro.cmd.Wait(); err != nil {
		t.Fatalf("ro-reader exit = %v\nstderr:\n%s", err, errDump(ro))
	}

	// Also independently verify on-disk .gvx_meta from the parent process.
	metaMap, err := hostfs.ReadMeta(filepath.Join(dir, hostfs.MetaFileName))
	if err != nil {
		t.Fatalf("parent ReadMeta: %v", err)
	}
	for id := range 2 {
		for r := range 18 {
			hookPath := fmt.Sprintf("hooks/post-commit-%d-%02d", id, r)
			attr, ok := metaMap[hookPath]
			if !ok || attr.Mode&0o7777 != 0o755 || attr.UID != uint32(500+id) || attr.GID != uint32(600+r) {
				t.Fatalf("parent ReadMeta[%s] = (%+v, %v), want mode 0755 owner %d:%d", hookPath, attr, ok, 500+id, 600+r)
			}
			lockTmp := fmt.Sprintf("refs/heads/wt/c%d-r%02d.lock", id, r)
			if leaked, exists := metaMap[lockTmp]; exists {
				t.Fatalf("unlinked ref lock %s survived in .gvx_meta: %+v", lockTmp, leaked)
			}
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
