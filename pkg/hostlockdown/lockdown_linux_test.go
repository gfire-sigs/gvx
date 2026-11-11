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

//go:build linux

package hostlockdown

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	"z.gfire.dev/gvx/internal/xsys/unix"

	"z.gfire.dev/gvx/pkg/seccomp"
)

// childEnv marks the process that applies the lockdown. Landlock and seccomp
// are irreversible, so each case that calls Apply runs in its own child of the
// test binary.
const childEnv = "GVX_HOSTLOCKDOWN_CHILD"

// runChild runs the named test in a child process and returns its output.
func runChild(t *testing.T, name string, env ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+name+"$", "-test.v")
	cmd.Env = append(os.Environ(), append([]string{childEnv + "=1"}, env...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func isAccessDenied(err error) bool {
	return errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM)
}

// installTestFilter returns a filter that allows every system call except the
// ones that Apply probes. Those return EPERM, as the filter of pkg/gvx does.
// With allowDirfdOpen, opens relative to a non-negative directory descriptor
// stay allowed in seccomp so the tests verify Landlock path containment.
func installTestFilter(allowDirfdOpen bool) func() error {
	return func() error {
		rejected := seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
			unix.SYS_EXECVE:   seccomp.MatchAll{},
			unix.SYS_EXECVEAT: seccomp.MatchAll{},
			unix.SYS_CLONE:    seccomp.MatchAll{},
			unix.SYS_SOCKET:   seccomp.MatchAll{},
			unix.SYS_OPENAT:   seccomp.MatchAll{},
		})
		const runtimeThread = unix.CLONE_VM |
			unix.CLONE_FS |
			unix.CLONE_FILES |
			unix.CLONE_SIGHAND |
			unix.CLONE_SYSVSEM |
			unix.CLONE_THREAD
		const libcThread = runtimeThread |
			unix.CLONE_SETTLS |
			unix.CLONE_PARENT_SETTID |
			unix.CLONE_CHILD_CLEARTID
		sets := []seccomp.RuleSet{
			{
				Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
					unix.SYS_CLONE: seccomp.Or{
						seccomp.PerArg{seccomp.EqualTo(runtimeThread)},
						seccomp.PerArg{seccomp.EqualTo(runtimeThread | unix.CLONE_SETTLS)},
						seccomp.PerArg{seccomp.EqualTo(libcThread)},
						seccomp.PerArg{seccomp.EqualTo(libcThread | unix.CLONE_DETACHED)},
					},
				}),
				Action: seccomp.Allow,
			},
		}
		if allowDirfdOpen {
			sets = append(sets, seccomp.RuleSet{
				Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
					unix.SYS_OPENAT: seccomp.PerArg{seccomp.NonNegativeFD{}},
					unix.SYS_OPENAT2: seccomp.PerArg{
						seccomp.NonNegativeFD{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.EqualTo(unix.SizeofOpenHow),
					},
				}),
				Action: seccomp.Allow,
			})
		}
		sets = append(sets, seccomp.RuleSet{Rules: rejected, Action: seccomp.ReturnError.Code(uint16(unix.EPERM))})
		program := &seccomp.Program{
			RuleSets: sets,
			Options:  seccomp.ProgramOptions{DefaultAction: seccomp.Allow},
		}
		return program.Install(nil)
	}
}

func TestLandlockHandledAccessFSMasksByABI(t *testing.T) {
	if got := landlockHandledAccessFS(0); got != 0 {
		t.Fatalf("landlockHandledAccessFS(0) = %#x, want 0", got)
	}
	v1 := landlockHandledAccessFS(1)
	if v1 != 0x1fff {
		t.Fatalf("ABI v1 mask = %#x, want 0x1fff", v1)
	}
	v2 := landlockHandledAccessFS(2)
	if v2 != (v1 | unix.LANDLOCK_ACCESS_FS_REFER) {
		t.Fatalf("ABI v2 mask = %#x, want %#x", v2, v1|unix.LANDLOCK_ACCESS_FS_REFER)
	}
	v3 := landlockHandledAccessFS(3)
	if v3 != (v2 | unix.LANDLOCK_ACCESS_FS_TRUNCATE) {
		t.Fatalf("ABI v3 mask = %#x, want %#x", v3, v2|unix.LANDLOCK_ACCESS_FS_TRUNCATE)
	}
	if v4 := landlockHandledAccessFS(4); v4 != v3 {
		t.Fatalf("ABI v4 FS mask = %#x, want %#x", v4, v3)
	}
	v5 := landlockHandledAccessFS(5)
	if v5 != (v3 | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV) {
		t.Fatalf("ABI v5 mask = %#x, want %#x", v5, v3|unix.LANDLOCK_ACCESS_FS_IOCTL_DEV)
	}
	if v6 := landlockHandledAccessFS(6); v6 != v5 {
		t.Fatalf("ABI v6 FS mask = %#x, want %#x", v6, v5)
	}
}

func TestLandlockMountAccessFSConfinesFileToFileBits(t *testing.T) {
	const dirOnlyBits = unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM |
		unix.LANDLOCK_ACCESS_FS_REFER

	for _, abi := range []int{1, 2, 3, 4, 5, 6} {
		handled := landlockHandledAccessFS(abi)
		fileRO := landlockMountAccessFS(handled, true, true)
		if fileRO&dirOnlyBits != 0 || fileRO&^handled != 0 {
			t.Fatalf("ABI v%d read-only file mask = %#x, contains invalid bits", abi, fileRO)
		}
		if fileRO != (unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE) {
			t.Fatalf("ABI v%d read-only file mask = %#x, want EXECUTE|READ_FILE", abi, fileRO)
		}

		fileRW := landlockMountAccessFS(handled, false, true)
		if fileRW&dirOnlyBits != 0 || fileRW&^handled != 0 {
			t.Fatalf("ABI v%d writable file mask = %#x, contains directory or unhandled bits", abi, fileRW)
		}
		wantTrunc := uint64(0)
		if abi >= 3 {
			wantTrunc = unix.LANDLOCK_ACCESS_FS_TRUNCATE
		}
		wantFileRW := unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | wantTrunc
		if fileRW != wantFileRW {
			t.Fatalf("ABI v%d writable file mask = %#x, want %#x", abi, fileRW, wantFileRW)
		}

		dirRO := landlockMountAccessFS(handled, true, false)
		if dirRO != (unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR) {
			t.Fatalf("ABI v%d read-only dir mask = %#x, want EXECUTE|READ_FILE|READ_DIR", abi, dirRO)
		}
		dirRW := landlockMountAccessFS(handled, false, false)
		if dirRW&^handled != 0 || dirRW&unix.LANDLOCK_ACCESS_FS_WRITE_FILE == 0 || dirRW&unix.LANDLOCK_ACCESS_FS_MAKE_REG == 0 {
			t.Fatalf("ABI v%d writable dir mask = %#x, missing write bits or exceeds handled %#x", abi, dirRW, handled)
		}
	}
}

func TestLinuxApplyProbesAndEnforcesTheFilter(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		out, err := runChild(t, "TestLinuxApplyProbesAndEnforcesTheFilter")
		if err != nil {
			t.Fatalf("child failed: %v\n%s", err, out)
		}
		return
	}
	st, err := Apply(Options{InstallSyscallFilter: installTestFilter(false)})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !st.Applied || !st.SubprocessBlocked || !st.UnboundFileOpenBlocked || !st.NetworkOutboundBlocked {
		t.Fatalf("Status = %+v, want applied with the subprocess, open, and network blocks", st)
	}
	if !IsLockedDown() {
		t.Error("IsLockedDown() = false after Apply")
	}
	if _, err := os.ReadFile("/etc/hostname"); !errors.Is(err, unix.EPERM) {
		t.Errorf("ReadFile after lockdown = %v, want EPERM", err)
	}
	if err := exec.Command("/bin/true").Run(); err == nil {
		t.Error("exec.Command(/bin/true) succeeded after lockdown")
	}
	if c, err := net.Dial("tcp", "127.0.0.1:1"); err == nil {
		_ = c.Close()
		t.Error("net.Dial succeeded after lockdown")
	}
}

func TestLinuxApplyWithWorkspaceConfinesDirectoryDescriptorOpens(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		out, err := runChild(
			t,
			"TestLinuxApplyWithWorkspaceConfinesDirectoryDescriptorOpens",
			"GVX_WORKSPACE="+t.TempDir(),
			"GVX_OUTSIDE="+t.TempDir(),
		)
		if err != nil {
			t.Fatalf("child failed: %v\n%s", err, out)
		}
		return
	}
	workspace := os.Getenv("GVX_WORKSPACE")
	outside := os.Getenv("GVX_OUTSIDE")
	if err := os.WriteFile(filepath.Join(workspace, "inside.txt"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	realWS, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal(err)
	}
	realSecret, err := filepath.EvalSymlinks(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	relToSecret, err := filepath.Rel(realWS, realSecret)
	if err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	wsFD, err := unix.Open(realWS, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(wsFD)
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)

	// Start ensureSigM before Apply, matching cmd/rungv signal.NotifyContext.
	sigCtx, stopSig := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSig()
	_ = sigCtx

	// Park a dedicated OS thread across Apply so it never schedules new
	// goroutines during lockdown, mirroring runtime.sysmon or a C pthread.
	parkedReady := make(chan int, 1)
	parkedRelease := make(chan struct{})
	parkedDone := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tidBefore := unix.Gettid()
		parkedReady <- tidBefore
		<-parkedRelease
		if tidAfter := unix.Gettid(); tidAfter != tidBefore {
			parkedDone <- errors.New("parked goroutine changed OS thread")
			return
		}
		if runtime.GOOS == "android" {
			parkedDone <- nil
			return
		}
		fd, openErr := unix.Openat(wsFD, relToSecret, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr == nil {
			_ = unix.Close(fd)
			parkedDone <- errors.New("parked OS thread escaped workspace after lockdown")
			return
		}
		if !isAccessDenied(openErr) {
			parkedDone <- openErr
			return
		}
		parkedDone <- nil
	}()
	<-parkedReady

	st, err := Apply(Options{
		Mounts:               []HostMount{{Path: workspace}},
		AllowOutboundNet:     true,
		InstallSyscallFilter: installTestFilter(true),
	})
	close(parkedRelease)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if parkedErr := <-parkedDone; parkedErr != nil {
		t.Fatalf("parked OS thread check: %v", parkedErr)
	}
	if !st.Applied || !st.SubprocessBlocked {
		t.Errorf("Status = %+v, want Applied and SubprocessBlocked", st)
	}
	wantUnbound := runtime.GOOS != "android"
	if st.UnboundFileOpenBlocked != wantUnbound {
		t.Errorf("UnboundFileOpenBlocked = %v, want %v", st.UnboundFileOpenBlocked, wantUnbound)
	}
	if st.NetworkOutboundBlocked {
		t.Error("NetworkOutboundBlocked = true with AllowOutboundNet")
	}

	// Reading and writing inside the mounted workspace must succeed.
	if f, err := root.Open("inside.txt"); err != nil {
		t.Errorf("open inside.txt through workspace root after lockdown: %v", err)
	} else {
		_ = f.Close()
	}
	wfd, err := unix.Openat(wsFD, "created.txt", unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatalf("create file inside mounted workspace after lockdown: %v", err)
	}
	if _, err := unix.Write(wfd, []byte("written-in-ws")); err != nil {
		_ = unix.Close(wfd)
		t.Fatalf("write file inside mounted workspace: %v", err)
	}
	_ = unix.Close(wfd)

	rfd, err := unix.Openat(wsFD, "created.txt", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("reopen created.txt inside mounted workspace: %v", err)
	}
	buf := make([]byte, 32)
	n, err := unix.Read(rfd, buf)
	_ = unix.Close(rfd)
	if err != nil || string(buf[:n]) != "written-in-ws" {
		t.Errorf("read created.txt = (%q, %v), want written-in-ws", string(buf[:n]), err)
	}

	if _, err := os.ReadFile("/etc/passwd"); !errors.Is(err, unix.EPERM) {
		t.Errorf("ReadFile(/etc/passwd) = %v, want EPERM from seccomp", err)
	}

	if runtime.GOOS == "android" {
		return
	}

	// Descriptor-relative escapes through "/" and through "../" from wsFD must
	// fail on every Go thread.
	for _, probe := range []struct {
		label string
		dirfd int
		path  string
	}{
		{"rootFD etc/passwd", rootFD, "etc/passwd"},
		{"rootFD outside secret", rootFD, strings.TrimPrefix(realSecret, "/")},
		{"wsFD parent traversal", wsFD, relToSecret},
	} {
		fd, openErr := unix.Openat(probe.dirfd, probe.path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr == nil {
			_ = unix.Close(fd)
			t.Errorf("%s succeeded after lockdown", probe.label)
			continue
		}
		if probe.path == "etc/passwd" && errors.Is(openErr, unix.ENOENT) {
			continue
		}
		if !isAccessDenied(openErr) {
			t.Errorf("%s = %v, want EACCES or EPERM", probe.label, openErr)
		}
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fd, openErr := unix.Openat(wsFD, relToSecret, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if openErr == nil {
				_ = unix.Close(fd)
				t.Errorf("worker goroutine escaped workspace via %q", relToSecret)
				return
			}
			if !isAccessDenied(openErr) {
				t.Errorf("worker goroutine escape error = %v, want EACCES or EPERM", openErr)
			}
		}()
	}
	wg.Wait()
}

func TestLinuxApplyWithSingleFileMountBlocksSiblingFiles(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		out, err := runChild(t, "TestLinuxApplyWithSingleFileMountBlocksSiblingFiles", "GVX_DIR="+t.TempDir())
		if err != nil {
			t.Fatalf("child failed: %v\n%s", err, out)
		}
		return
	}
	dir := os.Getenv("GVX_DIR")
	targetPath := filepath.Join(dir, "target.txt")
	siblingPath := filepath.Join(dir, "sibling.txt")
	if err := os.WriteFile(targetPath, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(siblingPath, []byte("secret-sibling"), 0o600); err != nil {
		t.Fatal(err)
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	parentFD, err := unix.Open(realDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parentFD)

	st, err := Apply(Options{
		Mounts:               []HostMount{{Path: targetPath, File: true}},
		AllowOutboundNet:     true,
		InstallSyscallFilter: installTestFilter(true),
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if st.UnboundFileOpenBlocked != (runtime.GOOS != "android") {
		t.Errorf("UnboundFileOpenBlocked = %v, want %v", st.UnboundFileOpenBlocked, runtime.GOOS != "android")
	}

	fd, err := unix.Openat(parentFD, "target.txt", unix.O_RDWR|unix.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open mounted file through parentFD: %v", err)
	}
	if _, err := unix.Write(fd, []byte("after")); err != nil {
		_ = unix.Close(fd)
		t.Fatalf("write mounted file: %v", err)
	}
	_ = unix.Close(fd)

	if runtime.GOOS == "android" {
		return
	}

	if sfd, sErr := unix.Openat(parentFD, "sibling.txt", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); sErr == nil {
		_ = unix.Close(sfd)
		t.Error("open sibling.txt succeeded under single-file mount")
	} else if !isAccessDenied(sErr) {
		t.Errorf("open sibling.txt = %v, want EACCES or EPERM", sErr)
	}
	if nfd, nErr := unix.Openat(parentFD, "created.txt", unix.O_CREAT|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600); nErr == nil {
		_ = unix.Close(nfd)
		t.Error("create file in parent directory of single-file mount succeeded")
	} else if !isAccessDenied(nErr) {
		t.Errorf("create file in parent directory = %v, want EACCES or EPERM", nErr)
	}
}

func TestLinuxApplyWithReadOnlyWorkspaceBlocksWrites(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		out, err := runChild(t, "TestLinuxApplyWithReadOnlyWorkspaceBlocksWrites", "GVX_WORKSPACE="+t.TempDir())
		if err != nil {
			t.Fatalf("child failed: %v\n%s", err, out)
		}
		return
	}
	workspace := os.Getenv("GVX_WORKSPACE")
	if err := os.WriteFile(filepath.Join(workspace, "inside.txt"), []byte("ro-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	realWS, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal(err)
	}
	wsFD, err := unix.Open(realWS, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(wsFD)

	st, err := Apply(Options{
		Mounts:               []HostMount{{Path: workspace, ReadOnly: true}},
		AllowOutboundNet:     true,
		InstallSyscallFilter: installTestFilter(true),
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if st.UnboundFileOpenBlocked != (runtime.GOOS != "android") {
		t.Errorf("UnboundFileOpenBlocked = %v, want %v", st.UnboundFileOpenBlocked, runtime.GOOS != "android")
	}

	rfd, err := unix.Openat(wsFD, "inside.txt", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("read open inside read-only mount failed: %v", err)
	}
	_ = unix.Close(rfd)

	if runtime.GOOS == "android" {
		return
	}

	if wfd, wErr := unix.Openat(wsFD, "inside.txt", unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); wErr == nil {
		_ = unix.Close(wfd)
		t.Error("write open inside read-only mount succeeded")
	} else if !isAccessDenied(wErr) {
		t.Errorf("write open inside read-only mount = %v, want EACCES or EPERM", wErr)
	}
	if cfd, cErr := unix.Openat(wsFD, "new.txt", unix.O_CREAT|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600); cErr == nil {
		_ = unix.Close(cfd)
		t.Error("create file inside read-only mount succeeded")
	} else if !isAccessDenied(cErr) {
		t.Errorf("create file inside read-only mount = %v, want EACCES or EPERM", cErr)
	}
}

func TestLinuxApplyRequiresAFilter(t *testing.T) {
	if _, err := Apply(Options{}); err == nil || !strings.Contains(err.Error(), "InstallSyscallFilter") {
		t.Fatalf("Apply without a filter = %v, want an error that names InstallSyscallFilter", err)
	}
	if IsLockedDown() {
		t.Error("IsLockedDown() = true after a failed Apply")
	}
}

func TestLinuxApplyRejectsAFilterThatLeavesExecOpen(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		out, err := runChild(t, "TestLinuxApplyRejectsAFilterThatLeavesExecOpen")
		if err != nil {
			t.Fatalf("child failed: %v\n%s", err, out)
		}
		return
	}
	_, err := Apply(Options{InstallSyscallFilter: func() error { return nil }})
	if err == nil || !strings.Contains(err.Error(), "execve probe") {
		t.Fatalf("Apply with an empty filter = %v, want the execve probe to fail", err)
	}
	if IsLockedDown() {
		t.Error("IsLockedDown() = true after a failed Apply")
	}
}
