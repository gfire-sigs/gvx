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

package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"unsafe"

	"z.gfire.dev/gvx/internal/systraptest"
	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/gvx"
)

const (
	foreignListenerTest = "TestE2ESystrapUnderForeignSeccompListener"
	foreignListenerEnv  = "GVX_E2E_FOREIGN_LISTENER"
)

// foreignListenerFD keeps the listener of the helper process open until the
// helper process exits.
var foreignListenerFD int

// installForeignListener installs a seccomp filter with a listener in every
// thread of this process. The filter sends only acct(2) to the listener, so
// the process never calls it. Each stub process that the Sentry creates later
// inherits the filter. This is the filter chain of a sandbox nested in a
// sandbox that owns a listener.
func installForeignListener(t *testing.T) {
	t.Helper()
	var auditArch uint32
	switch runtime.GOARCH {
	case "amd64":
		auditArch = linux.AUDIT_ARCH_X86_64
	case "arm64":
		auditArch = linux.AUDIT_ARCH_AARCH64
	default:
		t.Skipf("no audit architecture for %s", runtime.GOARCH)
	}
	const (
		offsetNR   = 0
		offsetArch = 4
	)
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offsetArch},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: auditArch},
		{Code: unix.BPF_RET | unix.BPF_K, K: uint32(linux.SECCOMP_RET_ALLOW)},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offsetNR},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_ACCT},
		{Code: unix.BPF_RET | unix.BPF_K, K: uint32(linux.SECCOMP_RET_USER_NOTIF)},
		{Code: unix.BPF_RET | unix.BPF_K, K: uint32(linux.SECCOMP_RET_ALLOW)},
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatalf("prctl(PR_SET_NO_NEW_PRIVS): %v", err)
	}
	flags := uintptr(linux.SECCOMP_FILTER_FLAG_NEW_LISTENER | linux.SECCOMP_FILTER_FLAG_TSYNC | unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH)
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, linux.SECCOMP_SET_MODE_FILTER, flags, uintptr(unsafe.Pointer(&prog)))
	if errno == unix.ENOSYS || errno == unix.EINVAL {
		t.Skipf("the host kernel does not support SECCOMP_FILTER_FLAG_NEW_LISTENER: %v", errno)
	}
	if errno != 0 {
		t.Fatalf("seccomp(SET_MODE_FILTER, NEW_LISTENER|TSYNC): %v", errno)
	}
	foreignListenerFD = int(fd)
	runtime.KeepAlive(filter)

	// A second listener must fail. Otherwise the filter does not reach the
	// threads of this process, and the test proves nothing.
	allow := []unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: uint32(linux.SECCOMP_RET_ALLOW)}}
	second := unix.SockFprog{Len: uint16(len(allow)), Filter: &allow[0]}
	_, _, errno = unix.Syscall(unix.SYS_SECCOMP, linux.SECCOMP_SET_MODE_FILTER, linux.SECCOMP_FILTER_FLAG_NEW_LISTENER, uintptr(unsafe.Pointer(&second)))
	if errno != unix.EBUSY {
		t.Fatalf("second seccomp listener = %v, want EBUSY", errno)
	}
}

// TestE2ESystrapUnderForeignSeccompListener starts a systrap guest in a process
// that has a seccomp listener from an ancestor. The kernel refuses a second
// listener with EBUSY, so the stub threads must use the futex loop. The test
// runs itself again as a helper process, because the filter cannot leave the
// process that installs it.
func TestE2ESystrapUnderForeignSeccompListener(t *testing.T) {
	if os.Getenv(foreignListenerEnv) == "" {
		systraptest.Require(t)
		cmd := exec.Command(os.Args[0], "-test.run=^"+foreignListenerTest+"$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), foreignListenerEnv+"=1")
		out, err := cmd.CombinedOutput()
		t.Logf("helper output:\n%s", out)
		if err != nil {
			t.Fatalf("the guest did not run under a foreign seccomp listener: %v", err)
		}
		if bytes.Contains(out, []byte("--- SKIP:")) {
			t.Skip("the helper skipped SECCOMP_FILTER_FLAG_NEW_LISTENER")
		}
		return
	}

	// Install the filter before the first systrap call, because the platform
	// forks the source stub process of every later stub when it starts.
	installForeignListener(t)
	elfData, err := testelf.BuildGuestELF64(runtime.GOARCH, 0, "foreign-listener-ok\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64 failed: %v", err)
	}
	code, stdout, backend := runELF(t, gvx.PlatformSystrap, elfData)
	if backend != string(gvx.PlatformSystrap) {
		t.Errorf("backend = %q, want %q", backend, gvx.PlatformSystrap)
	}
	if code != 0 || stdout != "foreign-listener-ok\n" {
		t.Errorf("guest = (%d, %q), want (0, %q)", code, stdout, "foreign-listener-ok\n")
	}
}
