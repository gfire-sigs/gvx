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
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/seccomp"
)

// childEnv marks the process that applies the lockdown. The seccomp filter is
// irreversible, so each case runs in its own child of the test binary.
const childEnv = "GVX_HOSTLOCKDOWN_CHILD"

// runChild runs the named test in a child process and returns its output.
func runChild(t *testing.T, name string, env ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+name+"$", "-test.v")
	cmd.Env = append(os.Environ(), append([]string{childEnv + "=1"}, env...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// installTestFilter returns a filter that allows every system call except the
// ones that Apply probes. Those return EPERM, as the filter of pkg/gvx does.
// With allowDirfdOpen, an open relative to a directory descriptor stays allowed,
// as it does for a workspace.
func installTestFilter(allowDirfdOpen bool) func() error {
	return func() error {
		rejected := seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
			unix.SYS_EXECVE:   seccomp.MatchAll{},
			unix.SYS_EXECVEAT: seccomp.MatchAll{},
			unix.SYS_CLONE:    seccomp.MatchAll{},
			unix.SYS_CLONE3:   seccomp.MatchAll{},
			unix.SYS_SOCKET:   seccomp.MatchAll{},
			unix.SYS_OPENAT:   seccomp.MatchAll{},
		})
		var sets []seccomp.RuleSet
		if allowDirfdOpen {
			sets = append(sets, seccomp.RuleSet{
				Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
					unix.SYS_OPENAT: seccomp.PerArg{seccomp.NonNegativeFD{}},
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

func TestLinuxApplyWithWorkspaceReportsTheDirectoryDescriptorGap(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		out, err := runChild(t, "TestLinuxApplyWithWorkspaceReportsTheDirectoryDescriptorGap", "GVX_WORKSPACE="+t.TempDir())
		if err != nil {
			t.Fatalf("child failed: %v\n%s", err, out)
		}
		return
	}
	workspace := os.Getenv("GVX_WORKSPACE")
	if err := os.WriteFile(filepath.Join(workspace, "inside.txt"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}

	st, err := Apply(Options{Mounts: []HostMount{{Path: workspace}}, AllowOutboundNet: true, InstallSyscallFilter: installTestFilter(true)})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !st.SubprocessBlocked {
		t.Errorf("Status = %+v, want the subprocess block", st)
	}
	if st.UnboundFileOpenBlocked {
		t.Error("UnboundFileOpenBlocked = true, but a descriptor-relative open reaches the host root")
	}
	if st.NetworkOutboundBlocked {
		t.Error("NetworkOutboundBlocked = true with AllowOutboundNet")
	}
	if f, err := root.Open("inside.txt"); err != nil {
		t.Errorf("open through the workspace root after lockdown: %v", err)
	} else {
		_ = f.Close()
	}
	if _, err := os.ReadFile("/etc/hostname"); !errors.Is(err, unix.EPERM) {
		t.Errorf("ReadFile of an absolute path = %v, want EPERM", err)
	}
	// This pins the documented limit: seccomp cannot read a path, so an
	// absolute path through a directory descriptor still opens.
	fd, err := unix.Openat(rootFD, "etc/hostname", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		t.Errorf("descriptor-relative open of an absolute path = %v, want success or ENOENT", err)
	}
	if err == nil {
		_ = unix.Close(fd)
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
	_, err := Apply(Options{InstallSyscallFilter: func() error { return nil }})
	if err == nil || !strings.Contains(err.Error(), "execve probe") {
		t.Fatalf("Apply with an empty filter = %v, want the execve probe to fail", err)
	}
	if IsLockedDown() {
		t.Error("IsLockedDown() = true after a failed Apply")
	}
}
