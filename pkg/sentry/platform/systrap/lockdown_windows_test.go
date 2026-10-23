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

//go:build windows

package systrap

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

const lockdownChildEnv = "GVX_SYSTRAP_LOCKDOWN_CHILD"

// TestWorksAfterHostLockdown runs the engine in a process that has applied the
// Sentry lockdown, which allows no new process. The stub host started before
// the lockdown and creates every stub, so address spaces keep working. The
// lockdown is irreversible, so the check runs in a child copy of the test
// binary.
func TestWorksAfterHostLockdown(t *testing.T) {
	if os.Getenv(lockdownChildEnv) != "" {
		t.Skip("running as the child")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockdownChild$", "-test.v")
	cmd.Env = append(os.Environ(), lockdownChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the locked child failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("--- PASS: TestLockdownChild")) {
		t.Fatalf("the locked child did not run its test:\n%s", out)
	}
}

func TestLockdownChild(t *testing.T) {
	if os.Getenv(lockdownChildEnv) == "" {
		t.Skip("runs only as the child of TestWorksAfterHostLockdown")
	}
	p := newPlatform(t)
	// The memory file needs a host file, so it exists before the lockdown.
	r1 := newRig(t, p)
	st, err := hostlockdown.Apply(hostlockdown.Options{})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !st.Applied || !st.SubprocessBlocked {
		t.Fatalf("lockdown status = %+v, want applied with blocked subprocesses", st)
	}
	// A new address space needs a new stub process, which the host creates.
	asI, err := p.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatalf("NewAddressSpace after lockdown: %v", err)
	}
	as2 := asI.(*addressSpace)
	defer as2.Release()

	r1.program(gSyscall(21, 3), gSyscall(22))
	for _, no := range []uint64{21, 22} {
		si, _, err := r1.run()
		mustSyscall(t, si, err, no, r1.ac)
	}
	// A second thread and an interrupt use the same machinery.
	c := p.NewContext(r1.rctx).(*Context)
	defer c.Release()
	ac := r1.ac.Fork()
	ac.SetIP(codeVA)
	si, _, err := c.Switch(r1.rctx, r1.mm, ac, -1)
	mustSyscall(t, si, err, 21, ac)
}
