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

package kernel

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/state"
)

func TestTwoSandboxesIsolateKernelAndIPCNamespaceAcrossSaveRestore(t *testing.T) {
	k1, k2 := &Kernel{}, &Kernel{}
	k1.SetReportedMemory(1 << 30)
	k2.SetReportedMemory(3 << 30)
	if !k1.SetKernelLogBufLen(KernelLogMinBufLen) || !k2.SetKernelLogBufLen(KernelLogMinBufLen*2) {
		t.Fatal("SetKernelLogBufLen before first KernelLog returned false")
	}
	k1.KernelLog().SetDmesgRestrict(true)
	k1.KernelLog().Printk(LogWarning, "k1-saved-entry")
	k2.KernelLog().SetDevkmsgMode(DevkmsgOff)
	k2.KernelLog().Printk(LogInfo, "k2-saved-entry")

	ipc1 := NewIPCNamespace(auth.NewRootUserNamespace())
	ipc2 := NewIPCNamespace(auth.NewRootUserNamespace())
	ipc1.SetShmRmidForced(1)
	ipc2.SetShmRmidForced(0)

	checkPair := func(phase string, ka, kb *Kernel, ia, ib *IPCNamespace) {
		t.Helper()
		if mem, ok := ka.ReportedMemory(); !ok || mem != 1<<30 {
			t.Fatalf("%s: k1 ReportedMemory = (%d, %v), want (1GiB, true)", phase, mem, ok)
		}
		if mem, ok := kb.ReportedMemory(); !ok || mem != 3<<30 {
			t.Fatalf("%s: k2 ReportedMemory = (%d, %v), want (3GiB, true)", phase, mem, ok)
		}
		if !ka.KernelLog().DmesgRestrict() || kb.KernelLog().DmesgRestrict() {
			t.Fatalf("%s: DmesgRestrict = (%v, %v), want (true, false)", phase, ka.KernelLog().DmesgRestrict(), kb.KernelLog().DmesgRestrict())
		}
		if ka.KernelLog().DevkmsgMode() != DevkmsgRatelimit || kb.KernelLog().DevkmsgMode() != DevkmsgOff {
			t.Fatalf("%s: DevkmsgMode = (%v, %v), want (ratelimit, off)", phase, ka.KernelLog().DevkmsgMode(), kb.KernelLog().DevkmsgMode())
		}
		out1 := string(ka.KernelLog().ReadAll(4096, false))
		out2 := string(kb.KernelLog().ReadAll(4096, false))
		if !strings.Contains(out1, "k1-saved-entry") || strings.Contains(out1, "k2-saved-entry") {
			t.Fatalf("%s: k1 ReadAll = %q, want k1-saved-entry only", phase, out1)
		}
		if !strings.Contains(out2, "k2-saved-entry") || strings.Contains(out2, "k1-saved-entry") {
			t.Fatalf("%s: k2 ReadAll = %q, want k2-saved-entry only", phase, out2)
		}
		if ia.ShmRmidForced() != 1 || ib.ShmRmidForced() != 0 {
			t.Fatalf("%s: ShmRmidForced = (%d, %d), want (1, 0)", phase, ia.ShmRmidForced(), ib.ShmRmidForced())
		}
	}

	checkPair("pre-save", k1, k2, ipc1, ipc2)

	var buf1, buf2 bytes.Buffer
	s1 := []any{k1, ipc1}
	s2 := []any{k2, ipc2}
	if _, err := state.Save(context.Background(), &buf1, &s1); err != nil {
		t.Fatalf("state.Save(sandbox 1): %v", err)
	}
	if _, err := state.Save(context.Background(), &buf2, &s2); err != nil {
		t.Fatalf("state.Save(sandbox 2): %v", err)
	}

	var l1, l2 []any
	if _, err := state.Load(context.Background(), bytes.NewReader(buf1.Bytes()), &l1); err != nil {
		t.Fatalf("state.Load(sandbox 1): %v", err)
	}
	if _, err := state.Load(context.Background(), bytes.NewReader(buf2.Bytes()), &l2); err != nil {
		t.Fatalf("state.Load(sandbox 2): %v", err)
	}
	checkPair("post-load", l1[0].(*Kernel), l2[0].(*Kernel), l1[1].(*IPCNamespace), l2[1].(*IPCNamespace))
}
