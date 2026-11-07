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

package wireguard

import (
	"os"
	"testing"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/syserr"
)

// kernelContext returns a context of a kernel whose memory file has its own
// accounting, as the kernel of a sandbox has.
func kernelContext(t *testing.T) (context.Context, *usage.MemoryLocked) {
	t.Helper()
	fd, err := memutil.CreateMemFD("wireguard-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD = %v", err)
	}
	acct := usage.NewMemoryLocked()
	mf, err := pgalloc.NewMemoryFile(os.NewFile(uintptr(fd), "wireguard-test"), pgalloc.MemoryFileOpts{Accounting: acct})
	if err != nil {
		t.Fatalf("NewMemoryFile = %v", err)
	}
	t.Cleanup(mf.Destroy)
	k := &kernel.Kernel{}
	k.SetMemoryFile(mf)
	return context.WithValues(context.Background(), map[any]any{kernel.CtxKernel: k}), acct
}

// TestLinksChargeTheAccountingOfTheirKernel creates links in two kernels of one
// process. Each kernel accounting must hold only the memory of its own links,
// and a limit on the total must compare with the links of one kernel only.
func TestLinksChargeTheAccountingOfTheirKernel(t *testing.T) {
	old, oldMax := usage.MemoryAccounting, usage.MaximumTotalMemoryBytes
	usage.MemoryAccounting = usage.NewMemoryLocked()
	t.Cleanup(func() { usage.MemoryAccounting, usage.MaximumTotalMemoryBytes = old, oldMax })
	ctxA, acctA := kernelContext(t)
	ctxB, acctB := kernelContext(t)
	st := newLoopbackStackOf(t)

	a, sysErr := newLink(ctxA, &netstack.NewLinkRequest{Stack: st, ID: 2, Name: "wg0"})
	if sysErr != nil {
		t.Fatalf("newLink in kernel A = %v", sysErr)
	}
	defer a.(*linkEndpoint).Close()
	if got := acctA.Total(); got != deviceBytes() {
		t.Errorf("accounting of kernel A = %d, want %d", got, deviceBytes())
	}
	if got := acctB.Total(); got != 0 {
		t.Errorf("accounting of kernel B = %d after a link in kernel A, want 0", got)
	}
	if got := usage.MemoryAccounting.Total(); got != 0 {
		t.Errorf("global accounting = %d, want 0: a kernel with its own accounting charged it", got)
	}

	// The total that fits in the memory of the host is the total of one kernel.
	usage.MaximumTotalMemoryBytes = deviceBytes()
	b, sysErr := newLink(ctxB, &netstack.NewLinkRequest{Stack: st, ID: 3, Name: "wg1"})
	if sysErr == syserr.ErrNoMemory {
		t.Fatalf("newLink in kernel B = ENOMEM, want success: the links of kernel A count against kernel B")
	}
	if sysErr != nil {
		t.Fatalf("newLink in kernel B = %v", sysErr)
	}
	b.(*linkEndpoint).Close()
	if got := acctB.Total(); got != 0 {
		t.Errorf("accounting of kernel B after Close = %d, want 0", got)
	}
}
