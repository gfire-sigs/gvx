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
	"runtime"
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/pkg/gvx"
)

// TestE2EPtraceGSBaseKeepsPatchedThreadAlive checks that a thread keeps
// running after a tracer changes its GS base. The systrap engine patches the
// syscall instructions of a thread with jumps that use GS. Linux has no such
// patch, so a tracer can set GS with PTRACE_SETREGS, PTRACE_SETREGSET, or
// PTRACE_POKEUSER at any time. Sentry must remove the patches in the same way
// as for arch_prctl(ARCH_SET_GS). A Sentry that runs inside a guest needs it,
// because the inner Sentry sets GS of its stub threads with ptrace.
func TestE2EPtraceGSBaseKeepsPatchedThreadAlive(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("only the amd64 engine patches syscall instructions with jumps that use GS")
	}
	b := gateBackend{"systrap", gvx.PlatformSystrap}
	requireBackend(t, b)
	bin := acceptprog.BuildPtraceGS(t, runtime.GOARCH)
	code, out := runParityProbe(t, b, bin, false)
	if code != 0 || !strings.Contains(out, "DONE") {
		t.Fatalf("ptracegs exited with %d\n%s", code, out)
	}
	for _, name := range []string{"setregs", "setregset", "pokeuser"} {
		if !strings.Contains(out, "PASS "+name+"\n") {
			t.Errorf("check %s did not pass\n%s", name, out)
		}
	}
	if strings.Contains(out, "FAIL ") {
		t.Errorf("failed checks:\n%s", out)
	}
}
