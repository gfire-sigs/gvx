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
	"runtime"
	"strings"
	"testing"
	"weak"
)

func TestKernelLogIsolatesPerSandboxStateAcrossKernels(t *testing.T) {
	k1 := &Kernel{}
	k2 := &Kernel{}

	if !k1.SetKernelLogBufLen(KernelLogMinBufLen) {
		t.Fatal("k1.SetKernelLogBufLen before first KernelLog() returned false")
	}
	if !k2.SetKernelLogBufLen(KernelLogMinBufLen * 4) {
		t.Fatal("k2.SetKernelLogBufLen before first KernelLog() returned false")
	}

	log1 := k1.KernelLog()
	log2 := k2.KernelLog()
	if log1 == log2 {
		t.Fatal("distinct Kernel instances share one KernelLog pointer")
	}
	if got, want := log1.BufLen(), KernelLogMinBufLen; got != want {
		t.Errorf("k1 BufLen = %d, want %d", got, want)
	}
	if got, want := log2.BufLen(), KernelLogMinBufLen*4; got != want {
		t.Errorf("k2 BufLen = %d, want %d", got, want)
	}
	if k1.SetKernelLogBufLen(KernelLogDefaultBufLen) {
		t.Error("SetKernelLogBufLen succeeded after KernelLog initialization")
	}

	log1.SetDmesgRestrict(true)
	log1.SetDevkmsgMode(DevkmsgOff)
	log1.Printk(LogWarning, "sandbox-one")
	log2.Printk(LogInfo, "sandbox-two")

	if log2.DmesgRestrict() {
		t.Error("k1 DmesgRestrict leaked into k2")
	}
	if got := log2.DevkmsgMode(); got != DevkmsgRatelimit {
		t.Errorf("k2 DevkmsgMode = %v, want %v", got, DevkmsgRatelimit)
	}
	out1 := string(log1.ReadAll(4096, false))
	out2 := string(log2.ReadAll(4096, false))
	if !strings.Contains(out1, "sandbox-one") || strings.Contains(out1, "sandbox-two") {
		t.Errorf("k1 ReadAll = %q, want sandbox-one only", out1)
	}
	if !strings.Contains(out2, "sandbox-two") || strings.Contains(out2, "sandbox-one") {
		t.Errorf("k2 ReadAll = %q, want sandbox-two only", out2)
	}

	if upstreamMsg := k1.Syslog().Log(); !bytes.Contains(upstreamMsg, []byte("Starting gVisor...")) {
		t.Errorf("upstream Kernel.Syslog().Log() = %q, want Starting gVisor header", upstreamMsg)
	}
}

func TestKernelLogRegistryReleasesDroppedKernels(t *testing.T) {
	var ref weak.Pointer[Kernel]
	func() {
		k := &Kernel{}
		if !k.SetKernelLogBufLen(KernelLogMinBufLen) {
			t.Fatal("SetKernelLogBufLen returned false")
		}
		k.KernelLog().Printk(LogInfo, "ephemeral")
		ref = weak.Make(k)
	}()

	for range 5 {
		runtime.GC()
	}
	if ref.Value() != nil {
		t.Fatal("kernelLogs retained an unreferenced Kernel instance")
	}
}
