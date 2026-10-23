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

//go:build darwin

package hostlockdown

import (
	"path/filepath"
	"strings"
	"testing"
)

// The probes must report failure on an unlocked process. A probe that passes
// everywhere would let Apply report a lockdown it never enforced.

func TestProbesRejectUnlockedProcess(t *testing.T) {
	ws := realTempDir(t)
	tests := []struct {
		name string
		run  func() error
		want string
	}{
		{"subprocess", probeSubprocessBlocked, "spawn succeeded"},
		{"unlisted open", func() error { return probeUnlistedOpenBlocked([]string{ws}) }, "succeeded after lockdown"},
		{"outbound", probeOutboundBlocked, "reached the network stack"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("probe on unlocked process = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestProbeMountsReachable(t *testing.T) {
	first, second := realTempDir(t), realTempDir(t)
	if err := probeMountsReachable([]string{first, second}); err != nil {
		t.Fatalf("probeMountsReachable(existing) = %v", err)
	}
	if err := probeMountsReachable(nil); err != nil {
		t.Fatalf("probeMountsReachable(no mounts) = %v", err)
	}
	if err := probeMountsReachable([]string{first, filepath.Join(second, "absent")}); err == nil {
		t.Fatal("probeMountsReachable(second mount missing) = nil, want error")
	}
}

func TestDescriptorProbeKeepsByte(t *testing.T) {
	p, err := newDescriptorProbe()
	if err != nil {
		t.Fatalf("newDescriptorProbe: %v", err)
	}
	if err := p.verify(); err != nil {
		t.Fatalf("verify on open descriptors = %v", err)
	}
	if err := p.verify(); err == nil {
		t.Fatal("second verify after close = nil, want error")
	}
}

func TestSandboxInitReportsCompilerText(t *testing.T) {
	err := sandboxInit("(version 1)\n(deny default (with report))\n", nil)
	if err == nil || !strings.Contains(err.Error(), "report modifier does not apply to deny action") {
		t.Fatalf("sandboxInit(invalid profile) = %v, want the Seatbelt compiler message", err)
	}
}
