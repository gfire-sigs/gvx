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

package main

import (
	"regexp"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// TestStubPrintsHandshakeData runs the real engine: it starts the stub host and
// a stub process, and measures one guest system call round trip.
func TestStubPrintsHandshakeData(t *testing.T) {
	code, stdout, stderr := runStub(t)
	if code != 0 || stderr != "" {
		t.Fatalf("rungv stub = (code %d, stderr %q), want (0, empty stderr)", code, stderr)
	}
	re := regexp.MustCompile(`^systrap stub ok\n` +
		`architecture: ` + runtime.GOARCH + `\n` +
		`host page size: (\d+)\n` +
		`stub pid: (\d+)\n` +
		`protocol version: (\d+)\n` +
		`syscall round trip: (\S+)\n` +
		`guest address range: 0x([0-9a-f]+)-0x([0-9a-f]+)\n$`)
	m := re.FindStringSubmatch(stdout)
	if m == nil {
		t.Fatalf("rungv stub stdout = %q, want the six reported fields", stdout)
	}
	if page, _ := strconv.Atoi(m[1]); page != 4096 {
		t.Errorf("host page size = %s, want 4096", m[1])
	}
	if pid, _ := strconv.Atoi(m[2]); pid <= 0 {
		t.Errorf("stub pid = %s, want a positive pid", m[2])
	}
	lo, _ := strconv.ParseUint(m[5], 16, 64)
	hi, _ := strconv.ParseUint(m[6], 16, 64)
	if lo == 0 || hi <= lo || lo%4096 != 0 || hi%4096 != 0 {
		t.Errorf("guest address range = %#x-%#x, want page-aligned bounds with lo < hi", lo, hi)
	}
	rt, err := time.ParseDuration(m[4])
	if err != nil || rt <= 0 {
		t.Errorf("round trip = %q (%v), want a positive duration", m[4], err)
	}
}
