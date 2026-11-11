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

package linux

import (
	"reflect"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/kernel"
)

func TestXplatSyscallTableBindings(t *testing.T) {
	cases := []struct {
		name          string
		table         *kernel.SyscallTable
		sysno         uintptr
		wantName      string
		wantFn        kernel.SyscallFn
		wantSupport   kernel.SyscallSupportLevel
		wantPointNon0 bool
	}{
		{"amd64 sysinfo", AMD64, amd64Sysinfo, "sysinfo", sysinfoXplat, kernel.SupportPartial, false},
		{"arm64 sysinfo", ARM64, arm64Sysinfo, "sysinfo", sysinfoXplat, kernel.SupportPartial, false},
		{"amd64 syslog", AMD64, amd64Syslog, "syslog", syslogXplat, kernel.SupportFull, false},
		{"arm64 syslog", ARM64, arm64Syslog, "syslog", syslogXplat, kernel.SupportFull, false},
		{"amd64 inotify_add_watch", AMD64, amd64InotifyAddWatch, "inotify_add_watch", inotifyAddWatchXplat, kernel.SupportPartial, true},
		{"arm64 inotify_add_watch", ARM64, arm64InotifyAddWatch, "inotify_add_watch", inotifyAddWatchXplat, kernel.SupportPartial, true},
		{"amd64 fallocate", AMD64, amd64Fallocate, "fallocate", fallocateXplat, kernel.SupportPartial, false},
		{"arm64 fallocate", ARM64, arm64Fallocate, "fallocate", fallocateXplat, kernel.SupportPartial, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry, ok := tc.table.Table[tc.sysno]
			if !ok {
				t.Fatalf("missing syscall %d in table %v", tc.sysno, tc.table.Arch)
			}
			if entry.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", entry.Name, tc.wantName)
			}
			if entry.SupportLevel != tc.wantSupport {
				t.Errorf("SupportLevel = %v, want %v", entry.SupportLevel, tc.wantSupport)
			}
			if (entry.PointCallback != nil) != tc.wantPointNon0 {
				t.Errorf("PointCallback != nil is %v, want %v", entry.PointCallback != nil, tc.wantPointNon0)
			}
			wantPtr := reflect.ValueOf(tc.wantFn).Pointer()
			if gotPtr := reflect.ValueOf(entry.Fn).Pointer(); gotPtr != wantPtr {
				t.Errorf("Table[%d].Fn = %#x, want %#x", tc.sysno, gotPtr, wantPtr)
			}
			if gotLookup := reflect.ValueOf(tc.table.Lookup(tc.sysno)).Pointer(); gotLookup != wantPtr {
				t.Errorf("Lookup(%d) = %#x, want %#x", tc.sysno, gotLookup, wantPtr)
			}
			if gotCallback := tc.table.LookupSyscallToProto(tc.sysno); (gotCallback != nil) != tc.wantPointNon0 {
				t.Errorf("LookupSyscallToProto(%d) != nil is %v, want %v", tc.sysno, gotCallback != nil, tc.wantPointNon0)
			}
		})
	}
}
