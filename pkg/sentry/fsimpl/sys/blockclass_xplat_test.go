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

package sys

import (
	"bytes"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/blockdev"
)

func TestDiskStatHasSeventeenFieldsPaddedToEight(t *testing.T) {
	s := blockdev.Snapshot{ReadsCompleted: 7, SectorsRead: 56, WritesCompleted: 3, SectorsWritten: 24, InFlight: 1, FlushesCompleted: 2}
	var buf bytes.Buffer
	writeDiskStat(&buf, s)

	got := buf.String()
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("stat %q has no final newline", got)
	}
	fields := strings.Fields(got)
	if len(fields) != blockdev.NumFields {
		t.Fatalf("stat %q has %d fields, want %d", got, len(fields), blockdev.NumFields)
	}
	want := "       7        0       56        0        3        0       24        0        1        0        0        0        0        0        0        2        0\n"
	if got != want {
		t.Errorf("stat = %q, want %q", got, want)
	}
}

func TestDiskDirectoriesAreKeyedByNameAndNumber(t *testing.T) {
	d := &blockdev.Device{Name: "vdb", Major: 254, Minor: 16}
	if got := byDiskName.format(d); got != "vdb" {
		t.Errorf("byDiskName = %q, want vdb", got)
	}
	if got := byDiskNumber.format(d); got != "254:16" {
		t.Errorf("byDiskNumber = %q, want 254:16", got)
	}
}
