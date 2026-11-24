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

package main

import (
	"bytes"
	"testing"

	"z.gfire.dev/gvx/pkg/gvx"
)

func TestParseRestoreServeAndAttachBindFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc, code, done := parseRestoreArgs([]string{
		"-checkpoint-dir", t.TempDir(),
		"--serve", "/host/proj:/mnt/proj",
		"--serve", "/host/file.txt:/mnt/file.txt:ro",
		"--attach-bind", "/host/data:/mnt/data:ro",
	}, bytes.NewReader(nil), &stdout, &stderr)
	if done || code != 0 {
		t.Fatalf("parseRestoreArgs failed: code=%d done=%v stderr=%s", code, done, stderr.String())
	}
	if len(rc.cfg.ServeMounts) != 2 {
		t.Fatalf("ServeMounts len = %d, want 2: %+v", len(rc.cfg.ServeMounts), rc.cfg.ServeMounts)
	}
	if rc.cfg.ServeMounts[0].HostPath != "/host/proj" || rc.cfg.ServeMounts[0].GuestPath != "/mnt/proj" || rc.cfg.ServeMounts[0].ReadOnly {
		t.Fatalf("ServeMounts[0] = %+v", rc.cfg.ServeMounts[0])
	}
	if rc.cfg.ServeMounts[1].HostPath != "/host/file.txt" || rc.cfg.ServeMounts[1].GuestPath != "/mnt/file.txt" || !rc.cfg.ServeMounts[1].ReadOnly {
		t.Fatalf("ServeMounts[1] = %+v", rc.cfg.ServeMounts[1])
	}
	if len(rc.cfg.Mounts) != 1 || rc.cfg.Mounts[0].Kind != gvx.MountBind || rc.cfg.Mounts[0].HostPath != "/host/data" || rc.cfg.Mounts[0].GuestPath != "/mnt/data" || !rc.cfg.Mounts[0].ReadOnly {
		t.Fatalf("Mounts = %+v, want 1 ro bind mount", rc.cfg.Mounts)
	}
}
