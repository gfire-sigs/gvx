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

package hostfs

import (
	"os"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// TestWindowsOpenDescendantBlocksHostRename documents the NTFS rule that the
// quiesce exists for. A directory with an open descendant file does not
// rename. The same rename works after the file closes.
func TestWindowsOpenDescendantBlocksHostRename(t *testing.T) {
	ws, err := openWorkspace(resolvedTempDir(t), false, workspaceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := ws.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	if err := ws.MkdirAll("d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ws.WriteFile("d/f", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := ws.OpenFile("d/f", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.host.rename("d", "e"); err == nil {
		_ = f.Close()
		t.Fatal("the host renamed a directory with an open descendant file, so the quiesce has no purpose here")
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ws.host.rename("d", "e"); err != nil {
		t.Fatalf("rename after the file closed: %v", err)
	}
}

// TestWindowsDefaultProbeTracksHandles checks that the capability probe turns
// the quiesce on for an NTFS workspace without a test override.
func TestWindowsDefaultProbeTracksHandles(t *testing.T) {
	e := newEnv(t)
	if !e.ws.Caps().LocksOpenDirMove {
		t.Fatalf("the probe reports LocksOpenDirMove = false on Windows")
	}
	if e.ws.handles == nil {
		t.Fatalf("a workspace with LocksOpenDirMove has no handle registry")
	}
}

// TestWindowsRenameBlockedByHostHandleRollsBack holds a descendant open in a
// host process that the quiesce cannot reach. The directory rename must fail,
// and the rollback must leave the guest file description usable at the old
// path. After the host process closes its handle, the rename succeeds.
func TestWindowsRenameBlockedByHostHandleRollsBack(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	e.writeFile("d/f", []byte("0123456789"))
	fd := e.mustOpen("d/f", linux.O_RDWR)
	defer fd.DecRef(e.ctx)

	host, err := os.Open(e.host("d/f"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.rename("d", "e"); err == nil {
		_ = host.Close()
		t.Fatal("rename succeeded while a host process held a descendant open")
	}
	if got := e.registered(fd); got != "d/f" {
		t.Fatalf("registered path after the failed rename = %q, want d/f", got)
	}
	if got := e.pread(fd, 0, 10); string(got) != "0123456789" {
		t.Fatalf("PRead after the failed rename = %q", got)
	}
	if _, err := fd.PWrite(e.ctx, usermem.BytesIOSequence([]byte("XY")), 4, vfs.WriteOptions{}); err != nil {
		t.Fatalf("PWrite after the failed rename: %v", err)
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.rename("d", "e"); err != nil {
		t.Fatalf("rename after the host process closed its handle: %v", err)
	}
	if got := e.pread(fd, 0, 10); string(got) != "0123XY6789" {
		t.Fatalf("PRead after the rename = %q", got)
	}
}
