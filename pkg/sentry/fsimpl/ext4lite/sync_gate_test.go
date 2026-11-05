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

package ext4lite

import (
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
)

// TestSyncWaitsForGateWriterWithoutHoldingWriteMutex starts an fdatasync while
// a write is in the operation gate and has not taken the write mutex yet. The
// flush of the sync waits for the write to leave the gate. The write then takes
// the write mutex, which the sync must not hold at that point. Otherwise the
// write waits for the sync and the sync waits for the write without end.
func TestSyncWaitsForGateWriterWithoutHoldingWriteMutex(t *testing.T) {
	d := newAuDrv(t)
	d.create("/f", 10)
	fd := d.e.mustOpen("/f", linux.O_RDWR)
	defer fd.DecRef(d.e.ctx)
	ino := fd.Impl().(*regularFD).dentry.inode
	gate := &d.e.fs.v.gate

	gate.enterOp()
	syncDone := make(chan error, 1)
	go func() { syncDone <- fd.SyncData(d.e.ctx) }()

	// The flush closes the gate and waits when it sets draining.
	deadline := time.Now().Add(10 * time.Second)
	for {
		gate.mu.Lock()
		draining := gate.draining
		gate.mu.Unlock()
		if draining {
			break
		}
		if time.Now().After(deadline) {
			gate.exit()
			t.Fatal("the flush of the sync did not wait for the operation in the gate")
		}
		time.Sleep(time.Millisecond)
	}

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		ino.wmu.Lock()
		ino.wmu.Unlock()
		gate.exit()
	}()
	select {
	case <-writerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("a write in the gate waits for the write mutex while the sync flushes the volume")
	}
	select {
	case err := <-syncDone:
		if err != nil {
			t.Errorf("fdatasync = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("fdatasync did not end after the write left the gate")
	}
}
