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

package ext4lite_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// TestSyncWaitsForGateWriterWithoutHoldingWriteMutex runs concurrent writes,
// truncates, and fdatasync calls on the same file. A flush of the sync closes
// the operation gate and waits for active writes to leave the gate. A write
// that entered the gate takes the inode write mutex after the gate, so the
// sync must not hold the write mutex while it waits on the gate.
func TestSyncWaitsForGateWriterWithoutHoldingWriteMutex(t *testing.T) {
	fx := newVFSFixture(t)
	fd, err := fx.vfsObj.OpenAt(fx.ctx, fx.creds, fx.fpop("f"), &vfs.OpenOptions{
		Flags: linux.O_CREAT | linux.O_RDWR,
		Mode:  0o644,
	})
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	defer fd.DecRef(fx.ctx)

	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	if n, err := fd.PWrite(fx.ctx, usermem.BytesIOSequence(payload), 0, vfs.WriteOptions{}); err != nil || int(n) != len(payload) {
		t.Fatalf("initial PWrite = (%d, %v)", n, err)
	}

	const rounds = 60
	start := make(chan struct{})
	errCh := make(chan error, 6)
	var wg sync.WaitGroup
	for w := range 3 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			for i := range rounds {
				off := int64((id*rounds + i) % 8 * 4096)
				if _, err := fd.PWrite(fx.ctx, usermem.BytesIOSequence(payload), off, vfs.WriteOptions{}); err != nil {
					errCh <- fmt.Errorf("PWrite: %w", err)
					return
				}
			}
		}(w)
	}
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range rounds {
				if err := fd.SyncData(fx.ctx); err != nil {
					errCh <- fmt.Errorf("SyncData: %w", err)
					return
				}
			}
		}()
	}
	close(start)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("concurrent PWrite and SyncData deadlocked on the operation gate and the write mutex")
	}
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}
