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

//go:build !race

package ext4lite

import (
	"encoding/binary"
	"sync"
	"testing"
)

// The guest stores through a mapping without synchronization, so the race
// detector flags the test below by design. It runs in the builds without it.

// TestRangeShiftWithAConcurrentMappedWriter shifts a file back and forth while
// another goroutine stores a counter into page 0 through the mapping. The
// stores must reach the file and the image must pass e2fsck afterwards.
func TestRangeShiftWithAConcurrentMappedWriter(t *testing.T) {
	forEachChunkMode(t, func(t *testing.T, e *env) {
		fd := e.fileWith("f", blocksPattern(1, 16))
		mp := e.mapFile(fd, 16*blockSize, true)
		var wg sync.WaitGroup
		stop := make(chan struct{})
		var last uint64
		wg.Add(1)
		go func() {
			defer wg.Done()
			var buf [8]byte
			for i := uint64(1); ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				binary.LittleEndian.PutUint64(buf[:], i)
				mp.store(0, buf[:])
				last = i
			}
		}()
		for range 150 {
			if err := e.allocate(fd, collapse, 4*blockSize, blockSize); err != nil {
				t.Fatal(err)
			}
			if err := e.allocate(fd, insert, 4*blockSize, blockSize); err != nil {
				t.Fatal(err)
			}
		}
		close(stop)
		wg.Wait()
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], last+1)
		mp.store(0, buf[:])
		mp.remove()
		if got := binary.LittleEndian.Uint64(e.readAll(fd)[:8]); got != last+1 {
			t.Fatalf("counter in the file = %d, want %d: a mapped store was lost", got, last+1)
		}
		requireCleanImage(t, e)
	})
}
