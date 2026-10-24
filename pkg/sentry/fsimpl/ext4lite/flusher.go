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
	"sync/atomic"
	"time"
)

// A guest that never calls fsync would otherwise keep every change in memory
// until the unmount. The memory use would grow without a bound, and a crash
// would lose the whole run. A mounted filesystem therefore flushes in the
// background, as the writeback of Linux does. The flush follows the same
// strict order as fsync.

// defaultFlushInterval is the time between two background flushes.
const defaultFlushInterval = 5 * time.Second

// flushIntervalNanos overrides the interval for the tests. A value of 0 selects
// defaultFlushInterval.
var flushIntervalNanos atomic.Int64

// flushHook, when set, runs after each background flush. The tests use it to
// wait for a flush without a sleep.
var flushHook atomic.Pointer[func()]

// flusher is the background goroutine of one filesystem.
type flusher struct {
	stop chan struct{}
	done chan struct{}
}

// startFlusher starts the background flush of a writable filesystem.
func (fs *filesystem) startFlusher() {
	interval := time.Duration(flushIntervalNanos.Load())
	if interval <= 0 {
		interval = defaultFlushInterval
	}
	f := &flusher{stop: make(chan struct{}), done: make(chan struct{})}
	fs.flusher = f
	go func() {
		defer close(f.done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-f.stop:
				return
			case <-t.C:
				// A failure stays in the engine. The next flush writes the
				// same blocks again, and fsync reports the error to the guest.
				_ = fs.syncAll()
				if hook := flushHook.Load(); hook != nil {
					(*hook)()
				}
			}
		}
	}()
}

// stopFlusher stops the background flush and waits for a running flush to end.
func (fs *filesystem) stopFlusher() {
	if f := fs.flusher; f != nil {
		close(f.stop)
		<-f.done
		fs.flusher = nil
	}
}
