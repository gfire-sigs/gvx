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

package pgalloc

import (
	"context"
	"runtime"
	"time"
)

// IsBackingOpen reports whether f owns an open backing file and has not
// started asynchronous destruction.
func (f *MemoryFile) IsBackingOpen() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.destroyed && f.file != nil
}

// WaitBackingClosed waits until the releaser goroutine of f closes its backing
// file and clears f.file under f.mu, or ctx ends.
func (f *MemoryFile) WaitBackingClosed(ctx context.Context) error {
	for {
		f.mu.Lock()
		closed := f.destroyed && f.file == nil
		f.mu.Unlock()
		if closed {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		runtime.Gosched()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}
