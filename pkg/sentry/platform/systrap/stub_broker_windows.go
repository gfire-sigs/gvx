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

package systrap

import (
	"errors"
	"io"
	"os"
	"runtime"
	"sync"

	"golang.org/x/sys/windows"
)

// StubBroker creates AppContainer stubs for one fixed Sentry worker.
// Close terminates its stubs and waits for the request loop to stop.
type StubBroker struct {
	requests io.ReadCloser
	replies  io.WriteCloser
	done     chan struct{}
	once     sync.Once
	err      error
}

// NewStubBroker takes ownership of both pipe ends and duplicates the worker handle.
// Requests cannot select an executable, environment, inherited handle, or target worker.
func NewStubBroker(worker uintptr, requests io.ReadCloser, replies io.WriteCloser) (*StubBroker, error) {
	if runtime.GOARCH != "arm64" {
		return nil, errors.New("systrap: confined stubs require windows/arm64")
	}
	if worker == 0 || requests == nil || replies == nil {
		return nil, errors.New("systrap: a worker and two pipe ends are required")
	}
	var child windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(worker), windows.CurrentProcess(), &child, windows.PROCESS_DUP_HANDLE, false, 0); err != nil {
		return nil, err
	}
	b := &StubBroker{requests: requests, replies: replies, done: make(chan struct{})}
	go func() {
		defer close(b.done)
		defer windows.CloseHandle(child)
		b.err = serveStubHost(child, true, requests, replies)
		_ = requests.Close()
		_ = replies.Close()
	}()
	return b, nil
}

func (b *StubBroker) Close() error {
	b.once.Do(func() { _ = b.requests.Close(); _ = b.replies.Close() })
	<-b.done
	if errors.Is(b.err, io.ErrClosedPipe) || errors.Is(b.err, os.ErrClosed) || errors.Is(b.err, windows.ERROR_BROKEN_PIPE) {
		return nil
	}
	return b.err
}
