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

//go:build darwin || linux

package main

import (
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func TestControlEndpointRetainsReadOnlyToken(t *testing.T) {
	isolateControlTokenDir(t)
	ep, err := listenCheckpointSocket("tcp://127.0.0.1:0", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ep.Cleanup)
	t.Cleanup(func() { _ = ep.Listener.Close() })
	if ep.tokenFile == nil {
		t.Fatal("missing token identity file")
	}
	flags, err := unix.FcntlInt(ep.tokenFile.Fd(), unix.F_GETFL, 0)
	runtime.KeepAlive(ep.tokenFile)
	if err != nil {
		t.Fatalf("get token descriptor access mode: %v", err)
	}
	if flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Errorf("token descriptor access mode = %#x, want O_RDONLY", flags&unix.O_ACCMODE)
	}
}
