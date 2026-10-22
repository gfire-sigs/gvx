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

package whpx

import (
	"encoding/binary"
	"errors"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

func newRealBrokeredPlatform(t *testing.T) *Platform {
	t.Helper()
	broker, err := NewBroker(uintptr(windows.CurrentProcess()))
	if errors.Is(err, ErrUnsupported) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := broker.Close(); err != nil {
			t.Error(err)
		}
	})
	server := rpc.NewServer()
	if err := server.RegisterName("Hypervisor", broker); err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	done := make(chan struct{})
	go func() { server.ServeConn(left); close(done) }()
	client := rpc.NewClient(right)
	t.Cleanup(func() { client.Close(); left.Close(); <-done })
	p, err := NewBrokered(client)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func TestRealBrokeredSyscall(t *testing.T) {
	p := newRealBrokeredPlatform(t)
	c, mm, ac := realGuest(t, p, guestSyscallCode)
	signal, _, err := c.Switch(nil, mm, ac, -1)
	if err != nil || signal != nil {
		t.Fatalf("brokered syscall: %v, %v", signal, err)
	}
	checkSyscallExit(t, ac)
}

func TestBrokerKeepsReadOnlyHostFileUnchanged(t *testing.T) {
	p := newRealBrokeredPlatform(t)
	path := filepath.Join(t.TempDir(), "read-only.dat")
	if err := os.WriteFile(path, make([]byte, pageSize), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	section, err := windows.CreateFileMapping(windows.Handle(file.Fd()), nil, windows.PAGE_READONLY, 0, pageSize, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := windows.CloseHandle(section); err != nil {
			t.Error(err)
		}
	})
	source, err := windows.MapViewOfFile(section, windows.FILE_MAP_READ, 0, 0, pageSize)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := windows.UnmapViewOfFile(source); err != nil {
			t.Error(err)
		}
	})
	const dataAddress = 0x800000
	var code []byte
	if runtime.GOARCH == "arm64" {
		for _, word := range []uint32{0xd2800540, 0x58000061, 0xf9000020, 0xd4000001} {
			code = binary.LittleEndian.AppendUint32(code, word)
		}
		code = binary.LittleEndian.AppendUint64(code, dataAddress)
	} else {
		code = append(code, 0x48, 0xc7, 0xc0, 42, 0, 0, 0, 0x48, 0xbf)
		code = binary.LittleEndian.AppendUint64(code, dataAddress)
		code = append(code, 0x48, 0x89, 0x07, 0x0f, 0x05)
	}
	c, mm, ac := realGuest(t, p, code)
	view := unsafe.Slice((*byte)(ptrFromUintptr(source)), pageSize)
	if err := mm.as.(*AddressSpace).mapHost(dataAddress, view, hostarch.AccessType{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	timerDone := make(chan struct{})
	timer := time.AfterFunc(3*time.Second, func() { c.Interrupt(); close(timerDone) })
	_, _, runErr := c.Switch(nil, mm, ac, -1)
	if !timer.Stop() {
		<-timerDone
	}
	if runErr != nil && !errors.Is(runErr, platform.ErrContextSignal) {
		t.Fatalf("write to read-only host pages: %v", runErr)
	}
	var disk [8]byte
	if _, err := file.ReadAt(disk[:], 0); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint64(disk[:]) != 0 || view[0] != 0 {
		t.Fatalf("guest changed a read-only host file: file=%v, view=%d", disk, view[0])
	}
}
