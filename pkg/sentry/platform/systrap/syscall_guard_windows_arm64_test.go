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
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

func TestGuestCannotCallNativeNTDLLService(t *testing.T) {
	service := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQuerySystemTime")
	if err := service.Find(); err != nil {
		t.Fatal(err)
	}
	var now int64
	status, _, _ := service.Call(uintptr(unsafe.Pointer(&now)))
	if status != 0 || now == 0 {
		t.Fatalf("native control: status=%#x time=%d", status, now)
	}
	var instructions [64]byte
	var read uintptr
	if err := windows.ReadProcessMemory(windows.CurrentProcess(), service.Addr(), &instructions[0], uintptr(len(instructions)), &read); err != nil {
		t.Fatal(err)
	}
	var entry uint64
	for offset := 0; offset+4 <= int(read); offset += 4 {
		if binary.LittleEndian.Uint32(instructions[offset:])&0xffe0001f == arm64SVC0 {
			entry = uint64(service.Addr()) + uint64(offset)
			break
		}
	}
	if entry == 0 {
		t.Fatal("native control has no syscall instruction")
	}
	r := newRig(t, newPlatform(t))
	data := r.mapPage(dataVA, hostarch.ReadWrite)
	binary.LittleEndian.PutUint64(data, 0x1122334455667788)
	r.program(gConst(0, dataVA), gJump(entry))
	signal, _, err := r.run()
	if !errors.Is(err, platform.ErrContextSignal) || signal == nil || signal.Signo != int32(linux.SIGILL) {
		t.Fatalf("native syscall entry: signal=%v error=%v", signal, err)
	}
	if got := binary.LittleEndian.Uint64(data); got != 0x1122334455667788 {
		t.Fatalf("native service wrote guest memory: %#x", got)
	}
}

func TestGuestSVCImmediateUsesLinuxDispatch(t *testing.T) {
	p := newPlatform(t)
	for _, immediate := range []uint32{0, 15, 0x8000, 0xffff} {
		t.Run(fmt.Sprintf("%x", immediate), func(t *testing.T) {
			r := newRig(t, p)
			r.program(gConst(8, 172), wordBytes(arm64SVC0|immediate<<5))
			signal, _, err := r.run()
			mustSyscall(t, signal, err, 172, r.ac)
		})
	}
}

func TestGuestCannotModifyHostCode(t *testing.T) {
	entry := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQuerySystemTime").Addr()
	r := newRig(t, newPlatform(t))
	r.program(gStoreTo(uint64(entry), uint64(arm64SVC0)), gSyscall(172))
	signal, _, err := r.run()
	if !errors.Is(err, platform.ErrContextSignal) || signal == nil || signal.Signo != int32(linux.SIGSEGV) {
		t.Fatalf("host code write: signal=%v error=%v", signal, err)
	}
}

func TestStubTokenCannotReadCallerFile(t *testing.T) {
	r := newRig(t, newPlatform(t))
	secret := filepath.Join(t.TempDir(), "caller-only.txt")
	if err := os.WriteFile(secret, []byte("caller data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(secret); err != nil {
		t.Fatal(err)
	}
	var primary windows.Token
	if err := windows.OpenProcessToken(r.as.sp.proc, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &primary); err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	for _, item := range []struct{ class, want uint32 }{{29, 1}, {30, 0}, {windows.TokenPrivileges, 0}} {
		var aligned [512]uint64
		data := unsafe.Slice((*byte)(unsafe.Pointer(&aligned[0])), 4096)
		var size uint32
		if err := windows.GetTokenInformation(primary, item.class, &data[0], uint32(len(data)), &size); err != nil {
			t.Fatalf("token class %d: %v", item.class, err)
		}
		if got := binary.LittleEndian.Uint32(data[:]); got != item.want {
			t.Fatalf("token class %d: %d, want %d", item.class, got, item.want)
		}
	}
	var impersonation windows.Token
	if err := windows.DuplicateTokenEx(primary, windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation); err != nil {
		t.Fatal(err)
	}
	defer impersonation.Close()
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.SetThreadToken(nil, impersonation); err != nil {
			result <- err
			return
		}
		_, err := os.ReadFile(secret)
		revert := windows.RevertToSelf()
		if revert != nil {
			result <- revert
			return
		}
		runtime.UnlockOSThread()
		if !errors.Is(err, os.ErrPermission) {
			result <- fmt.Errorf("stub read: %v", err)
			return
		}
		result <- nil
	}()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
