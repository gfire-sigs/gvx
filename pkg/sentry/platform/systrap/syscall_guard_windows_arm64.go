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
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sealHostSyscalls removes native syscall instructions before guest threads exist.
// The debugger retains control of all later executable mappings.
func sealHostSyscalls(process windows.Handle) error {
	var info struct {
		Architecture                           uint32
		PageSize                               uint32
		Minimum, Maximum, ActiveMask           uintptr
		Processors, ProcessorType, Granularity uint32
		Level, Revision                        uint16
	}
	modKernel32.NewProc("GetNativeSystemInfo").Call(uintptr(unsafe.Pointer(&info)))
	if info.Maximum == 0 {
		return fmt.Errorf("systrap: the host reported no user address range")
	}
	for address := uintptr(0); address <= info.Maximum; {
		var region windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(process, address, &region, unsafe.Sizeof(region)); err != nil {
			return fmt.Errorf("systrap: inspect host executable mappings at %#x: %w", address, err)
		}
		end := region.BaseAddress + region.RegionSize
		if end <= address {
			return fmt.Errorf("systrap: invalid host mapping at %#x", address)
		}
		if region.State == windows.MEM_COMMIT && region.Protect&(windows.PAGE_EXECUTE|windows.PAGE_EXECUTE_READ|windows.PAGE_EXECUTE_READWRITE|windows.PAGE_EXECUTE_WRITECOPY) != 0 {
			if err := sealExecutableRegion(process, region.BaseAddress, region.RegionSize); err != nil {
				return err
			}
			if region.Protect&(windows.PAGE_EXECUTE_READWRITE|windows.PAGE_EXECUTE_WRITECOPY) != 0 {
				var old uint32
				if err := windows.VirtualProtectEx(process, region.BaseAddress, region.RegionSize, windows.PAGE_EXECUTE_READ, &old); err != nil {
					return fmt.Errorf("systrap: make host code immutable at %#x: %w", region.BaseAddress, err)
				}
			}
		}
		address = end
	}
	return nil
}

func sealExecutableRegion(process windows.Handle, address, size uintptr) error {
	buffer := make([]byte, min(size, 4<<20))
	for offset := uintptr(0); offset < size; {
		length := min(uintptr(len(buffer)), size-offset)
		data := buffer[:length]
		var read uintptr
		if err := windows.ReadProcessMemory(process, address+offset, &data[0], length, &read); err != nil || read != length {
			return fmt.Errorf("systrap: read executable bytes at %#x (%d/%d): %v", address+offset, read, length, err)
		}
		for pageOffset := uintptr(0); pageOffset < length; pageOffset += blockSize {
			page := data[pageOffset:min(pageOffset+blockSize, length)]
			changed := false
			for instruction := 0; instruction+4 <= len(page); instruction += 4 {
				if binary.LittleEndian.Uint32(page[instruction:])&arm64SVCMask == arm64SVC0 {
					binary.LittleEndian.PutUint32(page[instruction:], brkWord(brkHostSyscall))
					changed = true
				}
			}
			if !changed {
				continue
			}
			base := address + offset + pageOffset
			var old uint32
			if err := windows.VirtualProtectEx(process, base, uintptr(len(page)), windows.PAGE_READWRITE, &old); err != nil {
				return fmt.Errorf("systrap: prepare native syscall page at %#x: %w", base, err)
			}
			var written uintptr
			if err := windows.WriteProcessMemory(process, base, &page[0], uintptr(len(page)), &written); err != nil || written != uintptr(len(page)) {
				return fmt.Errorf("systrap: replace native syscalls at %#x (%d/%d): %v", base, written, len(page), err)
			}
			if err := windows.VirtualProtectEx(process, base, uintptr(len(page)), windows.PAGE_EXECUTE_READ, &old); err != nil {
				return err
			}
			if err := flushInstructionCache(process, base, uintptr(len(page))); err != nil {
				return err
			}
		}
		offset += length
	}
	return nil
}
