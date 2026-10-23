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

package gvx

import (
	"encoding/binary"
	"fmt"
	"runtime"
)

// elfProbeBytes is the size of the file prefix that nonPIEHint reads. The
// program headers of an executable lie right behind the ELF header.
const elfProbeBytes = 16 << 10

const (
	elfHeaderSize  = 64
	elfTypeExec    = 2
	elfProgLoad    = 1
	elfProgHdrSize = 56
)

// lowestLoadAddress returns the lowest address of a loadable segment of a
// little-endian ELF64 executable that links at a fixed address (type ET_EXEC).
// It returns false for every other file, including a position-independent
// executable, and for a header that the prefix cuts off.
func lowestLoadAddress(header []byte) (uint64, bool) {
	if len(header) < elfHeaderSize || string(header[:4]) != "\x7fELF" || header[4] != 2 || header[5] != 1 {
		return 0, false
	}
	if binary.LittleEndian.Uint16(header[16:]) != elfTypeExec {
		return 0, false
	}
	phoff := binary.LittleEndian.Uint64(header[32:])
	phentsize := uint64(binary.LittleEndian.Uint16(header[54:]))
	phnum := uint64(binary.LittleEndian.Uint16(header[56:]))
	if phentsize < elfProgHdrSize {
		return 0, false
	}
	lowest, found := uint64(0), false
	for i := range phnum {
		off := phoff + i*phentsize
		if off+elfProgHdrSize > uint64(len(header)) {
			return 0, false
		}
		ph := header[off : off+elfProgHdrSize]
		if binary.LittleEndian.Uint32(ph[0:]) != elfProgLoad || binary.LittleEndian.Uint64(ph[40:]) == 0 {
			continue
		}
		if vaddr := binary.LittleEndian.Uint64(ph[16:]); !found || vaddr < lowest {
			lowest, found = vaddr, true
		}
	}
	return lowest, found
}

// hardwareEngine names the hardware engine of a host OS. It returns an empty
// string for a host that has none.
func hardwareEngine(goos string) string {
	switch goos {
	case "darwin":
		return "hvf"
	case "windows":
		return "whpx"
	}
	return ""
}

// nonPIEHint explains why a platform cannot start an executable. The file
// prefix header holds the ELF header of the executable. guestMin is the lowest
// guest address of the platform. The hint is empty unless the executable links
// below guestMin and so cannot load there.
func nonPIEHint(header []byte, guestMin uint64, goos string) string {
	lowest, ok := lowestLoadAddress(header)
	if !ok || lowest >= guestMin {
		return ""
	}
	hint := fmt.Sprintf("the executable is not position-independent and links at %#x, below the lowest guest address %#x of the systrap engine", lowest, guestMin)
	if hw := hardwareEngine(goos); hw != "" {
		hint += fmt.Sprintf("; run it with -platform=%s", hw)
	}
	return hint
}

// nonPIEHintForGuestFile reads the start of the guest executable and returns
// the hint of nonPIEHint, or an empty string when the file cannot explain the
// failure.
func (s *Sandbox) nonPIEHintForGuestFile(read func(path string, maxBytes int) ([]byte, error), execPath string) string {
	header, err := read(execPath, elfProbeBytes)
	if err != nil || header == nil {
		return ""
	}
	return nonPIEHint(header, uint64(s.plat.MinUserAddress()), runtime.GOOS)
}
