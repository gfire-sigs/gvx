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
	"fmt"
	"runtime"
)

// lowestLoadAddress returns the lowest address of a loadable segment of a
// little-endian ELF64 executable that links at a fixed address (type ET_EXEC).
// It returns false for every other file, including a position-independent
// executable, and for a header that the prefix cuts off.
func lowestLoadAddress(header []byte) (uint64, bool) {
	fileType, segments, ok := parseLoadSegments(header)
	if !ok || fileType != elfTypeExec || len(segments) == 0 {
		return 0, false
	}
	lowest := segments[0].vaddr
	for _, seg := range segments[1:] {
		lowest = min(lowest, seg.vaddr)
	}
	return lowest, true
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
