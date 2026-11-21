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

//go:build linux

package main

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

func setGuestForwardPolicy(accept bool) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("open guest filter socket: %w", err)
	}
	defer unix.Close(fd)

	// Encode the 64-bit Linux UAPI from ip_tables.h and x_tables.h. Only the
	// three built-in policies and the terminal ERROR entry are necessary.
	const (
		setReplace    = 64
		replaceHeader = 96
		entryHeader   = 112
		policyEntry   = entryHeader + 40
		errorEntry    = entryHeader + 64
		targetOffset  = 88
		nextOffset    = 90
		verdictOffset = 32
		acceptVerdict = ^uint32(1)
		dropVerdict   = ^uint32(0)
	)
	order := binary.NativeEndian
	const size = 3*policyEntry + errorEntry
	replace := make([]byte, replaceHeader+size)
	copy(replace, "filter")
	order.PutUint32(replace[32:], 1<<1|1<<2|1<<3)
	order.PutUint32(replace[36:], 4)
	order.PutUint32(replace[40:], size)
	for i := range 3 {
		hook := i + 1
		offset := i * policyEntry
		order.PutUint32(replace[44+4*hook:], uint32(offset))
		order.PutUint32(replace[64+4*hook:], uint32(offset))
		entry := replace[replaceHeader+offset:]
		order.PutUint16(entry[targetOffset:], entryHeader)
		order.PutUint16(entry[nextOffset:], policyEntry)
		target := entry[entryHeader:]
		order.PutUint16(target, policyEntry-entryHeader)
		verdict := acceptVerdict
		if hook == 2 && !accept {
			verdict = dropVerdict
		}
		order.PutUint32(target[verdictOffset:], verdict)
	}
	last := replace[replaceHeader+3*policyEntry:]
	order.PutUint16(last[targetOffset:], entryHeader)
	order.PutUint16(last[nextOffset:], errorEntry)
	terminal := last[entryHeader:]
	order.PutUint16(terminal, errorEntry-entryHeader)
	copy(terminal[2:], "ERROR")
	copy(terminal[32:], "ERROR")
	if err := unix.SetsockoptString(fd, unix.IPPROTO_IP, setReplace, string(replace)); err != nil {
		return fmt.Errorf("replace the guest filter table: %w", err)
	}
	return nil
}
