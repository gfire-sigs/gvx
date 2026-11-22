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
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	guestFilterInput   = 1
	guestFilterForward = 2
	guestFilterOutput  = 3
	guestFilterAccept  = ^uint32(1)
	guestFilterDrop    = ^uint32(0)
	guestVerdictOffset = 32
)

// These layouts describe the 64-bit Linux ip_tables and ip6_tables UAPI.
type guestFilterABI struct {
	family, level, entryHeader, targetOffset int
}

var (
	guestFilterV4 = guestFilterABI{unix.AF_INET, unix.IPPROTO_IP, 112, 88}
	guestFilterV6 = guestFilterABI{unix.AF_INET6, unix.IPPROTO_IPV6, 168, 140}
)

func (abi guestFilterABI) setPolicy(chain int, policy uint32) error {
	fd, err := unix.Socket(abi.family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open guest filter socket: %w", err)
	}
	defer unix.Close(fd)

	const replaceHeader = 96
	policyEntry := abi.entryHeader + 40
	errorEntry := abi.entryHeader + 64
	order := binary.NativeEndian
	size := 3*policyEntry + errorEntry
	replace := make([]byte, replaceHeader+size)
	copy(replace, "filter")
	order.PutUint32(replace[32:], 1<<1|1<<2|1<<3)
	order.PutUint32(replace[36:], 4)
	order.PutUint32(replace[40:], uint32(size))
	for i := range 3 {
		hook := i + 1
		offset := i * policyEntry
		order.PutUint32(replace[44+4*hook:], uint32(offset))
		order.PutUint32(replace[64+4*hook:], uint32(offset))
		entry := replace[replaceHeader+offset:]
		order.PutUint16(entry[abi.targetOffset:], uint16(abi.entryHeader))
		order.PutUint16(entry[abi.targetOffset+2:], uint16(policyEntry))
		target := entry[abi.entryHeader:]
		order.PutUint16(target, uint16(policyEntry-abi.entryHeader))
		verdict := guestFilterAccept
		if hook == chain {
			verdict = policy
		}
		order.PutUint32(target[guestVerdictOffset:], verdict)
	}
	last := replace[replaceHeader+3*policyEntry:]
	order.PutUint16(last[abi.targetOffset:], uint16(abi.entryHeader))
	order.PutUint16(last[abi.targetOffset+2:], uint16(errorEntry))
	terminal := last[abi.entryHeader:]
	order.PutUint16(terminal, uint16(errorEntry-abi.entryHeader))
	copy(terminal[2:], "ERROR")
	copy(terminal[32:], "ERROR")
	if err := unix.SetsockoptString(fd, abi.level, 64 /* SET_REPLACE */, string(replace)); err != nil {
		return fmt.Errorf("replace the guest filter table: %w", err)
	}
	return nil
}

func (abi guestFilterABI) expectPolicy(chain int, want uint32) error {
	fd, err := unix.Socket(abi.family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open guest filter socket: %w", err)
	}
	defer unix.Close(fd)
	get := func(option uintptr, data []byte) error {
		length := uint32(len(data))
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(abi.level), option,
			uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&length)), 0)
		if errno != 0 {
			return errno
		}
		if length != uint32(len(data)) {
			return fmt.Errorf("getsockopt returned %d bytes, want %d", length, len(data))
		}
		return nil
	}

	var info [84]byte
	copy(info[:], "filter")
	if err := get(64 /* GET_INFO */, info[:]); err != nil {
		return fmt.Errorf("read guest filter info for family %d: %w", abi.family, err)
	}
	order := binary.NativeEndian
	size := int(order.Uint32(info[80:]))
	const entriesHeader = 40
	if size < abi.entryHeader || size > 64<<10 {
		return fmt.Errorf("unexpected guest filter size %d", size)
	}
	table := make([]byte, entriesHeader+size)
	copy(table, "filter")
	order.PutUint32(table[32:], uint32(size))
	if err := get(65 /* GET_ENTRIES */, table); err != nil {
		return fmt.Errorf("read guest filter entries for family %d: %w", abi.family, err)
	}

	entryOffset := int(order.Uint32(info[56+4*chain:]))
	if entryOffset < 0 || entryOffset > size-abi.entryHeader {
		return fmt.Errorf("invalid chain %d policy offset %d", chain, entryOffset)
	}
	entry := table[entriesHeader+entryOffset:]
	targetOffset := int(order.Uint16(entry[abi.targetOffset:]))
	if targetOffset > len(entry)-guestVerdictOffset-4 {
		return fmt.Errorf("invalid chain %d target offset %d", chain, targetOffset)
	}
	if got := order.Uint32(entry[targetOffset+guestVerdictOffset:]); got != want {
		return fmt.Errorf("guest family %d chain %d verdict = %d, want %d", abi.family, chain, int32(got), int32(want))
	}
	return nil
}

func verifyGuestOutputDrop() error {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer listener.Close()
	conn, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("blocked")); err != nil {
		return err
	}
	if err := guestFilterV4.setPolicy(guestFilterOutput, guestFilterAccept); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("allowed")); err != nil {
		return err
	}
	if err := listener.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	var buf [16]byte
	n, err := listener.Read(buf[:])
	if err != nil {
		return fmt.Errorf("read guest loopback datagram after lifting DROP: %w", err)
	}
	if string(buf[:n]) != "allowed" {
		return fmt.Errorf("guest loopback delivered %q before OUTPUT DROP was lifted", buf[:n])
	}
	return nil
}
