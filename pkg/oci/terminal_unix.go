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

//go:build linux || darwin

package oci

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func isTerminalFile(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), ioctlGetTermios)
	return err == nil
}

// readPasswordFile reads a line from the terminal f with echo off. It
// restores the terminal state before it returns.
func readPasswordFile(f *os.File) (string, error) {
	fd := int(f.Fd())
	saved, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return "", fmt.Errorf("read the terminal state: %w", err)
	}
	quiet := *saved
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON | unix.ISIG
	quiet.Iflag |= unix.ICRNL
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &quiet); err != nil {
		return "", fmt.Errorf("turn the terminal echo off: %w", err)
	}
	line, readErr := ReadLine(f)
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, saved); err != nil && readErr == nil {
		readErr = fmt.Errorf("restore the terminal state: %w", err)
	}
	return line, readErr
}
