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

package oci

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func isTerminalFile(f *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}

// readPasswordFile reads a line from the console f with echo off. It restores
// the console mode before it returns.
func readPasswordFile(f *os.File) (string, error) {
	handle := windows.Handle(f.Fd())
	var saved uint32
	if err := windows.GetConsoleMode(handle, &saved); err != nil {
		return "", fmt.Errorf("read the console mode: %w", err)
	}
	quiet := saved&^windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT
	if err := windows.SetConsoleMode(handle, quiet); err != nil {
		return "", fmt.Errorf("turn the console echo off: %w", err)
	}
	line, readErr := ReadLine(f)
	if err := windows.SetConsoleMode(handle, saved); err != nil && readErr == nil {
		readErr = fmt.Errorf("restore the console mode: %w", err)
	}
	return line, readErr
}
