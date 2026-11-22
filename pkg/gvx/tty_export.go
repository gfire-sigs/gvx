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
	"context"
	"io"
)

// IsHostTerminal reports whether stream is an interactive host terminal.
func IsHostTerminal(stream any) bool {
	return isHostTerminal(stream)
}

// HostTerminalSize returns the current rows and columns of a host terminal.
func HostTerminalSize(in io.Reader, out io.Writer) (rows, cols uint16, ok bool) {
	return hostTerminalSize(in, out)
}

// EnterHostRawMode switches the host terminal to raw mode and returns a restore
// function and whether raw mode was activated.
func EnterHostRawMode(in io.Reader, out io.Writer) (restore func(), active bool) {
	return enterHostRawMode(in, out)
}

// WatchHostWinch invokes onResize when the host terminal size changes until ctx
// ends or the returned stop function is called.
func WatchHostWinch(ctx context.Context, in io.Reader, out io.Writer, onResize func(rows, cols uint16)) func() {
	return watchHostWinch(ctx, in, out, onResize)
}
