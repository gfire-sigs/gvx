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

//go:build darwin

package gvx

import (
	"testing"

	"github.com/creack/pty"
	"z.gfire.dev/gvx/internal/xsys/unix"
)

func TestHostTerminalPTYRawModeAndSize(t *testing.T) {
	ptmx, ttyFile, err := pty.Open()
	if err != nil {
		t.Fatalf("pty.Open: %v", err)
	}
	defer func() {
		_ = ptmx.Close()
		_ = ttyFile.Close()
	}()

	if !isHostTerminal(ttyFile) {
		t.Fatal("isHostTerminal(ttyFile) = false, want true")
	}
	if p := hostTerminalPath(ttyFile, ttyFile); p == "" {
		t.Fatal("hostTerminalPath(ttyFile) = empty, want /dev/ttys* path")
	}

	if err := pty.Setsize(ptmx, &pty.Winsize{Rows: 43, Cols: 132}); err != nil {
		t.Fatalf("pty.Setsize: %v", err)
	}
	rows, cols, ok := hostTerminalSize(ttyFile, ttyFile)
	if !ok || rows != 43 || cols != 132 {
		t.Fatalf("hostTerminalSize = (%d, %d, %v), want (43, 132, true)", rows, cols, ok)
	}

	origTermios, err := unix.IoctlGetTermios(int(ttyFile.Fd()), unix.TIOCGETA)
	if err != nil {
		t.Fatalf("IoctlGetTermios before raw: %v", err)
	}
	restore, active := enterHostRawMode(ttyFile, ttyFile)
	if !active {
		t.Fatal("enterHostRawMode = false, want true")
	}
	rawTermios, err := unix.IoctlGetTermios(int(ttyFile.Fd()), unix.TIOCGETA)
	if err != nil {
		t.Fatalf("IoctlGetTermios in raw mode: %v", err)
	}
	if rawTermios.Lflag&(unix.ECHO|unix.ICANON|unix.ISIG) != 0 {
		t.Fatalf("raw Lflag = %#x, still has ECHO/ICANON/ISIG set", rawTermios.Lflag)
	}
	restore()

	afterTermios, err := unix.IoctlGetTermios(int(ttyFile.Fd()), unix.TIOCGETA)
	if err != nil {
		t.Fatalf("IoctlGetTermios after restore: %v", err)
	}
	if afterTermios.Lflag != origTermios.Lflag || afterTermios.Iflag != origTermios.Iflag || afterTermios.Oflag != origTermios.Oflag {
		t.Fatalf("termios after restore = %+v, want %+v", afterTermios, origTermios)
	}
}
