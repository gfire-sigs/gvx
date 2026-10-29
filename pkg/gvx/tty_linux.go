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

package gvx

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

func isHostTerminal(stream any) bool {
	f, ok := stream.(*os.File)
	if !ok || f == nil {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

func hostTerminalPath(_ io.Reader, _ io.Writer) string {
	return ""
}

func hostTerminalSize(in io.Reader, out io.Writer) (rows, cols uint16, ok bool) {
	for _, stream := range []any{out, in} {
		f, isFile := stream.(*os.File)
		if !isFile || f == nil {
			continue
		}
		ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
		if err == nil && ws.Row > 0 && ws.Col > 0 {
			return ws.Row, ws.Col, true
		}
	}
	return 0, 0, false
}

func enterHostRawMode(in io.Reader, _ io.Writer) (restore func(), active bool) {
	f, ok := in.(*os.File)
	if !ok || f == nil {
		return func() {}, false
	}
	fd := int(f.Fd())
	orig, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return func() {}, false
	}
	raw := *orig
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		return func() {}, false
	}
	return func() {
		_ = unix.IoctlSetTermios(fd, unix.TCSETS, orig)
	}, true
}

func watchHostWinch(ctx context.Context, in io.Reader, out io.Writer, onResize func(rows, cols uint16)) func() {
	if !isHostTerminal(in) && !isHostTerminal(out) {
		return func() {}
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-sigCh:
				if rows, cols, ok := hostTerminalSize(in, out); ok {
					onResize(rows, cols)
				}
			case <-ctx.Done():
				return
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(sigCh)
		close(done)
	}
}
