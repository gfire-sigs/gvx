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

//go:build windows

package gvx

import (
	"context"
	"io"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func isHostTerminal(stream any) bool {
	f, ok := stream.(*os.File)
	if !ok || f == nil {
		return false
	}
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
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
		var info windows.ConsoleScreenBufferInfo
		if err := windows.GetConsoleScreenBufferInfo(windows.Handle(f.Fd()), &info); err != nil {
			continue
		}
		w := info.Window.Right - info.Window.Left + 1
		h := info.Window.Bottom - info.Window.Top + 1
		if w > 0 && h > 0 {
			return uint16(h), uint16(w), true
		}
	}
	return 0, 0, false
}

func enterHostRawMode(in io.Reader, out io.Writer) (restore func(), active bool) {
	inFile, ok := in.(*os.File)
	if !ok || inFile == nil {
		return func() {}, false
	}
	inHandle := windows.Handle(inFile.Fd())
	var origIn uint32
	if err := windows.GetConsoleMode(inHandle, &origIn); err != nil {
		return func() {}, false
	}
	rawIn := origIn &^ (windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT)
	rawIn |= windows.ENABLE_VIRTUAL_TERMINAL_INPUT
	if err := windows.SetConsoleMode(inHandle, rawIn); err != nil {
		return func() {}, false
	}

	var (
		outHandle  windows.Handle
		origOut    uint32
		restoreOut bool
	)
	if outFile, ok := out.(*os.File); ok && outFile != nil {
		h := windows.Handle(outFile.Fd())
		if windows.GetConsoleMode(h, &origOut) == nil {
			rawOut := origOut | windows.ENABLE_PROCESSED_OUTPUT | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
			if windows.SetConsoleMode(h, rawOut) == nil {
				outHandle = h
				restoreOut = true
			}
		}
	}

	return func() {
		_ = windows.SetConsoleMode(inHandle, origIn)
		if restoreOut {
			_ = windows.SetConsoleMode(outHandle, origOut)
		}
	}, true
}

func watchHostWinch(ctx context.Context, in io.Reader, out io.Writer, onResize func(rows, cols uint16)) func() {
	lastRows, lastCols, ok := hostTerminalSize(in, out)
	if !ok {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rows, cols, ok := hostTerminalSize(in, out)
				if ok && (rows != lastRows || cols != lastCols) {
					lastRows, lastCols = rows, cols
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
		close(done)
	}
}
