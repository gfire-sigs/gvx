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

package e2e

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

// TestE2EHostPTYInteractiveShell verifies that attaching a real host PTY to a
// guest shell puts the host terminal into raw mode, prevents double echo,
// propagates window dimensions, supports /dev/tty and canonical line editing,
// delivers Ctrl+C (SIGINT) to a foreground job without killing the shell, and
// restores the host terminal state on exit.
func TestE2EHostPTYInteractiveShell(t *testing.T) {
	requireRegistry(t)

	ptmx, ttyFile, err := pty.Open()
	if err != nil {
		t.Fatalf("pty.Open: %v", err)
	}
	defer func() {
		_ = ptmx.Close()
		_ = ttyFile.Close()
	}()

	if err := pty.Setsize(ptmx, &pty.Winsize{Rows: 40, Cols: 120}); err != nil {
		t.Fatalf("pty.Setsize: %v", err)
	}

	origTermios, err := unix.IoctlGetTermios(int(ttyFile.Fd()), unix.TIOCGETA)
	if err != nil {
		t.Fatalf("IoctlGetTermios before Run: %v", err)
	}

	out := newOutputLog()
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		_, _ = io.Copy(out, ptmx)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cfg := guestSpec{
		plat:  autoPlatform(),
		image: busyboxImage,
		argv:  []string{"/bin/busybox", "ash"},
		envv: []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"HOME=/root",
			"TERM=xterm",
			"PS1=" + ashPrompt,
		},
		stdin: ttyFile,
		tty:   true,
	}.config(sharedCacheDir(t), ttyFile, ttyFile)

	sb, err := gvx.New(ctx, cfg)
	if err != nil {
		t.Fatalf("gvx.New: %v", err)
	}
	defer func() {
		if err := sb.Close(); err != nil {
			t.Errorf("sb.Close: %v", err)
		}
	}()

	runDone := make(chan guestResult, 1)
	go func() {
		code, rErr := sb.Run(ctx)
		runDone <- guestResult{code: code, err: rErr}
	}()

	doneSig := make(chan struct{})
	var res guestResult
	go func() {
		res = <-runDone
		close(doneSig)
	}()

	pos := out.waitFor(t, 0, ashPrompt, sessionStep, doneSig)

	// 1. Verify single echo (zero double echo) and \r handling in xterm line-editing mode.
	cmd := "echo $((19+23))"
	if _, err := io.WriteString(ptmx, cmd+"\r"); err != nil {
		t.Fatalf("write %q: %v", cmd, err)
	}
	out.waitFor(t, pos, "42\r\n", sessionStep, doneSig)
	nextPos := out.waitFor(t, pos, ashPrompt, sessionStep, doneSig)
	segment := out.String()[pos:nextPos]
	if count := strings.Count(segment, "19+23"); count != 1 {
		t.Fatalf("command echoed %d times in transcript segment %q, want 1", count, segment)
	}
	pos = nextPos

	// 2. Verify TIOCGWINSZ reports the host PTY window dimensions (40x120).
	if _, err := io.WriteString(ptmx, "stty size\r"); err != nil {
		t.Fatalf("write stty size: %v", err)
	}
	out.waitFor(t, pos, "40 120\r\n", sessionStep, doneSig)
	pos = out.waitFor(t, pos, ashPrompt, sessionStep, doneSig)

	// 3. Verify /dev/tty controlling terminal works.
	if _, err := io.WriteString(ptmx, "echo ctty-ok > /dev/tty\r"); err != nil {
		t.Fatalf("write /dev/tty command: %v", err)
	}
	out.waitFor(t, pos, "ctty-ok\r\n", sessionStep, doneSig)
	pos = out.waitFor(t, pos, ashPrompt, sessionStep, doneSig)

	// 4. Start foreground `cat` (cooked ICANON|ECHO|ISIG mode), test Backspace (0x7f), then interrupt with Ctrl+C (0x03).
	if _, err := io.WriteString(ptmx, "sh -c 'echo CAT_READY; exec cat'\r"); err != nil {
		t.Fatalf("write cat launcher: %v", err)
	}
	pos = out.waitFor(t, pos, "CAT_READY\r\n", sessionStep, doneSig)
	if _, err := ptmx.Write([]byte{'h', 'e', 'l', 'o', 0x7f, 'l', 'o', '\r'}); err != nil {
		t.Fatalf("write canonical line to cat: %v", err)
	}
	// cat echoes "hello\r\n" after receiving the edited canonical line.
	pos = out.waitFor(t, pos, "\r\nhello\r\n", sessionStep, doneSig)

	// Send Ctrl+C (0x03) to terminate foreground `cat` and return to ash prompt.
	if _, err := ptmx.Write([]byte{0x03}); err != nil {
		t.Fatalf("write Ctrl+C: %v", err)
	}
	pos = out.waitFor(t, pos, ashPrompt, sessionStep, doneSig)

	// 5. Exit cleanly and verify host terminal attributes are restored.
	if _, err := io.WriteString(ptmx, "exit 0\r"); err != nil {
		t.Fatalf("write exit 0: %v", err)
	}
	select {
	case <-doneSig:
	case <-time.After(sessionStep):
		t.Fatalf("guest did not exit after exit 0; transcript:\n%s", out.String())
	}
	if res.err != nil || res.code != 0 {
		t.Fatalf("sb.Run = (%d, %v), want (0, nil)", res.code, res.err)
	}

	afterTermios, err := unix.IoctlGetTermios(int(ttyFile.Fd()), unix.TIOCGETA)
	if err != nil {
		t.Fatalf("IoctlGetTermios after Run: %v", err)
	}
	if afterTermios.Lflag != origTermios.Lflag || afterTermios.Iflag != origTermios.Iflag || afterTermios.Oflag != origTermios.Oflag {
		t.Fatalf("termios after Run = %+v, want restored %+v", afterTermios, origTermios)
	}
}
