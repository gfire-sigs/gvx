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
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

func readFromTTY(t *testing.T, tty *ttyState, maxBytes int) (string, error) {
	t.Helper()
	buf := make([]byte, maxBytes)
	n, err := tty.read(gvcontext.Background(), usermem.BytesIOSequence(buf))
	return string(buf[:n]), err
}

func TestTTYReadlineNonCanonicalNoDoubleEcho(t *testing.T) {
	var out bytes.Buffer
	tty := newTTYState(nil, &out, true, 24, 80)

	// Simulate bash readline disabling ICANON, ECHO, and ICRNL via TCSETS.
	kt := tty.termios
	kt.LocalFlags &^= linux.ICANON | linux.ECHO
	kt.InputFlags &^= linux.ICRNL
	tty.setTermios(kt, false)

	// Keystrokes arrive one by one or in escape sequences from the raw host terminal.
	tty.consumeInput([]byte("ls"))
	tty.consumeInput([]byte("\x1b[A"))
	tty.consumeInput([]byte("\t\r"))

	if out.Len() != 0 {
		t.Fatalf("non-canonical !ECHO mode echoed %q, want empty output so readline echoes once", out.String())
	}

	got, err := readFromTTY(t, tty, 64)
	if err != nil {
		t.Fatalf("tty.read: %v", err)
	}
	if want := "ls\x1b[A\t\r"; got != want {
		t.Fatalf("tty.read = %q, want %q", got, want)
	}
}

func TestTTYCanonicalLineEditingAndEcho(t *testing.T) {
	var out bytes.Buffer
	tty := newTTYState(nil, &out, true, 24, 80)

	// Partial line without newline must block with ErrWouldBlock in ICANON mode.
	tty.consumeInput([]byte("helo"))
	if _, err := readFromTTY(t, tty, 64); !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
		t.Fatalf("read before newline = %v, want ErrWouldBlock", err)
	}

	// Backspace (0x7f) erases 'o', then "lo\r" finishes the line (with ICRNL \r -> \n).
	tty.consumeInput([]byte{0x7f, 'l', 'o', '\r'})
	got, err := readFromTTY(t, tty, 64)
	if err != nil {
		t.Fatalf("tty.read after newline: %v", err)
	}
	if want := "hello\n"; got != want {
		t.Fatalf("canonical line = %q, want %q", got, want)
	}
	if wantEcho := "helo\b \blo\r\n"; out.String() != wantEcho {
		t.Fatalf("echo output = %q, want %q", out.String(), wantEcho)
	}
}

func TestTTYCanonicalWordEraseAndLineKill(t *testing.T) {
	var out bytes.Buffer
	tty := newTTYState(nil, &out, true, 24, 80)

	// Type "echo bad_word", erase word with Ctrl+W (0x17), type "good\r".
	tty.consumeInput([]byte("echo bad_word"))
	tty.consumeInput([]byte{0x17})
	tty.consumeInput([]byte("good\r"))

	got, err := readFromTTY(t, tty, 64)
	if err != nil {
		t.Fatalf("tty.read after VWERASE: %v", err)
	}
	if want := "echo good\n"; got != want {
		t.Fatalf("after VWERASE = %q, want %q", got, want)
	}

	// Type "discard this", kill line with Ctrl+U (0x15), type "keep\r".
	tty.consumeInput([]byte("discard this"))
	tty.consumeInput([]byte{0x15})
	tty.consumeInput([]byte("keep\r"))

	got, err = readFromTTY(t, tty, 64)
	if err != nil {
		t.Fatalf("tty.read after VKILL: %v", err)
	}
	if want := "keep\n"; got != want {
		t.Fatalf("after VKILL = %q, want %q", got, want)
	}
}

func TestTTYCanonicalVEOFBehaviors(t *testing.T) {
	var out bytes.Buffer
	tty := newTTYState(nil, &out, true, 24, 80)

	// 1. Ctrl+D (0x04) on non-empty line flushes pending bytes without newline.
	tty.consumeInput([]byte{'a', 'b', 'c', 0x04})
	got, err := readFromTTY(t, tty, 64)
	if err != nil {
		t.Fatalf("read after non-empty VEOF: %v", err)
	}
	if got != "abc" {
		t.Fatalf("read after non-empty VEOF = %q, want %q", got, "abc")
	}

	// 2. Ctrl+D (0x04) on empty line returns 0, io.EOF once, then allows further reads.
	tty.consumeInput([]byte{0x04})
	got, err = readFromTTY(t, tty, 64)
	if !errors.Is(err, io.EOF) || got != "" {
		t.Fatalf("read on empty VEOF = (%q, %v), want (\"\", io.EOF)", got, err)
	}

	// 3. Subsequent input after VEOF is still readable (e.g. bash after child cat exits).
	tty.consumeInput([]byte("pwd\r"))
	got, err = readFromTTY(t, tty, 64)
	if err != nil || got != "pwd\n" {
		t.Fatalf("read after VEOF recovery = (%q, %v), want (\"pwd\\n\", nil)", got, err)
	}
}

func TestTTYSignalCharacterFlushesInputAndEchoesCaret(t *testing.T) {
	var out bytes.Buffer
	tty := newTTYState(nil, &out, true, 24, 80)

	tty.consumeInput([]byte("partial"))
	out.Reset()
	// Ctrl+C (0x03) with ISIG | ECHO | ECHOCTL enabled.
	tty.consumeInput([]byte{0x03})

	if wantEcho := "^C\r\n"; out.String() != wantEcho {
		t.Fatalf("Ctrl+C echo = %q, want %q", out.String(), wantEcho)
	}
	if _, err := readFromTTY(t, tty, 64); !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
		t.Fatalf("read after Ctrl+C flush = %v, want ErrWouldBlock", err)
	}
}

func TestTTYWaitableReadinessAndONLCR(t *testing.T) {
	var out bytes.Buffer
	tty := newTTYState(nil, &out, true, 24, 80)
	fd := &stdioFD{reader: bytes.NewReader(nil), writer: &out, tty: tty, mu: tty.outMu}

	if r := fd.Readiness(waiter.ReadableEvents); r != 0 {
		t.Fatalf("Readiness before input = %#x, want 0", r)
	}
	tty.consumeInput([]byte("ok\r"))
	if r := fd.Readiness(waiter.ReadableEvents); r == 0 {
		t.Fatal("Readiness after newline = 0, want ReadableEvents")
	}

	n, err := fd.Write(gvcontext.Background(), usermem.BytesIOSequence([]byte("line1\nline2\n")), vfs.WriteOptions{})
	if err != nil || n != 12 {
		t.Fatalf("fd.Write = (%d, %v), want (12, nil)", n, err)
	}
	if want := "ok\r\nline1\r\nline2\r\n"; out.String() != want {
		t.Fatalf("output with ONLCR = %q, want %q", out.String(), want)
	}
}

func TestDevNullIsNotHostTerminal(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer func() {
		_ = f.Close()
	}()
	if isHostTerminalReader(f) {
		t.Fatalf("isHostTerminalReader(%s) = true, want false", os.DevNull)
	}
}
