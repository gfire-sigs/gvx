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

//go:build darwin || windows || linux

package e2e

import (
	"bytes"
	"context"
	"debug/elf"
	"io"
	"runtime"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
)

// M2 gate of SPEC section 4: boot static busybox as guest PID 1 on the
// hardware backend and run commands at an interactive busybox ash prompt.

const (
	busyboxImage = "busybox:1.36.1-musl"
	ashPrompt    = "gvx-ash$ "
	// sessionStep bounds one prompt round trip. The guest answers in
	// milliseconds, so the bound only catches a hung guest.
	sessionStep = 90 * time.Second
)

// ashSession drives one interactive guest shell through Config.Stdin.
type ashSession struct {
	t    *testing.T
	in   *io.PipeWriter
	out  *outputLog
	pos  int
	done chan struct{}
	res  guestResult
}

// startAshSession boots busybox as the guest process and returns after the
// first prompt appears.
func startAshSession(t *testing.T, plat gvx.PlatformType, argv []string, tty bool) *ashSession {
	t.Helper()
	pr, pw := io.Pipe()
	s := &ashSession{t: t, in: pw, out: newOutputLog(), done: make(chan struct{})}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	spec := guestSpec{
		plat:  plat,
		image: busyboxImage,
		argv:  argv,
		envv: []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"HOME=/root",
			"TERM=dumb",
			"PS1=" + ashPrompt,
		},
		stdin: pr,
		tty:   tty,
	}
	sb, err := gvx.New(ctx, spec.config(sharedCacheDir(t), s.out, s.out))
	if err != nil {
		cancel()
		t.Fatalf("gvx.New(%s, %s) failed: %v", plat, busyboxImage, err)
	}
	go func() {
		defer close(s.done)
		s.res.code, s.res.err = sb.Run(ctx)
	}()
	t.Cleanup(func() {
		// Closing stdin first ends a guest that still reads it. Cancel
		// follows, so a stuck guest gets SIGKILL.
		_ = pw.CloseWithError(io.ErrClosedPipe)
		cancel()
		<-s.done
		if err := sb.Close(); err != nil {
			t.Errorf("Close(%s) failed: %v", plat, err)
		}
	})
	s.pos = s.out.waitFor(t, 0, ashPrompt, sessionStep, s.done)
	return s
}

// send writes one command line to the guest. It fails the test when the guest
// ended before it consumed the line.
func (s *ashSession) send(line string) {
	s.t.Helper()
	written := make(chan error, 1)
	go func() {
		_, err := io.WriteString(s.in, line+"\n")
		written <- err
	}()
	select {
	case err := <-written:
		if err != nil {
			s.t.Fatalf("write %q to guest stdin: %v", line, err)
		}
	case <-s.done:
		s.t.Fatalf("guest ended before it read %q; transcript:\n%s", line, s.out.String())
	}
}

// do sends line, waits for want in the output and then for the next prompt.
// It returns the output between the command and the next prompt.
func (s *ashSession) do(line, want string) string {
	s.t.Helper()
	start := s.pos
	s.send(line)
	s.out.waitFor(s.t, start, want, sessionStep, s.done)
	s.pos = s.out.waitFor(s.t, start, ashPrompt, sessionStep, s.done)
	return s.out.String()[start:s.pos]
}

// finish closes stdin after the guest exits on its own and returns the exit
// code.
func (s *ashSession) finish() guestResult {
	s.t.Helper()
	select {
	case <-s.done:
	case <-time.After(sessionStep):
		s.t.Fatalf("guest still running after exit; transcript:\n%s", s.out.String())
	}
	return s.res
}

// busyboxBinary returns the bytes of /bin/busybox as the guest sees them.
func busyboxBinary(t *testing.T, plat gvx.PlatformType) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	sb, err := gvx.New(ctx, guestSpec{
		plat:  plat,
		image: busyboxImage,
		argv:  []string{"/bin/busybox", "cat", "/bin/busybox"},
	}.config(sharedCacheDir(t), &stdout, &stderr))
	if err != nil {
		t.Fatalf("gvx.New(%s, %s) failed: %v", plat, busyboxImage, err)
	}
	defer func() {
		if err := sb.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	}()
	code, err := sb.Run(ctx)
	if err != nil || code != 0 {
		t.Fatalf("cat /bin/busybox = (%d, %v), stderr=%s", code, err, stderr.String())
	}
	return stdout.Bytes()
}

// requireStaticELF fails the test unless data is a static ELF64 executable of
// the host architecture: no interpreter and no needed libraries.
func requireStaticELF(t *testing.T, data []byte) {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse busybox ELF (%d bytes): %v", len(data), err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close ELF: %v", err)
		}
	}()
	wantMachine := elf.EM_X86_64
	if runtime.GOARCH == "arm64" {
		wantMachine = elf.EM_AARCH64
	}
	if f.Class != elf.ELFCLASS64 || f.Machine != wantMachine {
		t.Fatalf("busybox ELF = (%v, %v), want (ELFCLASS64, %v)", f.Class, f.Machine, wantMachine)
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			t.Fatalf("busybox has a PT_INTERP program header, so it is dynamically linked")
		}
	}
	libs, err := f.ImportedLibraries()
	if err != nil {
		t.Fatalf("read DT_NEEDED entries: %v", err)
	}
	if len(libs) != 0 {
		t.Fatalf("busybox needs shared libraries %v, so it is not static", libs)
	}
}

func TestE2EGateM2BusyboxIsStatic(t *testing.T) {
	requireRegistry(t)
	requireStaticELF(t, busyboxBinary(t, autoPlatform()))
}

// TestE2EGateM2BusyboxAshInteractive drives a real interactive ash through
// Config.Stdin. Each command waits for its own output and the next prompt, so
// the test follows the guest instead of sleeping.
func TestE2EGateM2BusyboxAshInteractive(t *testing.T) {
	requireRegistry(t)
	for _, tc := range []struct {
		name string
		argv []string
		tty  bool
		// stdinKind is what `test -t 0` reports for the guest stdin.
		stdinKind string
	}{
		{"forced_interactive_on_pipe", []string{"/bin/busybox", "ash", "-i"}, false, "pipe"},
		{"terminal_line_discipline", []string{"/bin/busybox", "ash"}, true, "tty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := startAshSession(t, autoPlatform(), tc.argv, tc.tty)

			s.do(`echo "stdin=$(if [ -t 0 ]; then echo tty; else echo pipe; fi)"`, "stdin="+tc.stdinKind+"\n")

			// The shell is the first guest process, so its PID is 1.
			requireContains(t, "pid", s.do(`echo "pid=$$"`, "pid=1\n"), "pid=1\n")
			requireContains(t, "uname", s.do(`echo "os=$(uname -s)"`, "os=Linux\n"), "os=Linux\n")

			// A pipeline joins three guest processes through kernel pipes.
			requireContains(t, "pipeline", s.do(`echo hello gvx | tr a-z A-Z | rev`, "XVG OLLEH\n"), "XVG OLLEH\n")

			// Shell state persists between prompts.
			s.do(`N=41`, ashPrompt)
			requireContains(t, "arithmetic", s.do(`echo "sum=$((N + 1))"`, "sum=42\n"), "sum=42\n")

			// File writes and reads reach tmpfs through the same session.
			s.do(`cd /tmp && echo payload > f.txt`, ashPrompt)
			requireContains(t, "file", s.do(`echo "len=$(wc -c < f.txt) data=$(cat f.txt)"`, "len=8 data=payload\n"), "len=8 data=payload\n")

			// Exit statuses of failing commands reach the shell.
			requireContains(t, "status", s.do(`false; echo "rc=$?"`, "rc=1\n"), "rc=1\n")

			if tc.tty {
				requireContains(t, "dev_tty", s.do(`echo "ctty=ok" > /dev/tty`, "ctty=ok\n"), "ctty=ok\n")
				requireContains(t, "stty_size", s.do(`echo "winsize=$(stty size)"`, "winsize=24 80\n"), "winsize=24 80\n")
			}

			s.send("exit 7")
			res := s.finish()
			if res.err != nil || res.code != 7 {
				t.Fatalf("guest after exit 7 = (%d, %v), want (7, nil); transcript:\n%s", res.code, res.err, s.out.String())
			}
		})
	}
}
