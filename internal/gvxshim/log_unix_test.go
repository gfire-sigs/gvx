//go:build linux || darwin

package gvxshim

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestUnixLogUsesContainerdFIFO(t *testing.T) {
	paths := platformFixture(t)
	fifoPath := filepath.Join(paths.Identity.Bundle, "log")
	if err := unix.Mkfifo(fifoPath, 0600); err != nil {
		t.Fatal(err)
	}
	reader, err := unix.Open(fifoPath, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(reader)
	diagnostics, ref, err := createDiagnostics(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := diagnostics.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := openLog(t.Context(), paths, ref, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close(t.Context())
	const message = "containerd log record\n"
	if _, err := output.Writer.Write([]byte(message)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, len(message))
	deadline := time.Now().Add(5 * time.Second)
	for offset := 0; offset < len(data); {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatal("containerd FIFO record was not delivered")
		}
		poll := [1]unix.PollFd{{Fd: int32(reader), Events: unix.POLLIN}}
		if _, err := unix.Poll(poll[:], int((remaining+time.Millisecond-1)/time.Millisecond)); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			t.Fatal(err)
		}
		n, err := unix.Read(reader, data[offset:])
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		offset += n
	}
	if string(data) != message {
		t.Fatalf("FIFO record: %q", data)
	}
	if err := output.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fifoPath); err != nil {
		t.Fatalf("containerd FIFO removed: %v", err)
	}
}

func TestUnixLogWithoutReaderWritesDiagnostics(t *testing.T) {
	paths := platformFixture(t)
	fifoPath := filepath.Join(paths.Identity.Bundle, "log")
	if err := unix.Mkfifo(fifoPath, 0600); err != nil {
		t.Fatal(err)
	}
	file, ref, err := createDiagnostics(paths)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(fifoPath)
	if err != nil {
		t.Fatal(err)
	}
	id, err := platformInfoIdentity(info)
	if err != nil {
		t.Fatal(err)
	}
	sink := &unixLogSink{paths: paths, diagnostics: file, fifoID: &id, timeout: time.Second}
	defer sink.Close()
	if _, err := sink.Write([]byte("fallback")); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := paths.State.Root.ReadFile(ref.Name)
	if err != nil || string(data) != "fallback" {
		t.Fatalf("diagnostics: %q, %v", data, err)
	}
}

func TestUnixLogFullFIFOExpires(t *testing.T) {
	sink := fullFIFOLogFixture(t)
	sink.timeout = 20 * time.Millisecond
	if n, err := sink.Write([]byte("blocked")); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("full FIFO write = %d, %v; want deadline exceeded without bytes", n, err)
	}
}

func TestUnixLogCloseCancelsFullFIFO(t *testing.T) {
	sink := fullFIFOLogFixture(t)
	sink.timeout = time.Hour
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := sink.Write([]byte("blocked"))
		result <- err
	}()
	t.Cleanup(func() {
		sink.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("FIFO writer did not stop during cleanup")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		sink.mu.Lock()
		writing := sink.fifo != nil
		sink.mu.Unlock()
		if writing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("FIFO writer did not start")
		}
		runtime.Gosched()
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("cancelled FIFO write = %v, want closed file", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("closing the log did not cancel its blocked FIFO write")
	}
}

func fullFIFOLogFixture(t *testing.T) *unixLogSink {
	t.Helper()
	paths := platformFixture(t)
	path := filepath.Join(paths.Identity.Bundle, "log")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	reader, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(reader) })
	writer, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(writer)
	data := make([]byte, 4096)
	for len(data) > 0 {
		_, err := unix.Write(writer, data)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) {
			if len(data) == 1 {
				break
			}
			data = data[:1]
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	file, _, err := createDiagnostics(paths)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	id, err := platformInfoIdentity(info)
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	sink := &unixLogSink{paths: paths, diagnostics: file, fifoID: &id}
	t.Cleanup(func() { sink.Close() })
	return sink
}
