package gvxshim

import (
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func fullProcessBootstrapPipe(t *testing.T) *os.File {
	t.Helper()
	name := `\\.\pipe\gvx-test-bootstrap-` + rand.Text()
	pipeName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	dacl, err := protectedDACL()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(dacl)
	if err != nil {
		t.Fatal(err)
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	handle, err := windows.CreateNamedPipe(pipeName,
		windows.PIPE_ACCESS_OUTBOUND|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_NOWAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1, 4096, 0, 0, &attributes)
	if err != nil {
		t.Fatalf("create bootstrap pipe: %v", err)
	}
	writer := os.NewFile(uintptr(handle), name)
	t.Cleanup(func() {
		if err := writer.Close(); err != nil {
			t.Errorf("close bootstrap writer: %v", err)
		}
	})
	client, err := windows.CreateFile(pipeName, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatalf("open bootstrap reader: %v", err)
	}
	t.Cleanup(func() {
		if err := windows.CloseHandle(client); err != nil {
			t.Errorf("close bootstrap reader: %v", err)
		}
	})
	if err := windows.ConnectNamedPipe(handle, nil); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		t.Fatalf("connect bootstrap pipe: %v", err)
	}
	// Byte-mode PIPE_NOWAIT writes report zero progress only when the pipe is full.
	block := make([]byte, 4096)
	for {
		var written uint32
		if err := windows.WriteFile(handle, block, &written, nil); err != nil {
			t.Fatalf("fill bootstrap pipe: %v", err)
		}
		if written == 0 {
			break
		}
	}
	mode := uint32(windows.PIPE_WAIT)
	if err := windows.SetNamedPipeHandleState(handle, &mode, nil, nil); err != nil {
		t.Fatalf("set bootstrap pipe blocking mode: %v", err)
	}
	return writer
}
