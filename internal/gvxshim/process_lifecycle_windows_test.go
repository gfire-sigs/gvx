package gvxshim

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"golang.org/x/sys/windows"
)

func processStopAdmissionClosed(_ context.Context, address string, held net.Conn) (bool, error) {
	pipe, ok := held.(interface{ Fd() uintptr })
	if !ok {
		return false, fmt.Errorf("stop connection %T does not expose its pipe handle", held)
	}
	var instances uint32
	if err := windows.GetNamedPipeHandleState(windows.Handle(pipe.Fd()), nil, &instances, nil, nil, nil, 0); err != nil {
		return false, err
	}
	// go-winio retains an extra disconnected instance until its listener closes.
	// Only the held connection must remain before probing admission without DialPipeContext's busy retry.
	if instances != 1 {
		return false, nil
	}
	name, err := windows.UTF16PtrFromString(address)
	if err != nil {
		return false, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_ANONYMOUS, 0)
	if errors.Is(err, windows.ERROR_PIPE_BUSY) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, windows.CloseHandle(handle)
}

func processGatePeerClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, windows.WSAECONNRESET)
}
