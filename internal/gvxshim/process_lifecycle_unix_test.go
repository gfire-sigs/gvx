//go:build linux || darwin

package gvxshim

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
)

func processStopAdmissionClosed(ctx context.Context, address string, _ net.Conn) (bool, error) {
	connection, err := dialLocal(ctx, address)
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, connection.Close()
}

func processGatePeerClosed(err error) bool {
	return errors.Is(err, io.EOF)
}
