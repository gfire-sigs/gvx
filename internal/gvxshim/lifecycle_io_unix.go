//go:build linux || darwin

package gvxshim

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func boundedFileIO(ctx context.Context, file *os.File, operation func(io.ReadWriter) error) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	duplicate := -1
	var originalFlags int
	var descriptorError error
	err = raw.Control(func(descriptor uintptr) {
		originalFlags, descriptorError = unix.FcntlInt(descriptor, unix.F_GETFL, 0)
		if descriptorError != nil {
			return
		}
		duplicate, descriptorError = unix.FcntlInt(descriptor, unix.F_DUPFD_CLOEXEC, 0)
		if descriptorError != nil {
			return
		}
		descriptorError = unix.SetNonblock(duplicate, true)
	})
	if err != nil || descriptorError != nil {
		if duplicate >= 0 {
			descriptorError = errors.Join(descriptorError, unix.Close(duplicate))
		}
		return errors.Join(err, descriptorError)
	}
	// Duplicates share status flags, but the original Go wrapper must remain caller-owned.
	defer func() {
		restoreError := raw.Control(func(descriptor uintptr) { _, descriptorError = unix.FcntlInt(descriptor, unix.F_SETFL, originalFlags) })
		result = errors.Join(result, restoreError, descriptorError)
	}()
	owned := os.NewFile(uintptr(duplicate), file.Name())
	defer func() {
		closeError := owned.Close()
		if !errors.Is(closeError, os.ErrClosed) {
			result = errors.Join(result, closeError)
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := owned.SetDeadline(deadline); err != nil && !errors.Is(err, os.ErrNoDeadline) {
			return err
		}
	}
	cancelled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = owned.Close(); close(cancelled) })
	defer func() {
		if !stop() {
			<-cancelled
		}
		if ctx.Err() != nil {
			result = errors.Join(ctx.Err(), result)
		}
	}()
	return operation(owned)
}
