//go:build windows

package gvxshim

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
)

func TestWindowsBoundedFileIOPipeAndDiskPreserveCompletedTransfer(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()

	want := []byte("pipe-complete")
	if _, err := writer.Write(want); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var got []byte
	err = boundedFileIO(ctx, reader, func(stream io.ReadWriter) error {
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(stream, buf); err != nil {
			return err
		}
		got = buf
		// Cancel after the transfer completes to verify nil result is preserved.
		cancel()
		return nil
	})
	if err != nil {
		t.Fatalf("completed pipe transfer returned error %v, want nil", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("pipe bytes = %q, want %q", got, want)
	}

	diskFile, err := os.CreateTemp(t.TempDir(), "bounded-disk")
	if err != nil {
		t.Fatal(err)
	}
	defer diskFile.Close()

	diskCtx, diskCancel := context.WithCancel(t.Context())
	defer diskCancel()
	err = boundedFileIO(diskCtx, diskFile, func(stream io.ReadWriter) error {
		if err := writeAll(stream, []byte("disk-payload")); err != nil {
			return err
		}
		diskCancel()
		return nil
	})
	if err != nil {
		t.Fatalf("completed disk write returned error %v, want nil", err)
	}

	cancelledCtx, cancelNow := context.WithCancel(t.Context())
	err = boundedFileIO(cancelledCtx, diskFile, func(stream io.ReadWriter) error {
		cancelNow()
		var b [1]byte
		_, readErr := stream.Read(b[:])
		return readErr
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled disk read = %v, want context.Canceled", err)
	}
}
