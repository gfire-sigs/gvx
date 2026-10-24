//go:build linux || darwin

package gvxshim

import (
	"os"
	"testing"
	"time"
)

func fullProcessBootstrapPipe(t *testing.T) *os.File {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := writer.Close(); err != nil {
			t.Errorf("close bootstrap writer: %v", err)
		}
		if err := reader.Close(); err != nil {
			t.Errorf("close bootstrap reader: %v", err)
		}
	})
	if err := writer.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 4096)
	for {
		if _, err := writer.Write(block); err != nil {
			if !os.IsTimeout(err) {
				t.Fatalf("fill bootstrap pipe: %v", err)
			}
			break
		}
	}
	if err := writer.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	return writer
}
