package gvxshim

import (
	"bytes"
	"errors"
	"os"
	"sync"
	"testing"
)

type stalledLogSink struct {
	entered  chan []byte
	released chan struct{}
	once     sync.Once
}

func (s *stalledLogSink) Write(data []byte) (int, error) {
	s.entered <- data
	<-s.released
	return len(data), nil
}
func (s *stalledLogSink) Close() error { s.once.Do(func() { close(s.released) }); return nil }

func TestLogWriterBoundsQueuedRecordsWithoutBlockingCaller(t *testing.T) {
	sink := &stalledLogSink{entered: make(chan []byte, 65), released: make(chan struct{})}
	output := startBoundedLog(t.Context(), sink)
	t.Cleanup(func() { output.Close(t.Context()) })
	if _, err := output.Writer.Write(bytes.Repeat([]byte{'x'}, 4097)); !errors.Is(err, errLogRecordTooLarge) {
		t.Fatalf("oversize record: %v", err)
	}
	if n, err := output.Writer.Write(bytes.Repeat([]byte{'x'}, 4096)); err != nil || n != 4096 {
		t.Fatalf("maximum record: %d, %v", n, err)
	}
	<-sink.entered
	for i := range 64 {
		if _, err := output.Writer.Write([]byte("queued")); err != nil {
			t.Fatalf("queue record %d: %v", i, err)
		}
	}
	if _, err := output.Writer.Write([]byte("excess")); !errors.Is(err, errLogQueueFull) {
		t.Fatalf("full queue: %v", err)
	}
	if err := output.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Writer.Write([]byte("closed")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed logger: %v", err)
	}
}

func TestLogWriterCopiesAcceptedCallerBuffer(t *testing.T) {
	sink := &stalledLogSink{entered: make(chan []byte, 1), released: make(chan struct{})}
	output := startBoundedLog(t.Context(), sink)
	t.Cleanup(func() { output.Close(t.Context()) })
	data := []byte("original")
	if _, err := output.Writer.Write(data); err != nil {
		t.Fatal(err)
	}
	accepted := <-sink.entered
	copy(data, "mutated!")
	if string(accepted) != "original" {
		t.Fatalf("accepted record changed with caller buffer: %q", accepted)
	}
	if err := output.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}
