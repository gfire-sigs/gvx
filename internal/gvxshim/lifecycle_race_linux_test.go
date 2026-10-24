//go:build linux

package gvxshim

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDeletePreservesEvidenceWhenBothServingLoopsAreUnresponsive(t *testing.T) {
	child := startLifecycleChild(t)
	lease := holdProcessLease(t, child.record)
	admitted, err := admitDelete(t.Context(), child.record.Identity)
	if err != nil {
		t.Fatal(err)
	}
	defer admitted.Close()
	recordPath := filepath.Join(child.fixture.bundle, ".gvx-shim", "state.json")
	before, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	diagnostics, err := inspectEntry(admitted.Paths.State, "diagnostics.log", regularEntry)
	if err != nil {
		t.Fatal(err)
	}
	if err := child.command.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	resumed := false
	defer func() {
		if !resumed {
			if err := child.command.Process.Signal(syscall.SIGCONT); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Error(err)
			}
		}
	}()
	observed, cancelObservation := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelObservation()
	awaitLifecycleCondition(t, observed, "original child did not stop", func() (bool, error) {
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", child.command.Process.Pid))
		if err != nil {
			return false, err
		}
		return strings.Contains(string(status), "\nState:\tT"), nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	response, err := deleteInstance(ctx, admitted)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unresponsive delete = response %v, error %v; want deadline failure", response, err)
	}
	if response != nil {
		t.Fatalf("unresponsive delete returned a successful response: %v", response)
	}
	after, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("unresponsive delete removed state: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("unresponsive delete changed state evidence")
	}
	remaining, err := inspectEntry(admitted.Paths.State, "diagnostics.log", regularEntry)
	if err != nil {
		t.Fatalf("unresponsive delete removed diagnostics: %v", err)
	}
	if remaining != diagnostics {
		t.Fatal("unresponsive delete replaced diagnostics evidence")
	}
	if err := verifyBoundEndpoints(admitted.Paths, child.record); err != nil {
		t.Fatalf("unresponsive delete changed live endpoints: %v", err)
	}
	if err := tryLock(lease); !errors.Is(err, errLockBusy) {
		if err == nil {
			_ = unlock(lease)
		}
		t.Fatalf("unresponsive child lost its live lease: %v", err)
	}
	if err := child.command.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	resumed = true
	lifecycleDeleteResponse(t, child.fixture)
	<-child.done
}

func TestBoundedInputRestoresInheritedStatusFlags(t *testing.T) {
	var descriptors [2]int
	if err := unix.Pipe2(descriptors[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	reader := os.NewFile(uintptr(descriptors[0]), "inherited-reader")
	writer := os.NewFile(uintptr(descriptors[1]), "inherited-writer")
	defer reader.Close()
	defer writer.Close()
	original, err := unix.FcntlInt(uintptr(descriptors[0]), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if original&unix.O_NONBLOCK != 0 {
		t.Fatal("regression fixture is not an inherited blocking descriptor")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err = boundedFileIO(ctx, reader, func(stream io.ReadWriter) error {
		cancel()
		var data [1]byte
		_, err := stream.Read(data[:])
		return err
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("inherited read cancellation = %v", err)
	}
	restored, err := unix.FcntlInt(uintptr(descriptors[0]), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if restored != original {
		t.Fatalf("caller descriptor flags changed: before=%#x after=%#x", original, restored)
	}
}
