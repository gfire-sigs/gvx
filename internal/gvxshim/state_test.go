package gvxshim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func lifecycleIdentity(t *testing.T) instanceIdentity {
	t.Helper()
	owner, err := currentOwner()
	if err != nil {
		t.Fatal(err)
	}
	address := "/tmp/containerd-gvx-state-test.sock"
	if runtime.GOOS == "windows" {
		address = `\\.\pipe\containerd-gvx-state-test`
	}
	address, err = normalizeContainerdAddress(address)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := canonicalBundle(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return instanceIdentity{Owner: owner, ContainerdAddress: address, Namespace: "gvx-test", ID: "state-test", Bundle: bundle}
}

func lifecyclePrepared(t *testing.T) (*instancePaths, stateRecord, ownedEntry) {
	t.Helper()
	paths, err := openPaths(t.Context(), lifecycleIdentity(t), createPaths)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareEndpointDir(t.Context(), paths); err != nil {
		paths.Close()
		t.Fatal(err)
	}
	diagnostics, logRef, err := createDiagnostics(paths)
	if err != nil {
		paths.Close()
		t.Fatal(err)
	}
	if err := diagnostics.Close(); err != nil {
		t.Fatal(err)
	}
	record := stateRecord{Version: 1, Phase: recordPrepared, Identity: paths.Identity, Generation: strings.Repeat("ab", 32), Paths: paths.Snapshot, Task: endpointRef{Address: paths.TaskAddress}, Stop: endpointRef{Address: paths.StopAddress}, Log: logRef}
	ref, err := publishRecord(paths, record)
	if err != nil {
		paths.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Tests own this generation and all files below its private boundary.
		if paths.UnixEndpointDir != nil {
			_ = removeEndpointDir(paths, paths.UnixEndpointDir.ID)
		}
		if err := paths.Close(); err != nil {
			t.Error(err)
		}
	})
	return paths, record, ref
}

func TestDeleteCleansPreparedStateButRetainsStableLocks(t *testing.T) {
	paths, _, _ := lifecyclePrepared(t)
	admission, err := admitDelete(t.Context(), paths.Identity)
	if err != nil {
		t.Fatal(err)
	}
	defer admission.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	response, err := deleteInstance(ctx, admission)
	if err != nil {
		t.Fatal(err)
	}
	if response.Pid != 0 || response.ExitStatus != 0 || response.ExitedAt == nil {
		t.Fatalf("cleanup response = %v", response)
	}
	for _, name := range []string{"state.json", "diagnostics.log"} {
		if _, err := os.Lstat(filepath.Join(paths.Identity.Bundle, ".gvx-shim", name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s after cleanup: %v", name, err)
		}
	}
	for _, name := range []lockName{commandLock, lifetimeLease} {
		stable, err := openLock(paths, name)
		if err != nil {
			t.Fatalf("stable lock removed: %v", err)
		}
		if err := stable.Close(); err != nil {
			t.Fatal(err)
		}
	}
	repeated, err := admitDelete(t.Context(), paths.Identity)
	if err != nil {
		t.Fatal(err)
	}
	defer repeated.Close()
	if _, err := deleteInstance(ctx, repeated); err != nil {
		t.Fatalf("repeated cleanup: %v", err)
	}
}

func TestDeleteDoesNotAdoptReplacementGeneration(t *testing.T) {
	paths, record, ref := lifecyclePrepared(t)
	admission, err := admitDelete(t.Context(), paths.Identity)
	if err != nil {
		t.Fatal(err)
	}
	defer admission.Close()
	if err := removeOwned(paths.State, ref); err != nil {
		t.Fatal(err)
	}
	record.Generation = strings.Repeat("cd", 32)
	if _, err := publishRecord(paths, record); err != nil {
		t.Fatal(err)
	}
	if _, err := deleteInstance(t.Context(), admission); !errors.Is(err, errConflict) {
		t.Fatalf("replacement delete = %v, want ownership conflict", err)
	}
	remaining, _, err := readRecord(paths)
	if err != nil {
		t.Fatal(err)
	}
	if remaining == nil || remaining.Generation != record.Generation {
		t.Fatal("delete modified replacement generation")
	}
}

func TestDeleteDoesNotAdoptStateAfterAbsentAdmission(t *testing.T) {
	id := lifecycleIdentity(t)
	admission, err := admitDelete(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	defer admission.Close()
	paths, err := openPaths(t.Context(), id, createPaths)
	if err != nil {
		t.Fatal(err)
	}
	defer paths.Close()
	if _, err := deleteInstance(t.Context(), admission); err == nil {
		t.Fatal("delete accepted state created after absent admission")
	}
	stable, err := openLock(paths, commandLock)
	if err != nil {
		t.Fatalf("new coordination artifacts changed: %v", err)
	}
	stable.Close()
}

func TestStateReaderRejectsUnknownVersionWithoutDeletingRecord(t *testing.T) {
	paths, record, ref := lifecyclePrepared(t)
	record.Version = 2
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	file, err := openPrivateFile(paths.State, "state.json", os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAll(file, data); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := admitDelete(t.Context(), paths.Identity); !errors.Is(err, errInvalidState) {
		t.Fatalf("unknown state version = %v", err)
	}
	actual, err := inspectEntry(paths.State, "state.json", regularEntry)
	if err != nil {
		t.Fatal(err)
	}
	if actual.Identity != ref.Identity {
		t.Fatal("state reader replaced invalid record")
	}
}

func TestPrivateFrameRejectsOversizedLength(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := writer.Write([]byte{0, 1, 0, 1}); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	var report boundReport
	if err := readPrivateFrame(t.Context(), reader, &report); !errors.Is(err, errInvalidState) {
		t.Fatalf("oversized frame = %v", err)
	}
}

func TestDeletePreservesMalformedRecord(t *testing.T) {
	for _, data := range []string{`{"version":1,"phase":`, `{"version":1} {}`} {
		t.Run(data, func(t *testing.T) {
			paths, record, ref := lifecyclePrepared(t)
			file, err := openPrivateFile(paths.State, "state.json", os.O_WRONLY|os.O_TRUNC, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeAll(file, []byte(data)); err != nil {
				file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if admission, err := admitDelete(t.Context(), paths.Identity); !errors.Is(err, errInvalidState) {
				if admission != nil {
					admission.Close()
				}
				t.Fatalf("malformed record admission = %v, want invalid state", err)
			}
			remaining, err := os.ReadFile(filepath.Join(paths.Identity.Bundle, ".gvx-shim", "state.json"))
			if err != nil {
				t.Fatalf("malformed record removed: %v", err)
			}
			if !bytes.Equal(remaining, []byte(data)) {
				t.Fatal("delete changed malformed record bytes")
			}
			actual, err := inspectEntry(paths.State, "state.json", regularEntry)
			if err != nil || actual != ref {
				t.Fatalf("malformed record ownership changed: reference=%v error=%v", actual, err)
			}
			diagnostics, err := inspectEntry(paths.State, "diagnostics.log", regularEntry)
			if err != nil || diagnostics != record.Log {
				t.Fatalf("malformed record admission changed diagnostics: reference=%v error=%v", diagnostics, err)
			}
		})
	}
}

func TestBoundedInputCancellationKeepsCallerDescriptor(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err = boundedFileIO(ctx, reader, func(stream io.ReadWriter) error {
		cancel()
		var data [1]byte
		_, err := stream.Read(data[:])
		return err
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled input = %v, want cancellation", err)
	}
	if _, err := writer.Write([]byte{7}); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := io.ReadFull(reader, data[:]); err != nil {
		t.Fatalf("cancellation closed caller descriptor: %v", err)
	}
	if data[0] != 7 {
		t.Fatalf("caller input after cancellation = %d, want 7", data[0])
	}
}

func TestPrivateFramePreservesRedirectedFilePosition(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "private-frame")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	prefix := []byte("retained-prefix")
	if err := writeAll(file, prefix); err != nil {
		t.Fatal(err)
	}
	expected := boundReport{PID: 17, Error: "redirected private frame"}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := writePrivateFrame(ctx, file, expected); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(int64(len(prefix)), io.SeekStart); err != nil {
		t.Fatal(err)
	}
	var actual boundReport
	if err := readPrivateFrame(ctx, file, &actual); err != nil {
		t.Fatalf("read redirected frame after prefix: %v", err)
	}
	if actual.PID != expected.PID || actual.Error != expected.Error {
		t.Fatalf("redirected frame = %+v, want PID %d and error %q", actual, expected.PID, expected.Error)
	}
}

func TestExpiredLifecycleDoesNotWaitForDiagnosticReader(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	writeCommandError(ctx, writer, context.DeadlineExceeded)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if n, err := reader.Read(data[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("expired lifecycle attempted diagnostic output: n=%d err=%v", n, err)
	}
}
