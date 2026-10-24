package gvxshim

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	taskv2 "github.com/containerd/containerd/api/runtime/task/v2"
	task "github.com/containerd/containerd/api/runtime/task/v3"
	"google.golang.org/protobuf/proto"
)

func lifecycleDeleteResponse(t *testing.T, fixture *processFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	output, stderr, err := fixture.command(ctx, "delete", nil)
	if err != nil {
		t.Fatalf("delete instance: %v; stderr=%s", err, stderr)
	}
	var response taskv2.DeleteResponse
	if err := proto.Unmarshal(output, &response); err != nil {
		t.Fatalf("decode delete response: %v", err)
	}
	if response.Pid != 0 || response.ExitStatus != 0 || response.ExitedAt == nil {
		t.Fatalf("delete response = %v", &response)
	}
}

func assertLifecycleGenerationAlive(t *testing.T, record stateRecord) {
	t.Helper()
	client, ctx := processClient(t, record)
	assertProcessConnect(t, ctx, client, record)
	lease := holdProcessLease(t, record)
	if err := tryLock(lease); !errors.Is(err, errLockBusy) {
		if err == nil {
			_ = unlock(lease)
		}
		t.Fatalf("replacement generation lost its lifetime lease: %v", err)
	}
	admission, err := admitDelete(ctx, record.Identity)
	if err != nil {
		t.Fatalf("read replacement generation: %v", err)
	}
	defer admission.Close()
	if admission.Record == nil || !reflect.DeepEqual(*admission.Record, record) {
		t.Fatal("delayed delete changed the replacement record")
	}
	if err := verifyBoundEndpoints(admission.Paths, record); err != nil {
		t.Fatalf("delayed delete changed replacement endpoints: %v", err)
	}
}

func TestDelayedDeletePreservesLaterLiveGeneration(t *testing.T) {
	fixture := newProcessFixture(t)
	first := fixture.start()
	firstClient, firstContext := processClient(t, first)
	assertProcessConnect(t, firstContext, firstClient, first)
	admitted, err := admitDelete(t.Context(), first.Identity)
	if err != nil {
		t.Fatal(err)
	}
	defer admitted.Close()
	lease := holdProcessLease(t, first)
	if _, err := task.NewTTRPCTaskClient(firstClient).Shutdown(firstContext, &task.ShutdownRequest{ID: first.Identity.ID}); err != nil {
		t.Fatal(err)
	}
	awaitProcessExit(t, lease, first)
	lifecycleDeleteResponse(t, fixture)
	second := fixture.start()
	if second.Generation == first.Generation {
		t.Fatal("restart reused the previous generation")
	}
	secondClient, secondContext := processClient(t, second)
	assertProcessConnect(t, secondContext, secondClient, second)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := deleteInstance(ctx, admitted); err == nil {
		t.Fatal("delayed delete accepted a later live generation")
	}
	assertLifecycleGenerationAlive(t, second)
}

func TestAbsentDeleteAdmissionPreservesLaterLiveGeneration(t *testing.T) {
	fixture := newProcessFixture(t)
	identity, err := (commandOptions{namespace: fixture.namespace, id: fixture.id, address: fixture.address, bundle: fixture.bundle}).identity()
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := admitDelete(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	defer admitted.Close()
	record := fixture.start()
	client, ctx := processClient(t, record)
	assertProcessConnect(t, ctx, client, record)
	if _, err := deleteInstance(ctx, admitted); err == nil {
		t.Fatal("absent admission adopted a later live generation")
	}
	assertLifecycleGenerationAlive(t, record)
}

type lifecycleChild struct {
	fixture   *processFixture
	command   *exec.Cmd
	record    stateRecord
	done      chan struct{}
	waitError error
	stderr    bytes.Buffer
}

func startLifecycleChild(t *testing.T) *lifecycleChild {
	t.Helper()
	paths, prepared, _ := lifecyclePrepared(t)
	fixture := newProcessFixture(t)
	fixture.bundle = prepared.Identity.Bundle
	fixture.address = prepared.Identity.ContainerdAddress
	fixture.namespace = prepared.Identity.Namespace
	fixture.id = prepared.Identity.ID
	child := &lifecycleChild{fixture: fixture, done: make(chan struct{})}
	configReader, configWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer configReader.Close()
	defer configWriter.Close()
	reportReader, reportWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reportReader.Close()
	defer reportWriter.Close()
	child.command = fixture.cmd(t.Context(), "serve")
	child.command.Stdin = configReader
	child.command.Stdout = reportWriter
	child.command.Stderr = &child.stderr
	if err := child.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { child.waitError = child.command.Wait(); close(child.done) }()
	t.Cleanup(func() {
		select {
		case <-child.done:
			return
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, stderr, err := fixture.command(ctx, "delete", nil)
		if err != nil {
			t.Errorf("stop original child: %v; stderr=%s", err, stderr)
			if err := child.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Error(err)
			}
		}
		select {
		case <-child.done:
		case <-ctx.Done():
			t.Errorf("original child did not exit: %v", ctx.Err())
		}
	})
	if err := errors.Join(configReader.Close(), reportWriter.Close()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := writePrivateFrame(ctx, configWriter, startupConfig{Prepared: prepared}); err != nil {
		t.Fatal(err)
	}
	if err := configWriter.Close(); err != nil {
		t.Fatal(err)
	}
	var report boundReport
	if err := readPrivateFrame(ctx, reportReader, &report); err != nil {
		t.Fatalf("read original child report: %v", err)
	}
	if report.PID != uint32(child.command.Process.Pid) || report.Error != "" {
		t.Fatalf("original child report = %+v", report)
	}
	ready := prepared
	ready.Phase, ready.ShimPID, ready.Task, ready.Stop = recordReady, report.PID, report.Task, report.Stop
	if err := verifyBoundEndpoints(paths, ready); err != nil {
		t.Fatal(err)
	}
	if err := probeReady(ctx, ready); err != nil {
		t.Fatal(err)
	}
	if _, err := publishRecord(paths, ready); err != nil {
		t.Fatal(err)
	}
	child.record = ready
	client, requestContext := processClient(t, ready)
	assertProcessConnect(t, requestContext, client, ready)
	return child
}

func TestDeleteCleansCrashedChildAndAllowsRepeatedCleanup(t *testing.T) {
	child := startLifecycleChild(t)
	lease := holdProcessLease(t, child.record)
	if err := child.command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-child.done
	if child.waitError == nil {
		t.Fatal("killed child reported successful process exit")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := lock(ctx, lease); err != nil {
		t.Fatalf("dead child retained its lease: %v", err)
	}
	if err := unlock(lease); err != nil {
		t.Fatal(err)
	}
	stale := readProcessRecord(t, child.fixture.bundle)
	if stale.Generation != child.record.Generation || stale.Phase != recordReady {
		t.Fatal("crash removed or changed the ready record")
	}
	if _, err := os.Stat(filepath.Join(child.fixture.bundle, ".gvx-shim", "diagnostics.log")); err != nil {
		t.Fatalf("crash lost diagnostics evidence: %v", err)
	}
	staleAdmission, err := admitDelete(ctx, child.record.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyBoundEndpoints(staleAdmission.Paths, child.record); err != nil {
		staleAdmission.Close()
		t.Fatalf("crash changed admitted resource identities: %v", err)
	}
	if err := staleAdmission.Close(); err != nil {
		t.Fatal(err)
	}
	lifecycleDeleteResponse(t, child.fixture)
	assertProcessEndpointsAbsent(t, ctx, child.record.Task.Address, child.record.Stop.Address)
	if _, err := os.Stat(filepath.Join(child.fixture.bundle, ".gvx-shim", "state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale record remains after cleanup: %v", err)
	}
	lifecycleDeleteResponse(t, child.fixture)
}

func awaitLifecycleCondition(t *testing.T, ctx context.Context, description string, condition func() (bool, error)) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		ready, err := condition()
		if err != nil {
			t.Fatalf("%s: %v", description, err)
		}
		if ready {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s: %v", description, ctx.Err())
		case <-ticker.C:
		}
	}
}

func TestDeleteObservesLeaseAfterStopEndpointCloses(t *testing.T) {
	child := startLifecycleChild(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	blocked, err := dialLocal(ctx, child.record.Stop.Address)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	if err := blocked.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := writeAll(blocked, []byte{0}); err != nil {
		t.Fatal(err)
	}
	// A complete second request proves that the preceding incomplete connection reached the accept loop.
	rejected, err := dialLocal(ctx, child.record.Stop.Address)
	if err != nil {
		t.Fatal(err)
	}
	if err := rejected.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		rejected.Close()
		t.Fatal(err)
	}
	var wrong [32]byte
	if err := writeAll(rejected, wrong[:]); err != nil {
		rejected.Close()
		t.Fatal(err)
	}
	var reply [1]byte
	if _, err := io.ReadFull(rejected, reply[:]); err != nil {
		rejected.Close()
		t.Fatal(err)
	}
	if err := rejected.Close(); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0 {
		t.Fatalf("invalid stop token acknowledgment = %d", reply[0])
	}
	admitted, err := admitDelete(ctx, child.record.Identity)
	if err != nil {
		t.Fatal(err)
	}
	defer admitted.Close()
	lease := holdProcessLease(t, child.record)
	command, err := openLock(admitted.Paths, commandLock)
	if err != nil {
		t.Fatal(err)
	}
	defer command.Close()
	client, requestContext := processClient(t, child.record)
	if _, err := task.NewTTRPCTaskClient(client).Shutdown(requestContext, &task.ShutdownRequest{ID: child.record.Identity.ID}); err != nil {
		t.Fatal(err)
	}
	awaitLifecycleCondition(t, ctx, "stop listener did not close admission", func() (bool, error) {
		return processStopAdmissionClosed(ctx, child.record.Stop.Address, blocked)
	})
	if err := tryLock(lease); !errors.Is(err, errLockBusy) {
		if err == nil {
			_ = unlock(lease)
		}
		t.Fatalf("child exited before the delete race: %v", err)
	}
	deleted := make(chan error, 1)
	go func() { _, err := deleteInstance(ctx, admitted); deleted <- err }()
	deleteFinished := false
	defer func() {
		cancel()
		if !deleteFinished {
			<-deleted
		}
	}()
	awaitLifecycleCondition(t, ctx, "delete did not acquire the command lock", func() (bool, error) {
		err := tryLock(command)
		if errors.Is(err, errLockBusy) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return false, unlock(command)
	})
	if err := blocked.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	deleteErr := <-deleted
	deleteFinished = true
	if deleteErr != nil {
		t.Fatalf("delete rejected concurrent endpoint closure: %v", deleteErr)
	}
	<-child.done
	assertProcessEndpointsAbsent(t, ctx, child.record.Task.Address, child.record.Stop.Address)
}
