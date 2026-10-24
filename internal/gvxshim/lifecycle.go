package gvxshim

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"syscall"
	"time"

	task "github.com/containerd/containerd/api/runtime/task/v3"
	containerdlog "github.com/containerd/log"
	"github.com/containerd/ttrpc"
	"github.com/sirupsen/logrus"
)

func startInstance(ctx context.Context, identity instanceIdentity, timeout time.Duration, output *os.File) (result error) {
	paths, err := openPaths(ctx, identity, createPaths)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, paths.Close()) }()
	command, err := openLock(paths, commandLock)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, command.Close()) }()
	if err := tryLock(command); err != nil {
		return fmt.Errorf("duplicate start: %w", err)
	}
	defer func() { result = errors.Join(result, unlock(command)) }()
	if err := paths.Revalidate(paths.Snapshot); err != nil {
		return err
	}
	record, _, err := readRecord(paths)
	if err != nil {
		return err
	}
	if record != nil {
		return fmt.Errorf("cleanup required: %w", errConflict)
	}
	lease, err := openLock(paths, lifetimeLease)
	if err != nil {
		return err
	}
	if err := tryLock(lease); err != nil {
		return errors.Join(fmt.Errorf("duplicate start: %w", err), lease.Close())
	}
	if err := errors.Join(unlock(lease), lease.Close()); err != nil {
		return err
	}
	if err := requireAbsent(paths.State, "diagnostics.log"); err != nil {
		return err
	}
	if err := prepareEndpointDir(ctx, paths); err != nil {
		return err
	}
	var generation [32]byte
	if _, err := rand.Read(generation[:]); err != nil {
		return errors.Join(err, removePreparedDirectory(paths))
	}
	diagnostics, logRef, err := createDiagnostics(paths)
	if err != nil {
		return errors.Join(err, removePreparedDirectory(paths))
	}
	diagnosticsOpen := true
	prepared := stateRecord{Version: 1, Phase: recordPrepared, Identity: identity, Generation: hex.EncodeToString(generation[:]), Paths: paths.Snapshot, Task: endpointRef{Address: paths.TaskAddress}, Stop: endpointRef{Address: paths.StopAddress}, Log: logRef}
	var recordFile *ownedEntry
	cleanupRecord := prepared
	var child *exec.Cmd
	started := false
	success := false
	defer func() {
		if diagnosticsOpen {
			result = errors.Join(result, diagnostics.Close())
		}
		if success {
			return
		}
		if started {
			result = errors.Join(result, rollbackChild(child, &cleanupRecord, timeout))
		}
		if recordFile != nil {
			result = errors.Join(result, cleanTransient(paths, &cleanupRecord, recordFile))
			return
		}
		result = errors.Join(result, removeOwned(paths.State, logRef), removePreparedDirectory(paths))
	}()
	published, err := publishRecord(paths, prepared)
	if err != nil {
		return err
	}
	recordFile = &published
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	configRead, configWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer configRead.Close()
	defer configWrite.Close()
	reportRead, reportWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer reportRead.Close()
	defer reportWrite.Close()
	child = exec.Command(executable, "-namespace", identity.Namespace, "-id", identity.ID, "-address", identity.ContainerdAddress, "-bundle", identity.Bundle, "-timeout", timeout.String(), "serve")
	child.Stdin = configRead
	child.Stdout = reportWrite
	child.Stderr = diagnostics
	configureChild(child)
	if err := child.Start(); err != nil {
		return err
	}
	started = true
	if err := errors.Join(configRead.Close(), reportWrite.Close()); err != nil {
		return err
	}
	if err := writePrivateFrame(ctx, configWrite, startupConfig{Prepared: prepared}); err != nil {
		return err
	}
	if err := configWrite.Close(); err != nil {
		return err
	}
	var report boundReport
	if err := readPrivateFrame(ctx, reportRead, &report); err != nil {
		return err
	}
	if report.Error != "" {
		return fmt.Errorf("serving child: %s", report.Error)
	}
	if report.PID != uint32(child.Process.Pid) || report.PID == 0 || report.Task.Address != paths.TaskAddress || report.Stop.Address != paths.StopAddress {
		return errConflict
	}
	ready := prepared
	ready.Phase = recordReady
	ready.ShimPID = report.PID
	ready.Task = report.Task
	ready.Stop = report.Stop
	if err := validateRecord(paths, ready); err != nil {
		return err
	}
	if err := verifyBoundEndpoints(paths, ready); err != nil {
		return err
	}
	cleanupRecord = ready
	if err := probeReady(ctx, cleanupRecord); err != nil {
		return err
	}
	published, err = publishRecord(paths, cleanupRecord)
	if err != nil {
		return err
	}
	recordFile = &published
	bootstrap, err := json.Marshal(struct {
		Version  int    `json:"version"`
		Address  string `json:"address"`
		Protocol string `json:"protocol"`
	}{3, paths.TaskAddress, "ttrpc"})
	if err != nil {
		return err
	}
	bootstrap = append(bootstrap, '\n')
	if err := diagnostics.Close(); err != nil {
		diagnosticsOpen = false
		return err
	}
	diagnosticsOpen = false
	if err := boundedFileIO(ctx, output, func(stream io.ReadWriter) error { return writeAll(stream, bootstrap) }); err != nil {
		return err
	}
	if err := reportRead.Close(); err != nil {
		return err
	}
	if err := child.Process.Release(); err != nil {
		return err
	}
	success = true
	return nil
}

func removePreparedDirectory(paths *instancePaths) error {
	if paths.UnixEndpointDir == nil {
		return nil
	}
	return removeEndpointDir(paths, paths.UnixEndpointDir.ID)
}

func verifyBoundEndpoints(paths *instancePaths, record stateRecord) error {
	if err := paths.Revalidate(record.Paths); err != nil {
		return err
	}
	for _, endpoint := range []endpointRef{record.Task, record.Stop} {
		if endpoint.Socket == nil {
			continue
		}
		actual, err := inspectEntry(paths.UnixEndpointDir, endpoint.Socket.Name, socketEntry)
		if err != nil {
			return err
		}
		if actual != *endpoint.Socket {
			return errConflict
		}
	}
	return nil
}

func probeReady(ctx context.Context, record stateRecord) error {
	conn, err := dialLocal(ctx, record.Task.Address)
	if err != nil {
		return err
	}
	client := ttrpc.NewClient(conn)
	defer client.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	ctx = ttrpc.WithMetadata(ctx, ttrpc.MD{"containerd-namespace-ttrpc": {record.Identity.Namespace}, "gvx-startup-probe": {record.Generation}})
	response, err := task.NewTTRPCTaskClient(client).Connect(ctx, &task.ConnectRequest{ID: record.Identity.ID})
	if err != nil {
		return err
	}
	if response.ShimPid != record.ShimPID || response.TaskPid != 0 || response.Version != controlVersion {
		return errConflict
	}
	return nil
}

func rollbackChild(child *exec.Cmd, record *stateRecord, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = requestIndependentStop(ctx, record)
	exited := make(chan error, 1)
	go func() { exited <- child.Wait() }()
	select {
	case <-exited:
		return nil
	case <-ctx.Done():
		killErr := child.Process.Kill()
		waitErr := <-exited
		var exitError *exec.ExitError
		if errors.As(waitErr, &exitError) {
			waitErr = nil
		}
		if errors.Is(killErr, os.ErrProcessDone) {
			killErr = nil
		}
		return errors.Join(killErr, waitErr)
	}
}

func serveInstance(startup context.Context, identity instanceIdentity, timeout time.Duration, input, reportOutput *os.File) (exit processExit, result error) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	var config startupConfig
	if err := readPrivateFrame(startup, input, &config); err != nil {
		return exit, err
	}
	if err := input.Close(); err != nil {
		return exit, err
	}
	paths, err := openPaths(startup, identity, inspectPaths)
	if err != nil {
		return exit, err
	}
	defer func() { result = errors.Join(result, paths.Close()) }()
	if err := validateRecord(paths, config.Prepared); err != nil {
		return exit, err
	}
	if config.Prepared.Phase != recordPrepared {
		return exit, errInvalidState
	}
	if err := paths.Revalidate(config.Prepared.Paths); err != nil {
		return exit, err
	}
	record, _, err := readRecord(paths)
	if err != nil {
		return exit, err
	}
	if !reflect.DeepEqual(record, &config.Prepared) {
		return exit, errConflict
	}
	lease, err := openLock(paths, lifetimeLease)
	if err != nil {
		return exit, err
	}
	if err := tryLock(lease); err != nil {
		return exit, errors.Join(err, lease.Close())
	}
	exit.RetainLease = lease
	var taskOwned, stopOwned *ownedEndpoint
	defer func() {
		if taskOwned != nil {
			result = errors.Join(result, closeListener(taskOwned.Listener))
			if taskOwned.Ref.Socket != nil {
				result = errors.Join(result, removeOwned(paths.UnixEndpointDir, *taskOwned.Ref.Socket))
			}
		}
		if stopOwned != nil {
			result = errors.Join(result, closeListener(stopOwned.Listener))
			if stopOwned.Ref.Socket != nil {
				result = errors.Join(result, removeOwned(paths.UnixEndpointDir, *stopOwned.Ref.Socket))
			}
		}
		if paths.UnixEndpointDir != nil {
			result = errors.Join(result, removeEndpointDir(paths, paths.UnixEndpointDir.ID))
		}
	}()
	taskOwned, err = listenLocal(startup, paths, taskEndpoint)
	if err != nil {
		return exit, err
	}
	stopOwned, err = listenLocal(startup, paths, stopEndpoint)
	if err != nil {
		return exit, err
	}
	logContext, stopLog := context.WithCancel(context.Background())
	defer stopLog()
	log, err := openLog(logContext, paths, config.Prepared.Log, timeout)
	if err != nil {
		return exit, err
	}
	var state *controlState
	defer func() {
		deadline := time.Now().Add(timeout)
		if state != nil {
			if drain, stopping := state.DrainDeadline(); stopping {
				deadline = drain
			}
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		result = errors.Join(result, log.Close(ctx))
	}()
	handoffDeadline := time.Now().Add(timeout)
	state = newControlState(handoffDeadline, timeout)
	service, err := newService(identity, config.Prepared.Generation, uint32(os.Getpid()), state)
	if err != nil {
		return exit, err
	}
	server, err := ttrpc.NewServer()
	if err != nil {
		return exit, err
	}
	service.Register(server)
	transport := newTaskTransport(taskOwned.Listener, state)
	token, err := decodeGeneration(config.Prepared.Generation)
	if err != nil {
		return exit, err
	}
	stops := newStopServer(stopOwned.Listener, state, token, timeout)
	served := make(chan error, 1)
	logger := logrus.New()
	logger.SetOutput(log.Writer)
	servingContext := containerdlog.WithLogger(context.Background(), logrus.NewEntry(logger))
	go func() {
		err := server.Serve(servingContext, transport)
		if !state.Stopping() {
			state.RequestStop()
		}
		served <- err
	}()
	lifetimeDone := make(chan struct{})
	lifetimeExited := make(chan struct{})
	defer func() { close(lifetimeDone); <-lifetimeExited }()
	go func() {
		defer close(lifetimeExited)
		timer := time.NewTimer(time.Until(handoffDeadline))
		defer timer.Stop()
		select {
		case <-timer.C:
			state.expireHandoff()
		case <-state.Attached():
		case <-signals:
			state.RequestStop()
			return
		case <-state.StopRequested():
			return
		case <-lifetimeDone:
			return
		}
		select {
		case <-signals:
			state.RequestStop()
		case <-state.StopRequested():
		case <-lifetimeDone:
		}
	}()
	report := boundReport{PID: uint32(os.Getpid()), Task: taskOwned.Ref, Stop: stopOwned.Ref}
	if err := writePrivateFrame(startup, reportOutput, report); err != nil {
		state.RequestStop()
		result = err
	}
	if err := reportOutput.Close(); err != nil {
		state.RequestStop()
		result = errors.Join(result, err)
	}
	<-state.StopRequested()
	deadline, _ := state.DrainDeadline()
	drain, cancelDrain := context.WithDeadline(context.Background(), deadline)
	defer cancelDrain()
	result = errors.Join(result, closeListener(transport))
	barrierErr := state.WaitAndSeal(drain)
	if barrierErr == nil {
		barrierErr = server.Shutdown(drain)
	}
	if barrierErr != nil {
		result = errors.Join(result, barrierErr, transport.CloseConnections(), server.Close())
	} else {
		result = errors.Join(result, transport.CloseConnections(), server.Close())
	}
	servedErr := <-served
	if servedErr != nil && !errors.Is(servedErr, net.ErrClosed) && !errors.Is(servedErr, ttrpc.ErrServerClosed) {
		result = errors.Join(result, servedErr)
	}
	result = errors.Join(result, stops.close(drain))
	return exit, result
}

func closeListener(listener net.Listener) error {
	err := listener.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
