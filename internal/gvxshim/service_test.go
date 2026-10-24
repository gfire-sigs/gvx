package gvxshim

import (
	"context"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	sandbox "github.com/containerd/containerd/api/runtime/sandbox/v1"
	taskv2 "github.com/containerd/containerd/api/runtime/task/v2"
	task "github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/ttrpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const testGeneration = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type rpcFixture struct {
	state     *controlState
	server    *ttrpc.Server
	transport *taskTransport
	client    *ttrpc.Client
	task      task.TTRPCTaskService
	sandbox   sandbox.TTRPCSandboxService
	ctx       context.Context
}

func serviceIdentity(t *testing.T) instanceIdentity {
	t.Helper()
	address := "unix:///containerd-test.sock"
	if runtime.GOOS == "windows" {
		address = `\\.\pipe\containerd-test`
	}
	return instanceIdentity{Owner: "test-owner", ContainerdAddress: address, Namespace: "test-ns", ID: "test-id", Bundle: t.TempDir()}
}

func newRPCFixture(t *testing.T) *rpcFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	state := newControlState(time.Now().Add(time.Minute), time.Second)
	service, err := newService(serviceIdentity(t), testGeneration, uint32(os.Getpid()), state)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ttrpc.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	service.Register(server)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	transport := newTaskTransport(listener, state)
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, transport) }()
	t.Cleanup(func() {
		if err := transport.Close(); err != nil {
			t.Errorf("close listener: %v", err)
		}
		if err := transport.CloseConnections(); err != nil {
			t.Errorf("close connections: %v", err)
		}
		if err := server.Shutdown(ctx); err != nil {
			t.Errorf("await server connections: %v", err)
		}
		if err := server.Close(); err != nil {
			t.Errorf("close server: %v", err)
		}
		select {
		case <-served:
		case <-ctx.Done():
			t.Error("Task server did not exit")
		}
	})
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := ttrpc.NewClient(conn)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close client: %v", err)
		}
		if err := client.UserOnCloseWait(ctx); err != nil {
			t.Errorf("await client worker: %v", err)
		}
	})
	return &rpcFixture{state: state, server: server, transport: transport, client: client, task: task.NewTTRPCTaskClient(client), sandbox: sandbox.NewTTRPCSandboxClient(client), ctx: ctx}
}

func (f *rpcFixture) namespaced() context.Context {
	return ttrpc.WithMetadata(f.ctx, ttrpc.MD{"containerd-namespace-ttrpc": {"test-ns"}})
}

func requireWireCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Fatalf("RPC code = %v (%v), want %v", got, err, want)
	}
}

func requireUnattached(t *testing.T, state *controlState) {
	t.Helper()
	select {
	case <-state.Attached():
		t.Fatal("request completed external handoff")
	default:
	}
	if state.Stopping() {
		t.Fatal("rejected request stopped the daemon")
	}
}

func TestConnectReturnsServingProcessIdentity(t *testing.T) {
	f := newRPCFixture(t)
	response, err := f.task.Connect(f.namespaced(), &task.ConnectRequest{ID: "test-id"})
	if err != nil {
		t.Fatal(err)
	}
	if response.ShimPid != uint32(os.Getpid()) || response.TaskPid != 0 || response.Version != "gvx-control-v1" {
		t.Fatalf("Connect = %v, want shim PID %d, no task, and control version", response, os.Getpid())
	}
	select {
	case <-f.state.Attached():
	default:
		t.Fatal("external Connect did not complete handoff")
	}
}

func TestStartupProbeDoesNotCompleteHandoff(t *testing.T) {
	f := newRPCFixture(t)
	ctx := ttrpc.WithMetadata(f.ctx, ttrpc.MD{"containerd-namespace-ttrpc": {"test-ns"}, "gvx-startup-probe": {testGeneration}})
	response, err := f.task.Connect(ctx, &task.ConnectRequest{ID: "test-id"})
	if err != nil {
		t.Fatal(err)
	}
	if response.ShimPid != uint32(os.Getpid()) {
		t.Fatalf("probe PID = %d, want %d", response.ShimPid, os.Getpid())
	}
	requireUnattached(t, f.state)
}

func TestRejectedControlIdentityCannotAttachOrStop(t *testing.T) {
	cases := []struct {
		name     string
		metadata ttrpc.MD
		id       string
		code     codes.Code
	}{
		{name: "missing namespace", id: "test-id", code: codes.InvalidArgument},
		{name: "empty namespace", metadata: ttrpc.MD{"containerd-namespace-ttrpc": {""}}, id: "test-id", code: codes.InvalidArgument},
		{name: "duplicate namespace", metadata: ttrpc.MD{"containerd-namespace-ttrpc": {"test-ns", "test-ns"}}, id: "test-id", code: codes.InvalidArgument},
		{name: "foreign namespace", metadata: ttrpc.MD{"containerd-namespace-ttrpc": {"other"}}, id: "test-id", code: codes.PermissionDenied},
		{name: "missing ID", metadata: ttrpc.MD{"containerd-namespace-ttrpc": {"test-ns"}}, code: codes.InvalidArgument},
		{name: "malformed ID", metadata: ttrpc.MD{"containerd-namespace-ttrpc": {"test-ns"}}, id: "../invalid", code: codes.InvalidArgument},
		{name: "foreign ID", metadata: ttrpc.MD{"containerd-namespace-ttrpc": {"test-ns"}}, id: "other-id", code: codes.NotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRPCFixture(t)
			ctx := ttrpc.WithMetadata(f.ctx, tc.metadata)
			_, err := f.task.Connect(ctx, &task.ConnectRequest{ID: tc.id})
			requireWireCode(t, err, tc.code)
			_, err = f.task.Shutdown(ctx, &task.ShutdownRequest{ID: tc.id})
			requireWireCode(t, err, tc.code)
			_, err = f.sandbox.CreateSandbox(ctx, &sandbox.CreateSandboxRequest{SandboxID: tc.id})
			requireWireCode(t, err, tc.code)
			_, err = f.sandbox.ShutdownSandbox(ctx, &sandbox.ShutdownSandboxRequest{SandboxID: tc.id})
			requireWireCode(t, err, tc.code)
			requireUnattached(t, f.state)
		})
	}
}

func TestInvalidProbeCannotAttachOrStop(t *testing.T) {
	for _, probes := range [][]string{{""}, {strings.Repeat("f", 64)}, {testGeneration, testGeneration}} {
		t.Run(strings.Join(probes, ","), func(t *testing.T) {
			f := newRPCFixture(t)
			ctx := ttrpc.WithMetadata(f.ctx, ttrpc.MD{"containerd-namespace-ttrpc": {"test-ns"}, "gvx-startup-probe": probes})
			_, err := f.task.Connect(ctx, &task.ConnectRequest{ID: "test-id"})
			requireWireCode(t, err, codes.InvalidArgument)
			requireUnattached(t, f.state)
		})
	}
	f := newRPCFixture(t)
	ctx := ttrpc.WithMetadata(f.ctx, ttrpc.MD{"containerd-namespace-ttrpc": {"test-ns"}, "gvx-startup-probe": {testGeneration}})
	_, err := f.task.Shutdown(ctx, &task.ShutdownRequest{ID: "test-id"})
	requireWireCode(t, err, codes.InvalidArgument)
	_, err = f.sandbox.CreateSandbox(ctx, &sandbox.CreateSandboxRequest{SandboxID: "test-id"})
	requireWireCode(t, err, codes.InvalidArgument)
	_, err = f.sandbox.ShutdownSandbox(ctx, &sandbox.ShutdownSandboxRequest{SandboxID: "test-id"})
	requireWireCode(t, err, codes.InvalidArgument)
	requireUnattached(t, f.state)
}

func TestUnavailableWorkloadsReturnWireUnimplemented(t *testing.T) {
	f := newRPCFixture(t)
	_, err := f.task.Create(f.namespaced(), &task.CreateTaskRequest{ID: "test-id"})
	requireWireCode(t, err, codes.Unimplemented)
	_, err = f.sandbox.PingSandbox(f.namespaced(), &sandbox.PingRequest{})
	requireWireCode(t, err, codes.Unimplemented)
	_, err = f.sandbox.SandboxStatus(f.namespaced(), &sandbox.SandboxStatusRequest{SandboxID: "test-id"})
	requireWireCode(t, err, codes.Unimplemented)
	_, err = taskv2.NewTaskClient(f.client).Connect(f.namespaced(), &taskv2.ConnectRequest{ID: "test-id"})
	requireWireCode(t, err, codes.Unimplemented)
	requireUnattached(t, f.state)
	_, err = f.sandbox.CreateSandbox(f.namespaced(), &sandbox.CreateSandboxRequest{SandboxID: "test-id"})
	requireWireCode(t, err, codes.Unimplemented)
	select {
	case <-f.state.Attached():
	default:
		t.Fatal("native CreateSandbox did not acknowledge external attachment")
	}
	if f.state.Stopping() {
		t.Fatal("unsupported sandbox creation stopped daemon before cleanup")
	}
}

func TestShutdownReplyDrainsBeforeServerShutdown(t *testing.T) {
	for _, method := range []string{"task", "sandbox"} {
		for _, idle := range []bool{false, true} {
			name := method + "/fresh"
			if idle {
				name = method + "/idle"
			}
			t.Run(name, func(t *testing.T) {
				f := newRPCFixture(t)
				if idle {
					if _, err := f.task.Connect(f.namespaced(), &task.ConnectRequest{ID: "test-id"}); err != nil {
						t.Fatal(err)
					}
				}
				drained := make(chan error, 1)
				go func() {
					select {
					case <-f.state.StopRequested():
					case <-f.ctx.Done():
						drained <- f.ctx.Err()
						return
					}
					if err := f.transport.Close(); err != nil {
						drained <- err
						return
					}
					if err := f.state.WaitAndSeal(f.ctx); err != nil {
						drained <- err
						return
					}
					drained <- f.server.Shutdown(f.ctx)
				}()
				t.Cleanup(func() {
					select {
					case err := <-drained:
						if err != nil {
							t.Errorf("drain server: %v", err)
						}
					case <-f.ctx.Done():
						t.Error("shutdown coordinator did not exit")
					}
				})
				if method == "task" {
					_, err := f.task.Shutdown(f.namespaced(), &task.ShutdownRequest{ID: "test-id", Now: idle})
					if err != nil {
						t.Fatalf("Task Shutdown lost successful reply: %v", err)
					}
				} else {
					_, err := f.sandbox.ShutdownSandbox(f.namespaced(), &sandbox.ShutdownSandboxRequest{SandboxID: "test-id"})
					if err != nil {
						t.Fatalf("ShutdownSandbox lost successful reply: %v", err)
					}
				}
			})
		}
	}
}

func TestStoppingRejectsConnectAndSealedShutdown(t *testing.T) {
	f := newRPCFixture(t)
	if _, err := f.task.Connect(f.namespaced(), &task.ConnectRequest{ID: "test-id"}); err != nil {
		t.Fatal(err)
	}
	f.state.RequestStop()
	_, err := f.task.Connect(f.namespaced(), &task.ConnectRequest{ID: "test-id"})
	requireWireCode(t, err, codes.FailedPrecondition)
	_, err = f.sandbox.CreateSandbox(f.namespaced(), &sandbox.CreateSandboxRequest{SandboxID: "test-id"})
	requireWireCode(t, err, codes.FailedPrecondition)
	if err := f.state.WaitAndSeal(f.ctx); err != nil {
		t.Fatal(err)
	}
	_, err = f.task.Shutdown(f.namespaced(), &task.ShutdownRequest{ID: "test-id"})
	requireWireCode(t, err, codes.FailedPrecondition)
	_, err = f.sandbox.ShutdownSandbox(f.namespaced(), &sandbox.ShutdownSandboxRequest{SandboxID: "test-id"})
	requireWireCode(t, err, codes.FailedPrecondition)
}

func TestRepeatedShutdownSucceedsUntilResponseRegistrationSeals(t *testing.T) {
	f := newRPCFixture(t)
	if _, err := f.task.Shutdown(f.namespaced(), &task.ShutdownRequest{ID: "test-id"}); err != nil {
		t.Fatalf("first shutdown: %v", err)
	}
	if _, err := f.sandbox.ShutdownSandbox(f.namespaced(), &sandbox.ShutdownSandboxRequest{SandboxID: "test-id"}); err != nil {
		t.Fatalf("repeated shutdown before seal: %v", err)
	}
	if err := f.state.WaitAndSeal(f.ctx); err != nil {
		t.Fatal(err)
	}
	_, err := f.task.Shutdown(f.namespaced(), &task.ShutdownRequest{ID: "test-id"})
	requireWireCode(t, err, codes.FailedPrecondition)
}

func TestServiceRejectsInvalidConstruction(t *testing.T) {
	validIdentity := serviceIdentity(t)
	state := newControlState(time.Now().Add(time.Minute), time.Second)
	for _, name := range []string{"namespace", "ID", "owner", "bundle", "address", "generation", "PID", "state"} {
		t.Run(name, func(t *testing.T) {
			id := validIdentity
			generation := testGeneration
			pid := uint32(os.Getpid())
			control := state
			switch name {
			case "namespace":
				id.Namespace = ""
			case "ID":
				id.ID = "../invalid"
			case "owner":
				id.Owner = ""
			case "bundle":
				id.Bundle = "relative"
			case "address":
				id.ContainerdAddress = "tcp://remote:1234"
			case "generation":
				generation = strings.ToUpper(testGeneration)
			case "PID":
				pid = 0
			case "state":
				control = nil
			}
			if _, err := newService(id, generation, pid, control); err == nil {
				t.Fatal("invalid service construction returned nil")
			}
		})
	}
}
