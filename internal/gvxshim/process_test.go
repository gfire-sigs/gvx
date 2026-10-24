package gvxshim

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	sandboxapi "github.com/containerd/containerd/api/runtime/sandbox/v1"
	taskv2 "github.com/containerd/containerd/api/runtime/task/v2"
	task "github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/ttrpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const processReexecEnv = "GVX_SHIM_TEST_REEXEC"

func TestMain(m *testing.M) {
	if os.Getenv(processReexecEnv) == "1" {
		gate, err := processServeGate()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer runtime.KeepAlive(gate)
		Main()
	}
	os.Exit(m.Run())
}

type processFixture struct {
	t         *testing.T
	binary    string
	bundle    string
	address   string
	namespace string
	id        string
	timeout   time.Duration
}

func newProcessFixture(t *testing.T) *processFixture {
	t.Helper()
	binary := os.Getenv("GVX_SHIM_BINARY")
	if binary == "" {
		var err error
		binary, err = os.Executable()
		if err != nil {
			t.Fatal(err)
		}
	} else {
		binary = requireExecutable(t, "GVX_SHIM_BINARY")
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	id := "gvx-" + hex.EncodeToString(nonce[:])
	bundle := t.TempDir()
	address := "unix://" + filepath.Join(bundle, "containerd.sock")
	if runtime.GOOS == "windows" {
		address = `\\.\pipe\` + id + "-containerd"
	}
	f := &processFixture{t: t, binary: binary, bundle: bundle, address: address, namespace: "gvx-process-test", id: id, timeout: 5 * time.Second}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, stderr, err := f.command(ctx, "delete", nil)
		if err != nil {
			t.Errorf("cleanup shim %s: %v; stderr=%s", f.id, err, stderr)
			return
		}
		var response taskv2.DeleteResponse
		if err := proto.Unmarshal(out, &response); err != nil {
			t.Errorf("decode cleanup response: %v", err)
		}
	})
	return f
}

func requireExecutable(t *testing.T, variable string) string {
	t.Helper()
	value := os.Getenv(variable)
	if value == "" {
		t.Fatalf("%s must name an absolute executable", variable)
	}
	if !filepath.IsAbs(value) {
		t.Fatalf("%s=%q is not absolute", variable, value)
	}
	info, err := os.Stat(value)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("%s=%q is not a regular executable: %v", variable, value, err)
	}
	return value
}

func (f *processFixture) args(action string) []string {
	return []string{"-namespace", f.namespace, "-id", f.id, "-address", f.address, "-bundle", f.bundle, "-timeout", f.timeout.String(), action}
}

func (f *processFixture) cmd(ctx context.Context, action string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, f.binary, f.args(action)...)
	cmd.Env = append(os.Environ(), processReexecEnv+"=1")
	return cmd
}

func (f *processFixture) command(ctx context.Context, action string, input []byte) ([]byte, string, error) {
	cmd := f.cmd(ctx, action)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	return out, stderr.String(), err
}

func (f *processFixture) start() stateRecord {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(f.t.Context(), 15*time.Second)
	defer cancel()
	out, stderr, err := f.command(ctx, "start", nil)
	if err != nil {
		f.t.Fatalf("start shim: %v; stderr=%s", err, stderr)
	}
	return f.started(out, stderr)
}

func (f *processFixture) started(out []byte, stderr string) stateRecord {
	f.t.Helper()
	if stderr != "" {
		f.t.Fatalf("successful start stderr=%q, want empty", stderr)
	}
	var bootstrap struct {
		Version  int    `json:"version"`
		Address  string `json:"address"`
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(out, &bootstrap); err != nil {
		f.t.Fatalf("decode bootstrap %q: %v", out, err)
	}
	if bootstrap.Version != 3 || bootstrap.Protocol != "ttrpc" || bootstrap.Address == "" {
		f.t.Fatalf("bootstrap=%+v, want version 3 and local ttRPC address", bootstrap)
	}
	record := readProcessRecord(f.t, f.bundle)
	if record.Phase != recordReady || record.ShimPID == 0 || record.ShimPID == uint32(os.Getpid()) || record.Task.Address != bootstrap.Address {
		f.t.Fatalf("ready record disagrees with bootstrap: phase=%q pid=%d task=%q bootstrap=%q", record.Phase, record.ShimPID, record.Task.Address, bootstrap.Address)
	}
	return record
}

func readProcessRecord(t *testing.T, bundle string) stateRecord {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(bundle, ".gvx-shim", "state.json"))
	if err != nil {
		t.Fatalf("read shim state: %v", err)
	}
	var record stateRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("decode shim state: %v", err)
	}
	return record
}

func processClient(t *testing.T, record stateRecord) (*ttrpc.Client, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	conn, err := dialLocal(ctx, record.Task.Address)
	if err != nil {
		t.Fatalf("dial shim: %v", err)
	}
	client := ttrpc.NewClient(conn)
	t.Cleanup(func() { _ = client.Close() })
	return client, namespaces.WithNamespace(ctx, record.Identity.Namespace)
}

func assertProcessConnect(t *testing.T, ctx context.Context, client *ttrpc.Client, record stateRecord) {
	t.Helper()
	response, err := task.NewTTRPCTaskClient(client).Connect(ctx, &task.ConnectRequest{ID: record.Identity.ID})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if response.ShimPid != record.ShimPID || response.TaskPid != 0 || response.Version != "gvx-control-v1" {
		t.Fatalf("Connect=%+v, want shim_pid=%d, no task PID, gvx-control-v1", response, record.ShimPID)
	}
}

func holdProcessLease(t *testing.T, record stateRecord) *ownedLock {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	paths, err := openPaths(ctx, record.Identity, inspectPaths)
	if err != nil {
		t.Fatalf("pin child lease: %v", err)
	}
	lease, err := openLock(paths, lifetimeLease)
	closeErr := paths.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("open child lease: %v; close paths: %v", err, closeErr)
	}
	t.Cleanup(func() {
		if err := lease.Close(); err != nil {
			t.Errorf("close observed lease: %v", err)
		}
	})
	return lease
}

func awaitProcessExit(t *testing.T, lease *ownedLock, record stateRecord) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if err := lock(ctx, lease); err != nil {
		t.Fatalf("child %d retained its lifetime lease: %v", record.ShimPID, err)
	}
	if err := unlock(lease); err != nil {
		t.Fatalf("unlock observed lease: %v", err)
	}
	assertProcessEndpointsAbsent(t, ctx, record.Task.Address, record.Stop.Address)
}

func assertProcessEndpointsAbsent(t *testing.T, ctx context.Context, addresses ...string) {
	t.Helper()
	for _, address := range addresses {
		if strings.HasPrefix(address, "unix://") || strings.HasPrefix(address, "/") {
			if _, err := os.Lstat(strings.TrimPrefix(address, "unix://")); !os.IsNotExist(err) {
				t.Errorf("endpoint %q remains after child exit: %v", address, err)
			}
			continue
		}
		conn, err := dialLocal(ctx, address)
		if err == nil {
			_ = conn.Close()
			t.Errorf("endpoint %q still accepts after child exit", address)
		}
	}
}

func TestProcessConnectShutdown(t *testing.T) {
	f := newProcessFixture(t)
	record := f.start()
	lease := holdProcessLease(t, record)
	client, ctx := processClient(t, record)
	assertProcessConnect(t, ctx, client, record)
	if _, err := task.NewTTRPCTaskClient(client).Create(ctx, &task.CreateTaskRequest{ID: f.id}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("Task Create error=%v, want Unimplemented", err)
	}
	if _, err := task.NewTTRPCTaskClient(client).Shutdown(ctx, &task.ShutdownRequest{ID: f.id}); err != nil {
		t.Fatalf("Shutdown response did not drain: %v", err)
	}
	awaitProcessExit(t, lease, record)
}

func TestProcessShutdownFirstRequest(t *testing.T) {
	f := newProcessFixture(t)
	record := f.start()
	lease := holdProcessLease(t, record)
	client, ctx := processClient(t, record)
	if _, err := task.NewTTRPCTaskClient(client).Shutdown(ctx, &task.ShutdownRequest{ID: f.id, Now: true}); err != nil {
		t.Fatalf("first-request Shutdown response did not drain: %v", err)
	}
	awaitProcessExit(t, lease, record)
}

func TestProcessNativeCreateRejects(t *testing.T) {
	f := newProcessFixture(t)
	record := f.start()
	lease := holdProcessLease(t, record)
	client, ctx := processClient(t, record)
	native := sandboxapi.NewTTRPCSandboxClient(client)
	if _, err := native.CreateSandbox(ctx, &sandboxapi.CreateSandboxRequest{SandboxID: f.id}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("native CreateSandbox error=%v, want Unimplemented", err)
	}
	assertProcessConnect(t, ctx, client, record)
	if _, err := native.ShutdownSandbox(ctx, &sandboxapi.ShutdownSandboxRequest{SandboxID: f.id}); err != nil {
		t.Fatalf("ShutdownSandbox response did not drain: %v", err)
	}
	awaitProcessExit(t, lease, record)
}

func TestProcessIndependentDelete(t *testing.T) {
	f := newProcessFixture(t)
	configPath := filepath.Join(f.bundle, "config.json")
	config := []byte("{\"caller\":\"owned\"}\n")
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rootfs", "work"} {
		if err := os.Mkdir(filepath.Join(f.bundle, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	record := f.start()
	lease := holdProcessLease(t, record)
	client, ctx := processClient(t, record)
	assertProcessConnect(t, ctx, client, record)
	out, stderr, err := f.command(ctx, "delete", nil)
	if err != nil {
		t.Fatalf("independent delete: %v; stderr=%s", err, stderr)
	}
	var response taskv2.DeleteResponse
	if err := proto.Unmarshal(out, &response); err != nil {
		t.Fatalf("decode Task v2 DeleteResponse: %v", err)
	}
	if response.Pid != 0 || response.ExitStatus != 0 || response.ExitedAt == nil {
		t.Errorf("delete fabricated a task or omitted completion: %+v", &response)
	}
	awaitProcessExit(t, lease, record)
	if _, err := os.Stat(filepath.Join(f.bundle, ".gvx-shim", "state.json")); !os.IsNotExist(err) {
		t.Errorf("state record remains after delete: %v", err)
	}
	if info, err := os.Stat(f.bundle); err != nil || !info.IsDir() {
		t.Errorf("delete removed caller bundle: %v", err)
	}
	if got, err := os.ReadFile(configPath); err != nil || !bytes.Equal(got, config) {
		t.Errorf("delete changed caller config: got=%q err=%v", got, err)
	}
	for _, name := range []string{"rootfs", "work"} {
		if info, err := os.Stat(filepath.Join(f.bundle, name)); err != nil || !info.IsDir() {
			t.Errorf("delete removed caller directory %s: %v", name, err)
		}
	}
}

func TestProcessConcurrentStarts(t *testing.T) {
	f := newProcessFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	type result struct {
		out    []byte
		stderr string
		err    error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			<-start
			out, stderr, err := f.command(ctx, "start", nil)
			results <- result{out, stderr, err}
		})
	}
	close(start)
	workers.Wait()
	close(results)
	var winner result
	var successes int
	for got := range results {
		if got.err == nil {
			successes++
			winner = got
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent start successes=%d, want exactly one", successes)
	}
	record := f.started(winner.out, winner.stderr)
	client, rpcCtx := processClient(t, record)
	assertProcessConnect(t, rpcCtx, client, record)
}

func TestProcessUnattachedExpires(t *testing.T) {
	f := newProcessFixture(t)
	f.timeout = 2 * time.Second
	record := f.start()
	lease := holdProcessLease(t, record)
	awaitProcessExit(t, lease, record)
}

func TestProcessOptionsPipeExpires(t *testing.T) {
	f := newProcessFixture(t)
	f.timeout = 250 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	cmd := f.cmd(ctx, "start")
	cmd.Stdin = reader
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("start accepted options pipe without EOF")
	}
	if ctx.Err() != nil {
		t.Fatalf("options input exceeded lifecycle deadline: %v", ctx.Err())
	}
	if out.Len() != 0 {
		t.Errorf("failed options read emitted bootstrap: %q", out.Bytes())
	}
	if _, err := os.Stat(filepath.Join(f.bundle, ".gvx-shim")); !os.IsNotExist(err) {
		t.Errorf("options validation created resources before EOF: %v", err)
	}
}

func TestProcessRejectsNonemptyOptions(t *testing.T) {
	f := newProcessFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	out, stderr, err := f.command(ctx, "start", []byte{1})
	if err == nil || len(out) != 0 {
		t.Fatalf("nonempty options: err=%v stdout=%q stderr=%q", err, out, stderr)
	}
	if _, err := os.Stat(filepath.Join(f.bundle, ".gvx-shim")); !os.IsNotExist(err) {
		t.Errorf("unsupported options created resources: %v", err)
	}
}

func TestProcessPrivateInputExpires(t *testing.T) {
	f := newProcessFixture(t)
	f.timeout = 250 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	cmd := f.cmd(ctx, "serve")
	cmd.Stdin = reader
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("serve accepted a private frame without a length or payload")
	}
	if ctx.Err() != nil {
		t.Fatalf("stalled private input outlived its deadline: %v", ctx.Err())
	}
	if _, err := os.Stat(filepath.Join(f.bundle, ".gvx-shim")); !os.IsNotExist(err) {
		t.Errorf("stalled private input created instance resources: %v", err)
	}
}

func TestProcessBlockedBootstrapExpires(t *testing.T) {
	testBlockedProcessBootstrap(t, false)
}

func TestProcessLauncherDeathBeforeBootstrap(t *testing.T) {
	testBlockedProcessBootstrap(t, true)
}

func testBlockedProcessBootstrap(t *testing.T, killLauncher bool) {
	t.Helper()
	f := newProcessFixture(t)
	f.timeout = 2 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	writer := fullProcessBootstrapPipe(t)
	cmd := f.cmd(ctx, "start")
	cmd.Stdout = writer
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("kill original launcher: %v", err)
			}
			<-done
		}
	})
	record := awaitReadyProcessRecord(t, ctx, f.bundle)
	lease := holdProcessLease(t, record)
	if killLauncher {
		if err := cmd.Process.Kill(); err != nil {
			t.Fatalf("kill original launcher before bootstrap: %v", err)
		}
	}
	select {
	case err := <-done:
		done <- err
		if err == nil {
			t.Fatal("launcher succeeded without writing bootstrap")
		}
	case <-ctx.Done():
		t.Fatalf("launcher remained blocked: %v", ctx.Err())
	}
	awaitProcessExit(t, lease, record)
}

func awaitReadyProcessRecord(t *testing.T, ctx context.Context, bundle string) stateRecord {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	path := filepath.Join(bundle, ".gvx-shim", "state.json")
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			var record stateRecord
			if err := json.Unmarshal(data, &record); err != nil {
				t.Fatalf("read atomically published state: %v", err)
			}
			if record.Phase == recordReady {
				return record
			}
		} else if !os.IsNotExist(err) {
			t.Fatalf("observe startup state: %v", err)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("no ready child while launcher output was blocked: %v", ctx.Err())
		}
	}
}

func TestProcessBrokenBootstrapRollsBack(t *testing.T) {
	f := newProcessFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	cmd := f.cmd(ctx, "start")
	cmd.Stdout = writer
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("start succeeded after its bootstrap reader closed")
	}
	if ctx.Err() != nil {
		t.Fatalf("broken bootstrap rollback exceeded deadline: %v", ctx.Err())
	}
	owner, err := currentOwner()
	if err != nil {
		t.Fatal(err)
	}
	address, err := normalizeContainerdAddress(f.address)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := canonicalBundle(f.bundle)
	if err != nil {
		t.Fatal(err)
	}
	id := instanceIdentity{Owner: owner, ContainerdAddress: address, Namespace: f.namespace, ID: f.id, Bundle: bundle}
	paths, err := openPaths(ctx, id, inspectPaths)
	if err != nil {
		t.Fatalf("inspect failed launcher resources: %v", err)
	}
	defer paths.Close()
	lease, err := openLock(paths, lifetimeLease)
	if err != nil {
		t.Fatalf("open failed launcher's stable lease: %v", err)
	}
	defer lease.Close()
	if err := lock(ctx, lease); err != nil {
		t.Fatalf("failed launcher left a serving child: %v; stderr=%s", err, stderr.String())
	}
	if err := unlock(lease); err != nil {
		t.Fatal(err)
	}
	assertProcessEndpointsAbsent(t, ctx, paths.TaskAddress, paths.StopAddress)
	for _, name := range []string{"state.json", "diagnostics.log"} {
		if _, err := os.Stat(filepath.Join(f.bundle, ".gvx-shim", name)); !os.IsNotExist(err) {
			t.Errorf("failed launcher retained %s: %v", name, err)
		}
	}
}
