//go:build linux

package gvxshim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/sandbox"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

func shortInteropDir(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "gvxi-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Errorf("remove private interop directory: %v", err)
		}
	})
	return base
}

const observerSocketEnv = "GVX_SHIM_INTEROP_OBSERVER"
const observerBinaryEnv = "GVX_SHIM_INTEROP_BINARY"

type observedLaunch struct {
	Bundle    string      `json:"bundle"`
	Record    stateRecord `json:"record"`
	Bootstrap []byte      `json:"bootstrap"`
	Stderr    string      `json:"stderr"`
	Error     string      `json:"error,omitempty"`
}

func init() {
	if os.Getenv(observerSocketEnv) != "" {
		os.Exit(observeShimInvocation())
	}
}

// observeShimInvocation delegates every argument and input byte to the actual command.
// It holds successful bootstrap output only until the test pins the real child's lease.
func observeShimInvocation() int {
	cmd := exec.Command(os.Getenv(observerBinaryEnv), os.Args[1:]...)
	cmd.Stdin = os.Stdin
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "start" {
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return 1
		}
		return 0
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	observation := observedLaunch{Bootstrap: stdout.Bytes(), Stderr: stderr.String()}
	if err != nil {
		observation.Error = err.Error()
	} else {
		observation.Bundle, err = os.Getwd()
		if err == nil {
			var data []byte
			data, err = os.ReadFile(filepath.Join(observation.Bundle, ".gvx-shim", "state.json"))
			if err == nil {
				err = json.Unmarshal(data, &observation.Record)
			}
		}
		if err != nil {
			observation.Error = err.Error()
		}
	}
	conn, dialErr := net.DialTimeout("unix", os.Getenv(observerSocketEnv), 5*time.Second)
	if dialErr != nil {
		fmt.Fprintln(os.Stderr, dialErr)
		return 1
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return 1
	}
	if err := json.NewEncoder(conn).Encode(observation); err != nil {
		return 1
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != 1 {
		return 1
	}
	if _, err := os.Stderr.Write(stderr.Bytes()); err != nil {
		return 1
	}
	if observation.Error != "" {
		return 1
	}
	if _, err := os.Stdout.Write(stdout.Bytes()); err != nil {
		return 1
	}
	return 0
}

func TestContainerdNativeRejection(t *testing.T) {
	shimConfigured := os.Getenv("GVX_SHIM_BINARY") != ""
	daemonConfigured := os.Getenv("GVX_CONTAINERD_BINARY") != ""
	if !shimConfigured && !daemonConfigured {
		t.Skip("set GVX_SHIM_BINARY and GVX_CONTAINERD_BINARY for private containerd v2.2.4 interoperability")
	}
	shimBinary := requireExecutable(t, "GVX_SHIM_BINARY")
	daemonBinary := requireExecutable(t, "GVX_CONTAINERD_BINARY")
	wrapperBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	base := shortInteropDir(t)
	observerPath := filepath.Join(base, "observer.sock")
	observer, err := net.ListenUnix("unix", &net.UnixAddr{Name: observerPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	if err := observer.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	address := filepath.Join(base, "containerd.sock")
	state := filepath.Join(base, "state")
	config := fmt.Sprintf(`version = 3
root = %q
state = %q
temp = %q
disabled_plugins = [
  "io.containerd.grpc.v1.cri",
  "io.containerd.cri.v1.images",
  "io.containerd.cri.v1.runtime",
  "io.containerd.nri.v1.nri",
]
[grpc]
  address = %q
  tcp_address = ""
  uid = %d
  gid = %d
[ttrpc]
  address = %q
  uid = %d
  gid = %d
[cgroup]
  path = ""
`, filepath.Join(base, "root"), state, filepath.Join(base, "tmp"), address, os.Getuid(), os.Getgid(), filepath.Join(base, "containerd.ttrpc"), os.Getuid(), os.Getgid())
	configPath := filepath.Join(base, "containerd.toml")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(base, "containerd.log")
	logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			data, err := os.ReadFile(logPath)
			if err != nil {
				t.Logf("read containerd diagnostics: %v", err)
			} else {
				t.Logf("private containerd diagnostics:\n%s", data)
			}
		}
		if err := logFile.Close(); err != nil {
			t.Errorf("close containerd diagnostics: %v", err)
		}
	})
	cmd := exec.Command(daemonBinary, "--config", configPath)
	cmd.Env = append(os.Environ(), observerSocketEnv+"="+observerPath, observerBinaryEnv+"="+shimBinary)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start private containerd: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("stop private containerd: %v", err)
		}
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("kill original private containerd process: %v", err)
			}
			<-done
			t.Error("private containerd did not stop after SIGTERM")
		}
	})
	client, err := containerd.New(address, containerd.WithTimeout(15*time.Second))
	if err != nil {
		t.Fatalf("create private containerd client: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close private containerd client: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	version, err := client.VersionService().Version(ctx, &emptypb.Empty{}, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("private containerd readiness: %v", err)
	}
	if strings.TrimPrefix(version.Version, "v") != "2.2.4" {
		t.Fatalf("private daemon version=%q, want 2.2.4", version.Version)
	}
	t.Logf("external containerd version=%s revision=%s", version.Version, version.Revision)
	assertNativePlugins(t, ctx, client)
	ctx = namespaces.WithNamespace(ctx, "gvx-native-test")
	spec, err := typeurl.MarshalAny(&specs.Spec{Version: specs.Version})
	if err != nil {
		t.Fatal(err)
	}
	info := sandbox.Sandbox{ID: "native-rejection", Sandboxer: "shim", Runtime: sandbox.RuntimeOpts{Name: wrapperBinary}, Spec: spec}
	result := make(chan error, 1)
	go func() { result <- client.SandboxController("shim").Create(ctx, info) }()
	resultReceived := false
	defer func() {
		cancel()
		if !resultReceived {
			select {
			case <-result:
			case <-time.After(5 * time.Second):
				t.Error("native creation worker did not stop after cancellation")
			}
		}
	}()
	conn, err := observer.AcceptUnix()
	if err != nil {
		t.Fatalf("observe actual shim launcher: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var observed observedLaunch
	if err := json.NewDecoder(io.LimitReader(conn, 128<<10)).Decode(&observed); err != nil {
		t.Fatalf("decode actual launcher observation: %v", err)
	}
	if observed.Bundle != "" {
		if !strings.HasPrefix(observed.Bundle, state+string(filepath.Separator)) {
			t.Fatalf("native bundle %q escapes private daemon state %q", observed.Bundle, state)
		}
		t.Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cleanupCancel()
			cleanup := exec.CommandContext(cleanupCtx, shimBinary, "-namespace", "gvx-native-test", "-id", info.ID, "-address", address, "-bundle", observed.Bundle, "delete")
			if output, err := cleanup.CombinedOutput(); err != nil {
				t.Errorf("cleanup observed native shim: %v; output=%s", err, output)
			}
		})
	}
	if observed.Error != "" {
		_, _ = conn.Write([]byte{1})
		t.Fatalf("real shim launcher failed before native creation: %s; stderr=%s", observed.Error, observed.Stderr)
	}
	if observed.Stderr != "" {
		t.Errorf("successful actual launcher stderr=%q", observed.Stderr)
	}
	var bootstrap struct {
		Version  int    `json:"version"`
		Protocol string `json:"protocol"`
		Address  string `json:"address"`
	}
	if err := json.Unmarshal(observed.Bootstrap, &bootstrap); err != nil || bootstrap.Version != 3 || bootstrap.Protocol != "ttrpc" || bootstrap.Address != observed.Record.Task.Address {
		t.Fatalf("actual launcher bootstrap=%q: %v", observed.Bootstrap, err)
	}
	if observed.Record.ShimPID == 0 || observed.Record.Phase != recordReady || observed.Record.Identity.ID != info.ID {
		t.Fatalf("actual launcher record lacks a ready child: %+v", observed.Record)
	}
	lease := holdProcessLease(t, observed.Record)
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatalf("release real bootstrap to containerd: %v", err)
	}
	select {
	case err := <-result:
		resultReceived = true
		if !errdefs.IsNotImplemented(err) {
			t.Fatalf("native CreateSandbox error=%v, want NotImplemented after actual shim launch", err)
		}
	case <-ctx.Done():
		t.Fatalf("native CreateSandbox did not complete: %v", ctx.Err())
	}
	awaitProcessExit(t, lease, observed.Record)
	if _, err := os.Stat(observed.Bundle); !os.IsNotExist(err) {
		t.Errorf("native creation failure retained bundle: %v", err)
	}
	stored, err := client.SandboxStore().Get(ctx, info.ID)
	if err == nil {
		if deleteErr := client.SandboxStore().Delete(ctx, stored.ID); deleteErr != nil {
			t.Errorf("delete client-owned sandbox metadata: %v", deleteErr)
		}
	} else if !errdefs.IsNotFound(err) {
		t.Errorf("inspect sandbox metadata after rejection: %v", err)
	}
}

func assertNativePlugins(t *testing.T, ctx context.Context, client *containerd.Client) {
	t.Helper()
	response, err := client.IntrospectionService().Plugins(ctx)
	if err != nil {
		t.Fatalf("inspect private daemon plugins: %v", err)
	}
	needed := map[string]bool{
		"io.containerd.shim.v1.manager":             false,
		"io.containerd.sandbox.controller.v1.shim":  false,
		"io.containerd.grpc.v1.sandbox-controllers": false,
		"io.containerd.grpc.v1.sandboxes":           false,
		"io.containerd.metadata.v1.bolt":            false,
		"io.containerd.event.v1.exchange":           false,
	}
	for _, plugin := range response.Plugins {
		key := plugin.Type + "." + plugin.ID
		if _, required := needed[key]; !required {
			continue
		}
		if plugin.InitErr != nil {
			t.Errorf("required private daemon plugin %s failed: %v", key, plugin.InitErr)
			continue
		}
		needed[key] = true
	}
	for key, available := range needed {
		if !available {
			t.Errorf("required private daemon plugin %s is unavailable", key)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
}
