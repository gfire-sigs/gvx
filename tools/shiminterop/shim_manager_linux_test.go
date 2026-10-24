//go:build linux

package shiminterop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	task "github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/containerd/v2/core/events/exchange"
	"github.com/containerd/containerd/v2/core/runtime"
	v2 "github.com/containerd/containerd/v2/core/runtime/v2"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type instanceObservation struct {
	Phase   string `json:"phase"`
	ShimPID uint32 `json:"shim_pid"`
	Task    struct {
		Address string `json:"address"`
	} `json:"task"`
	Stop struct {
		Address string `json:"address"`
	} `json:"stop"`
}

func TestShimManagerInterop(t *testing.T) {
	if os.Getenv("GVX_SHIM_BINARY") == "" {
		t.Skip("set GVX_SHIM_BINARY to exercise an actual command through containerd v2.1.5 ShimManager")
	}
	binary := os.Getenv("GVX_SHIM_BINARY")
	if !filepath.IsAbs(binary) {
		t.Fatalf("GVX_SHIM_BINARY=%q must be absolute", binary)
	}
	if info, err := os.Stat(binary); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		t.Fatalf("GVX_SHIM_BINARY=%q is not an executable file: %v", binary, err)
	}
	typeurl.Register(&specs.Spec{}, "types.containerd.io", "opencontainers/runtime-spec", strconv.Itoa(specs.VersionMajor), "Spec")
	for _, scenario := range []string{"shutdown", "disconnect"} {
		t.Run(scenario, func(t *testing.T) {
			base := privateDirectory(t)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			ctx = namespaces.WithNamespace(ctx, "gvx-manager-test")
			manager, err := v2.NewShimManager(&v2.ManagerConfig{
				Address:      filepath.Join(base, "containerd.sock"),
				TTRPCAddress: filepath.Join(base, "containerd.ttrpc"),
				Events:       exchange.NewExchange(),
			})
			if err != nil {
				t.Fatalf("create upstream ShimManager: %v", err)
			}
			spec, err := typeurl.MarshalAny(&specs.Spec{Version: specs.Version})
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := v2.NewBundle(ctx, filepath.Join(base, "root"), filepath.Join(base, "state"), "control-"+scenario, spec)
			if err != nil {
				t.Fatalf("create upstream bundle: %v", err)
			}
			instance, err := manager.Start(ctx, bundle.ID, bundle, runtime.CreateOpts{Runtime: binary, Spec: spec})
			if err != nil {
				t.Fatalf("upstream ShimManager Start: %v", err)
			}
			deleted := false
			t.Cleanup(func() {
				if deleted {
					return
				}
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cleanupCancel()
				cleanupCtx = namespaces.WithNamespace(cleanupCtx, bundle.Namespace)
				if err := instance.Delete(cleanupCtx); err != nil {
					t.Errorf("upstream disconnect cleanup: %v", err)
				}
			})
			observation := readInstance(t, bundle.Path)
			lease, err := os.OpenFile(filepath.Join(bundle.Path, ".gvx-shim", "lease"), os.O_RDWR, 0)
			if err != nil {
				t.Fatalf("open actual child's stable lease: %v", err)
			}
			t.Cleanup(func() {
				if err := lease.Close(); err != nil {
					t.Errorf("close observed lease: %v", err)
				}
			})
			client, err := v2.NewTaskClient(instance.Client(), 3)
			if err != nil {
				t.Fatalf("upstream Task v3 client: %v", err)
			}
			connected, err := client.Connect(ctx, &task.ConnectRequest{ID: bundle.ID})
			if err != nil {
				t.Fatalf("upstream Connect: %v", err)
			}
			peerPID := endpointProcessID(t, observation.Task.Address)
			if connected.ShimPid != peerPID || connected.ShimPid != observation.ShimPID || connected.ShimPid == 0 || connected.TaskPid != 0 || connected.Version != "gvx-control-v1" {
				t.Fatalf("upstream Connect=%+v, kernel peer PID=%d, record PID=%d", connected, peerPID, observation.ShimPID)
			}
			if _, err := client.Create(ctx, &task.CreateTaskRequest{ID: bundle.ID, Bundle: bundle.Path}); status.Code(err) != codes.Unimplemented {
				t.Fatalf("direct Task v3 Create=%v, want Unimplemented without v2 retry", err)
			}
			if scenario == "shutdown" {
				if _, err := client.Shutdown(ctx, &task.ShutdownRequest{ID: bundle.ID}); err != nil {
					t.Fatalf("upstream Shutdown response: %v", err)
				}
			} else if err := instance.Close(); err != nil {
				t.Fatalf("disconnect upstream client: %v", err)
			}
			awaitExit(t, ctx, lease, observation)
			// Delete waits for the upstream disconnect callback before removing its bundle.
			if err := instance.Delete(ctx); err != nil {
				t.Fatalf("await upstream executable delete and bundle cleanup: %v", err)
			}
			deleted = true
			if _, err := os.Stat(bundle.Path); !os.IsNotExist(err) {
				t.Errorf("upstream bundle remains: %v", err)
			}
			if _, err := manager.Get(ctx, bundle.ID); !errdefs.IsNotFound(err) {
				t.Errorf("upstream manager retains stopped shim: %v", err)
			}
			t.Logf("SDK 2.1.5 %s: real shim PID=%d, no task PID, lease released, endpoints and bundle removed", scenario, peerPID)
		})
	}
}

func privateDirectory(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "gvxm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Errorf("remove private manager directory: %v", err)
		}
	})
	return base
}

func readInstance(t *testing.T, bundle string) instanceObservation {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(bundle, ".gvx-shim", "state.json"))
	if err != nil {
		t.Fatalf("read actual shim state: %v", err)
	}
	var observation instanceObservation
	if err := json.Unmarshal(data, &observation); err != nil {
		t.Fatalf("decode actual shim state: %v", err)
	}
	if observation.Phase != "ready" || observation.ShimPID == 0 || observation.Task.Address == "" || observation.Stop.Address == "" {
		t.Fatalf("actual shim state lacks a ready child: %+v", observation)
	}
	return observation
}

func endpointProcessID(t *testing.T, address string) uint32 {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Net: "unix", Name: strings.TrimPrefix(address, "unix://")})
	if err != nil {
		t.Fatalf("observe actual Task peer: %v", err)
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var credentials *unix.Ucred
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		t.Fatalf("query Task peer credentials: %v", err)
	}
	if credentialErr != nil || credentials == nil || credentials.Pid <= 0 {
		t.Fatalf("Task peer credentials=%+v error=%v", credentials, credentialErr)
	}
	return uint32(credentials.Pid)
}

func awaitExit(t *testing.T, ctx context.Context, lease *os.File, observation instanceObservation) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := unix.Flock(int(lease.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			t.Fatalf("observe child lease release: %v", err)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("child %d retained its lease: %v", observation.ShimPID, ctx.Err())
		}
	}
	defer func() {
		if err := unix.Flock(int(lease.Fd()), unix.LOCK_UN); err != nil {
			t.Errorf("unlock observed lease: %v", err)
		}
	}()
	for _, address := range []string{observation.Task.Address, observation.Stop.Address} {
		if _, err := os.Lstat(strings.TrimPrefix(address, "unix://")); !os.IsNotExist(err) {
			t.Errorf("child endpoint %q remains after lease release: %v", address, err)
		}
	}
}
