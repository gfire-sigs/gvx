//go:build linux || darwin

package gvxshim

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestUnsafeStateDirectoryIsNotRepaired(t *testing.T) {
	owner, err := currentOwner()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := canonicalBundle(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(bundle, ".gvx-shim")
	if err := os.Mkdir(state, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0755); err != nil {
		t.Fatal(err)
	}
	id := instanceIdentity{Owner: owner, Namespace: "unsafe-tests", ID: "mode", Bundle: bundle}
	id.ContainerdAddress = "unix:///tmp/platform-containerd"
	if paths, err := openPaths(t.Context(), id, createPaths); err == nil {
		paths.Close()
		t.Fatal("unsafe directory accepted")
	}
	info, err := os.Stat(state)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("existing mode changed: %v, %v", info, err)
	}
}

func TestStateSymlinkDoesNotModifyTarget(t *testing.T) {
	owner, err := currentOwner()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := canonicalBundle(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(bundle, ".gvx-shim")); err != nil {
		t.Fatal(err)
	}
	id := instanceIdentity{Owner: owner, Namespace: "unsafe-tests", ID: "symlink", Bundle: bundle, ContainerdAddress: "unix:///tmp/platform-containerd"}
	if paths, err := openPaths(t.Context(), id, createPaths); err == nil {
		paths.Close()
		t.Fatal("symlink accepted")
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatalf("symlink target modified: %v, %v", entries, err)
	}
}

func TestPinnedDirectoryReplacementIsRejected(t *testing.T) {
	paths := platformFixture(t)
	state := filepath.Join(paths.Identity.Bundle, ".gvx-shim")
	if err := os.Rename(state, state+"-saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	if err := paths.Revalidate(paths.Snapshot); !errors.Is(err, errPathChanged) {
		t.Fatalf("replaced directory: %v", err)
	}
}

func TestUnixEndpointAuthorizesOwnerAndRetainsSocketForOwnedCleanup(t *testing.T) {
	paths := platformFixture(t)
	if err := prepareEndpointDir(t.Context(), paths); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := removeEndpointDir(paths, *paths.Snapshot.UnixEndpointDir); err != nil {
			t.Error(err)
		}
	})
	endpoint, err := listenLocal(t.Context(), paths, taskEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		endpoint.Listener.Close()
		if err := removeOwned(paths.UnixEndpointDir, *endpoint.Ref.Socket); err != nil {
			t.Error(err)
		}
	})
	accepted := make(chan error, 1)
	go func() {
		conn, err := endpoint.Listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		var byte [1]byte
		_, err = io.ReadFull(conn, byte[:])
		if err == nil && byte[0] != 42 {
			err = errors.New("incorrect socket payload")
		}
		accepted <- err
	}()
	conn, err := dialLocal(t.Context(), paths.TaskAddress)
	if err != nil {
		endpoint.Listener.Close()
		<-accepted
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, writeErr := conn.Write([]byte{42})
	conn.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if err := endpoint.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := paths.UnixEndpointDir.Root.Lstat("task")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode: %v", info.Mode())
	}
	if err := removeOwned(paths.UnixEndpointDir, *endpoint.Ref.Socket); err != nil {
		t.Fatal(err)
	}
	if _, err := paths.UnixEndpointDir.Root.Lstat("task"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned socket remains: %v", err)
	}
}

func TestLocalDialRejectsNonFilesystemTransports(t *testing.T) {
	for _, address := range []string{"tcp://127.0.0.1:1", "unix://@abstract", "unix:///tmp/../outside"} {
		if conn, err := dialLocal(t.Context(), address); err == nil {
			conn.Close()
			t.Errorf("accepted %q", address)
		}
	}
}

func TestUnixPeerUIDPolicyRejectsEveryForeignOwner(t *testing.T) {
	for _, tc := range []struct {
		name    string
		peer    uint32
		owner   uint32
		allowed bool
	}{
		{"same root", 0, 0, true},
		{"same user", 1000, 1000, true},
		{"foreign user", 1001, 1000, false},
		{"root is not configured owner", 0, 1000, false},
		{"user is not root owner", 1000, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := authorizeUID(tc.peer, tc.owner)
			if tc.allowed && err != nil {
				t.Fatalf("same UID rejected: %v", err)
			}
			if !tc.allowed && !errors.Is(err, errUnsafeEntry) {
				t.Fatalf("foreign UID accepted: %v", err)
			}
		})
	}
}

func TestOwnedSocketCleanupPreservesReplacement(t *testing.T) {
	paths := platformFixture(t)
	if err := prepareEndpointDir(t.Context(), paths); err != nil {
		t.Fatal(err)
	}
	var listeners []net.Listener
	var refs []ownedEntry
	t.Cleanup(func() {
		for _, listener := range listeners {
			listener.Close()
		}
		for _, ref := range refs {
			if err := removeOwned(paths.UnixEndpointDir, ref); err != nil {
				t.Error(err)
			}
		}
		if err := removeEndpointDir(paths, *paths.Snapshot.UnixEndpointDir); err != nil {
			t.Error(err)
		}
	})
	original, err := listenLocal(t.Context(), paths, taskEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	listeners = append(listeners, original.Listener)
	refs = append(refs, *original.Ref.Socket)
	if err := original.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := paths.UnixEndpointDir.Root.Rename("task", "retained"); err != nil {
		t.Fatal(err)
	}
	refs[0].Name = "retained"
	replacement, err := listenLocal(t.Context(), paths, taskEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	listeners = append(listeners, replacement.Listener)
	refs = append(refs, *replacement.Ref.Socket)
	if err := removeOwned(paths.UnixEndpointDir, *original.Ref.Socket); !errors.Is(err, errPathChanged) {
		t.Fatalf("replaced socket cleanup: %v", err)
	}
	if err := removeBoundSocket(paths.UnixEndpointDir, *original.Ref.Socket); !errors.Is(err, errPathChanged) {
		t.Fatalf("startup rollback removed replacement socket: %v", err)
	}
	actual, err := inspectEntry(paths.UnixEndpointDir, "task", socketEntry)
	if err != nil || actual != *replacement.Ref.Socket {
		t.Fatalf("replacement socket changed: %+v, %v", actual, err)
	}
}

func TestEndpointDirectoryCleanupPreservesUnknownEntry(t *testing.T) {
	paths := platformFixture(t)
	if err := prepareEndpointDir(t.Context(), paths); err != nil {
		t.Fatal(err)
	}
	file, err := openPrivateFile(paths.UnixEndpointDir, "unrelated", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("preserve"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	ref, err := inspectEntry(paths.UnixEndpointDir, "unrelated", regularEntry)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := removeOwned(paths.UnixEndpointDir, ref); err != nil {
			t.Error(err)
		}
		if err := removeEndpointDir(paths, *paths.Snapshot.UnixEndpointDir); err != nil {
			t.Error(err)
		}
	})
	if err := removeEndpointDir(paths, *paths.Snapshot.UnixEndpointDir); err == nil {
		t.Fatal("nonempty endpoint directory removed")
	}
	data, err := paths.UnixEndpointDir.Root.ReadFile("unrelated")
	if err != nil || string(data) != "preserve" {
		t.Fatalf("unknown entry changed: %q, %v", data, err)
	}
}

func TestUnsafeDiagnosticsAccessIsRejectedWithoutRepair(t *testing.T) {
	paths := platformFixture(t)
	file, ref, err := createDiagnostics(paths)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("private diagnostics"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(paths.Identity.Bundle, ".gvx-shim", ref.Name)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if output, err := openLog(t.Context(), paths, ref, time.Second); err == nil {
		output.Close(t.Context())
		t.Fatal("group-readable diagnostics accepted")
	} else if !errors.Is(err, errUnsafeEntry) {
		t.Fatalf("unsafe diagnostics error: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatalf("unsafe diagnostics permissions changed: %v", info.Mode())
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "private diagnostics" {
		t.Fatalf("unsafe diagnostics changed: %q, %v", data, err)
	}
}

func TestBoundSocketRollbackAfterDescriptorExhaustion(t *testing.T) {
	const childEnvironment = "GVX_SOCKET_ROLLBACK_CHILD"
	if os.Getenv(childEnvironment) != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestBoundSocketRollbackAfterDescriptorExhaustion$")
		cmd.Env = append(os.Environ(), childEnvironment+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("descriptor-limit subprocess: %v\n%s", err, output)
		}
		return
	}
	paths := platformFixture(t)
	if err := prepareEndpointDir(t.Context(), paths); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := removeEndpointDir(paths, *paths.Snapshot.UnixEndpointDir); err != nil {
			t.Error(err)
		}
	})
	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
		t.Fatal(err)
	}
	limited := original
	limited.Cur = min(limited.Cur, 128)
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limited); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
			t.Error(err)
		}
	}()
	var descriptors []int
	defer func() {
		for _, fd := range descriptors {
			unix.Close(fd)
		}
	}()
	for {
		fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.EMFILE) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		descriptors = append(descriptors, fd)
	}
	if len(descriptors) == 0 {
		t.Fatal("no descriptor available to reserve for bind")
	}
	last := len(descriptors) - 1
	if err := unix.Close(descriptors[last]); err != nil {
		t.Fatal(err)
	}
	descriptors = descriptors[:last]
	listener, bindErr := bindPinnedSocket(paths.UnixEndpointDir, "task")
	if listener != nil {
		listener.Close()
	}
	for _, fd := range descriptors {
		unix.Close(fd)
	}
	descriptors = nil
	if !errors.Is(bindErr, unix.EMFILE) {
		t.Fatalf("listener conversion failure: got %v, want descriptor exhaustion", bindErr)
	}
	if _, err := paths.UnixEndpointDir.Root.Lstat("task"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed conversion retained bound socket: %v", err)
	}
}
