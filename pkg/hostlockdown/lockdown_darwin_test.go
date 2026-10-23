// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build darwin

package hostlockdown

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The tests re-execute the test binary as a locked child. Seatbelt and
// RLIMIT_NPROC cannot be undone, so the lockdown must never touch the parent.

const (
	childModeEnv = "GVX_HOSTLOCKDOWN_CHILD_MODE"
	childWSEnv   = "GVX_HOSTLOCKDOWN_WORKSPACE"
	childWS2Env  = "GVX_HOSTLOCKDOWN_WORKSPACE2"
	childOutEnv  = "GVX_HOSTLOCKDOWN_OUTSIDE"
	childPeerEnv = "GVX_HOSTLOCKDOWN_PEER_PORT"
	childTCPEnv  = "GVX_HOSTLOCKDOWN_TCP_ADDR"
	childUDPEnv  = "GVX_HOSTLOCKDOWN_UDP_ADDR"
	childTCP6Env = "GVX_HOSTLOCKDOWN_TCP6_ADDR"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(childModeEnv); mode != "" {
		if err := runLockedChild(mode); err != nil {
			fmt.Fprintf(os.Stderr, "child %s: %v\n", mode, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type childResult struct {
	cmd    *exec.Cmd
	stdout *bufio.Reader
	stderr *lockedBuffer
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// realTempDir returns a temp directory whose path has no symlink component.
// The Seatbelt subpath filter matches resolved paths.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return dir
}

func startChild(t *testing.T, mode string, env ...string) *childResult {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	// The race runtime sleeps one second at exit unless told otherwise.
	cmd.Env = append(os.Environ(), append([]string{childModeEnv + "=" + mode, "GORACE=atexit_sleep_ms=0"}, env...)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	res := &childResult{cmd: cmd, stdout: bufio.NewReader(stdout), stderr: &lockedBuffer{}}
	cmd.Stderr = res.stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child %s: %v", mode, err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return res
}

// readLine returns the next stdout line of the child.
func (c *childResult) readLine(t *testing.T) string {
	t.Helper()
	line, err := c.stdout.ReadString('\n')
	if err != nil {
		t.Fatalf("read child stdout: %v\nchild stderr:\n%s", err, c.stderr.String())
	}
	return strings.TrimSpace(line)
}

func (c *childResult) wait(t *testing.T) {
	t.Helper()
	if _, err := io.Copy(io.Discard, c.stdout); err != nil {
		t.Fatalf("drain child stdout: %v", err)
	}
	if err := c.cmd.Wait(); err != nil {
		t.Fatalf("locked child failed: %v\nchild stderr:\n%s", err, c.stderr.String())
	}
}

func runChildToCompletion(t *testing.T, mode string, env ...string) {
	t.Helper()
	startChild(t, mode, env...).wait(t)
}

func workspaceEnv(t *testing.T) (ws, outside string, env []string) {
	t.Helper()
	ws = realTempDir(t)
	outside = realTempDir(t)
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("host-secret"), 0o600); err != nil {
		t.Fatalf("WriteFile secret: %v", err)
	}
	return ws, outside, []string{childWSEnv + "=" + ws, childOutEnv + "=" + outside}
}

func TestLockdownDarwinFilesAndProcesses(t *testing.T) {
	_, _, env := workspaceEnv(t)
	runChildToCompletion(t, "files", env...)
}

// TestLockdownDarwinPreSpawnedChild covers a helper process that Apply must
// leave alone: the stub of the systrap engine starts before Apply.
func TestLockdownDarwinPreSpawnedChild(t *testing.T) {
	_, _, env := workspaceEnv(t)
	runChildToCompletion(t, "prespawned-child", env...)
}

func TestLockdownDarwinReadOnlyWorkspace(t *testing.T) {
	_, _, env := workspaceEnv(t)
	runChildToCompletion(t, "readonly-workspace", env...)
}

func TestLockdownDarwinNetworkBlocked(t *testing.T) {
	_, _, env := workspaceEnv(t)
	runChildToCompletion(t, "net-none", env...)
}

func TestLockdownDarwinRuntimeStillWorks(t *testing.T) {
	_, _, env := workspaceEnv(t)
	runChildToCompletion(t, "runtime", env...)
}

func TestLockdownDarwinOutboundNATAndInbound(t *testing.T) {
	_, _, env := workspaceEnv(t)
	child := startChild(t, "net-nat", env...)
	addr := child.readLine(t)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial child listener %s: %v\nchild stderr:\n%s", addr, err, child.stderr.String())
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatalf("write to child listener: %v", err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || reply != "pong\n" {
		t.Fatalf("child listener reply = %q, %v; want pong\\n\nchild stderr:\n%s", reply, err, child.stderr.String())
	}
	child.wait(t)
}

func TestLockdownDarwinWireGuardStyleUDP(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP peer: %v", err)
	}
	defer func() { _ = peer.Close() }()
	peerPort := peer.LocalAddr().(*net.UDPAddr).Port

	_, _, env := workspaceEnv(t)
	child := startChild(t, "net-udp", append(env, childPeerEnv+"="+strconv.Itoa(peerPort))...)
	childAddr, err := net.ResolveUDPAddr("udp4", child.readLine(t))
	if err != nil {
		t.Fatalf("resolve child UDP address: %v", err)
	}
	if _, err := peer.WriteToUDP([]byte("from-peer"), childAddr); err != nil {
		t.Fatalf("peer send: %v", err)
	}
	buf := make([]byte, 64)
	if err := peer.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "from-child" {
		t.Fatalf("peer received %q, %v; want from-child\nchild stderr:\n%s", buf[:n], err, child.stderr.String())
	}
	child.wait(t)
}

// TestLockdownDarwinFreshOutboundSockets dials from a child that opened no
// socket before Apply. The Go net package probes IP stack support with bind,
// which the profile denies, so Apply must run that probe first.
func TestLockdownDarwinFreshOutboundSockets(t *testing.T) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = tcp.Close() }()
	go func() {
		conn, err := tcp.Accept()
		if err == nil {
			_, _ = io.Copy(conn, conn)
			_ = conn.Close()
		}
	}()
	tcp6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatalf("Listen tcp6: %v", err)
	}
	defer func() { _ = tcp6.Close() }()
	go func() {
		conn, err := tcp6.Accept()
		if err == nil {
			_, _ = io.Copy(conn, conn)
			_ = conn.Close()
		}
	}()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer func() { _ = udp.Close() }()
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udp.WriteToUDP(buf[:n], from)
		}
	}()
	_, _, env := workspaceEnv(t)
	runChildToCompletion(t, "net-fresh", append(env,
		childTCPEnv+"="+tcp.Addr().String(), childTCP6Env+"="+tcp6.Addr().String(), childUDPEnv+"="+udp.LocalAddr().String())...)
}

func TestLockdownDarwinTwoMountsWithDifferentAccess(t *testing.T) {
	_, _, env := workspaceEnv(t)
	env = append(env, childWS2Env+"="+realTempDir(t))
	runChildToCompletion(t, "two-mounts", env...)
}

func TestLockdownDarwinNestedAndDuplicateMounts(t *testing.T) {
	_, _, env := workspaceEnv(t)
	runChildToCompletion(t, "nested-mounts", env...)
}

func TestLockdownDarwinRejectsRootWorkspace(t *testing.T) {
	runChildToCompletion(t, "root-workspace")
}

func TestLockdownDarwinRejectsMissingWorkspace(t *testing.T) {
	runChildToCompletion(t, "missing-workspace", childWSEnv+"="+filepath.Join(realTempDir(t), "absent"))
}

// childChecks collects every failed expectation so that one run reports all
// broken properties.
type childChecks struct{ errs []error }

func (c *childChecks) expect(ok bool, format string, args ...any) {
	if !ok {
		c.errs = append(c.errs, fmt.Errorf(format, args...))
	}
}

func (c *childChecks) err() error { return errors.Join(c.errs...) }

func runLockedChild(mode string) error {
	switch mode {
	case "files":
		return childFiles()
	case "readonly-workspace":
		return childReadOnlyWorkspace()
	case "two-mounts":
		return childTwoMounts()
	case "nested-mounts":
		return childNestedMounts()
	case "prespawned-child":
		return childPreSpawned()
	case "net-none":
		return childNetNone()
	case "net-nat":
		return childNetNAT()
	case "net-udp":
		return childNetUDP()
	case "net-fresh":
		return childNetFresh()
	case "runtime":
		return childRuntime()
	case "root-workspace":
		_, err := Apply(Options{Mounts: []HostMount{{Path: "/"}}})
		if err == nil {
			return errors.New("Apply accepted workspace /")
		}
		if IsLockedDown() {
			return errors.New("IsLockedDown after rejected Apply")
		}
		return nil
	case "missing-workspace":
		_, err := Apply(Options{Mounts: []HostMount{{Path: os.Getenv(childWSEnv)}}})
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("Apply(missing workspace) = %v, want ErrNotExist", err)
		}
		if IsLockedDown() {
			return errors.New("IsLockedDown after rejected Apply")
		}
		return nil
	}
	return fmt.Errorf("unknown mode %q", mode)
}

func childFiles() error {
	ws, outside := os.Getenv(childWSEnv), os.Getenv(childOutEnv)
	secret := filepath.Join(outside, "secret.txt")

	root, err := os.OpenRoot(ws)
	if err != nil {
		return err
	}
	pre, err := os.OpenFile(filepath.Join(ws, "pre.txt"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(ws, "existing.txt"), []byte("existing"), 0o600); err != nil {
		return err
	}
	if err := os.Symlink(secret, filepath.Join(ws, "escape")); err != nil {
		return err
	}
	secretHandle, err := os.Open(secret)
	if err != nil {
		return err
	}

	st, err := Apply(Options{Mounts: []HostMount{{Path: ws}}})
	if err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	var c childChecks
	c.expect(st.Applied && st.SubprocessBlocked && st.UnboundFileOpenBlocked && st.NetworkOutboundBlocked, "status = %+v", st)
	c.expect(IsLockedDown(), "IsLockedDown = false after Apply")
	again, err := Apply(Options{Mounts: []HostMount{{Path: ws}}})
	c.expect(err == nil && again == st, "second Apply = %+v, %v; want %+v", again, err, st)

	// Descriptors opened before Apply keep working, including descriptors for
	// files that no profile rule names.
	_, err = pre.WriteString("pre-opened")
	c.expect(err == nil, "write pre-opened fd: %v", err)
	data, err := io.ReadAll(secretHandle)
	c.expect(err == nil && string(data) == "host-secret", "read pre-opened outside fd = %q, %v", data, err)

	// The pinned root handle serves create, rename and remove.
	f, err := root.OpenFile("new.txt", os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	c.expect(err == nil, "root create: %v", err)
	if err == nil {
		_, werr := f.WriteString("created")
		c.expect(werr == nil, "root write: %v", werr)
		c.expect(f.Close() == nil, "root close")
	}
	c.expect(root.Mkdir("sub", 0o700) == nil, "root mkdir")
	c.expect(root.Rename("new.txt", "sub/renamed.txt") == nil, "root rename")
	c.expect(root.Remove("sub/renamed.txt") == nil, "root remove")
	data, err = os.ReadFile(filepath.Join(ws, "existing.txt"))
	c.expect(err == nil && string(data) == "existing", "read existing by path = %q, %v", data, err)
	c.expect(os.WriteFile(filepath.Join(ws, "byname.txt"), []byte("x"), 0o600) == nil, "create by absolute path in workspace")

	// New opens outside the workspace fail with a permission error.
	_, err = os.ReadFile(secret)
	c.expect(errors.Is(err, fs.ErrPermission), "read outside by path = %v, want permission error", err)
	err = os.WriteFile(filepath.Join(outside, "created.txt"), []byte("x"), 0o600)
	c.expect(errors.Is(err, fs.ErrPermission), "create outside = %v, want permission error", err)
	_, err = os.Open("/private/etc/passwd")
	c.expect(errors.Is(err, fs.ErrPermission), "open /private/etc/passwd = %v, want permission error", err)
	_, err = os.ReadDir(filepath.Dir(ws))
	c.expect(errors.Is(err, fs.ErrPermission), "list workspace parent = %v, want permission error", err)
	_, err = os.CreateTemp("", "gvx-lockdown-")
	c.expect(errors.Is(err, fs.ErrPermission), "CreateTemp in TMPDIR = %v, want permission error", err)
	_, err = os.ReadFile(filepath.Join(ws, "escape"))
	c.expect(errors.Is(err, fs.ErrPermission), "read symlink escaping the workspace = %v, want permission error", err)

	// Signals reach only the locked process itself.
	err = syscall.Kill(os.Getppid(), 0)
	c.expect(errors.Is(err, syscall.EPERM), "kill(parent, 0) = %v, want EPERM", err)

	// Process creation fails through every Go entry point.
	_, err = os.StartProcess("/usr/bin/true", []string{"true"}, &os.ProcAttr{})
	c.expect(err != nil, "os.StartProcess succeeded")
	c.expect(exec.Command("/usr/bin/true").Run() != nil, "exec.Command succeeded")
	_, err = syscall.ForkExec("/usr/bin/true", []string{"true"}, &syscall.ProcAttr{})
	c.expect(err != nil, "syscall.ForkExec succeeded")
	return c.err()
}

// childTwoMounts applies two mounts with different access. Both must open and
// follow their own read-only flag. A path outside both must stay closed.
func childTwoMounts() error {
	rw, ro, outside := os.Getenv(childWSEnv), os.Getenv(childWS2Env), os.Getenv(childOutEnv)
	if err := os.WriteFile(filepath.Join(rw, "in.txt"), []byte("rw-data"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(ro, "in.txt"), []byte("ro-data"), 0o600); err != nil {
		return err
	}
	st, err := Apply(Options{Mounts: []HostMount{{Path: rw}, {Path: ro, ReadOnly: true}}})
	if err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	var c childChecks
	c.expect(st.Applied && st.UnboundFileOpenBlocked, "status = %+v", st)
	data, err := os.ReadFile(filepath.Join(rw, "in.txt"))
	c.expect(err == nil && string(data) == "rw-data", "read writable mount = %q, %v", data, err)
	c.expect(os.WriteFile(filepath.Join(rw, "out.txt"), []byte("x"), 0o600) == nil, "write in writable mount")
	data, err = os.ReadFile(filepath.Join(ro, "in.txt"))
	c.expect(err == nil && string(data) == "ro-data", "read read-only mount = %q, %v", data, err)
	err = os.WriteFile(filepath.Join(ro, "out.txt"), []byte("x"), 0o600)
	c.expect(errors.Is(err, fs.ErrPermission), "write in read-only mount = %v, want permission error", err)
	_, err = os.ReadFile(filepath.Join(outside, "secret.txt"))
	c.expect(errors.Is(err, fs.ErrPermission), "read outside both mounts = %v, want permission error", err)
	_, err = os.ReadDir(filepath.Dir(rw))
	c.expect(errors.Is(err, fs.ErrPermission), "list the parent of the mounts = %v, want permission error", err)
	return c.err()
}

// childNestedMounts applies a duplicate mount and a mount below another one.
// Apply must succeed, and the probes must pick paths that no mount covers.
func childNestedMounts() error {
	ws, outside := os.Getenv(childWSEnv), os.Getenv(childOutEnv)
	sub := filepath.Join(ws, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(sub, "in.txt"), []byte("nested"), 0o600); err != nil {
		return err
	}
	_, err := Apply(Options{Mounts: []HostMount{{Path: ws}, {Path: sub, ReadOnly: true}, {Path: ws}, {Path: sub, ReadOnly: true}}})
	if err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	var c childChecks
	data, err := os.ReadFile(filepath.Join(sub, "in.txt"))
	c.expect(err == nil && string(data) == "nested", "read nested mount = %q, %v", data, err)
	_, err = os.ReadFile(filepath.Join(outside, "secret.txt"))
	c.expect(errors.Is(err, fs.ErrPermission), "read outside the mounts = %v, want permission error", err)
	return c.err()
}

func childPreSpawned() error {
	ws := os.Getenv(childWSEnv)
	helper := exec.Command("/bin/sleep", "60")
	if err := helper.Start(); err != nil {
		return err
	}
	if _, err := Apply(Options{Mounts: []HostMount{{Path: ws}}}); err != nil {
		_ = helper.Process.Kill()
		return fmt.Errorf("Apply: %w", err)
	}
	var c childChecks
	c.expect(helper.Process.Signal(syscall.Signal(0)) == nil, "signal 0 to pre-spawned child failed")
	c.expect(helper.Process.Kill() == nil, "kill pre-spawned child failed")
	err := helper.Wait()
	var exitErr *exec.ExitError
	c.expect(errors.As(err, &exitErr), "wait for pre-spawned child = %v, want exit error from the kill", err)
	return c.err()
}

func childReadOnlyWorkspace() error {
	ws := os.Getenv(childWSEnv)
	existing := filepath.Join(ws, "existing.txt")
	if err := os.WriteFile(existing, []byte("existing"), 0o600); err != nil {
		return err
	}
	root, err := os.OpenRoot(ws)
	if err != nil {
		return err
	}
	if _, err := Apply(Options{Mounts: []HostMount{{Path: ws, ReadOnly: true}}}); err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	var c childChecks
	data, err := os.ReadFile(existing)
	c.expect(err == nil && string(data) == "existing", "read in read-only workspace = %q, %v", data, err)
	f, err := root.Open("existing.txt")
	c.expect(err == nil, "root open for read: %v", err)
	if err == nil {
		_ = f.Close()
	}
	_, err = root.OpenFile("existing.txt", os.O_WRONLY, 0)
	c.expect(errors.Is(err, fs.ErrPermission), "root open for write = %v, want permission error", err)
	_, err = root.OpenFile("created.txt", os.O_CREATE|os.O_WRONLY, 0o600)
	c.expect(errors.Is(err, fs.ErrPermission), "root create = %v, want permission error", err)
	c.expect(errors.Is(root.Remove("existing.txt"), fs.ErrPermission), "root remove did not fail with a permission error")
	return c.err()
}

func childNetNone() error {
	ws := os.Getenv(childWSEnv)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	st, err := Apply(Options{Mounts: []HostMount{{Path: ws}}})
	if err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	var c childChecks
	c.expect(st.NetworkOutboundBlocked, "NetworkOutboundBlocked = false")
	_, err = net.DialTimeout("tcp4", l.Addr().String(), 5*time.Second)
	c.expect(errors.Is(err, fs.ErrPermission), "TCP dial = %v, want permission error", err)
	_, err = u.WriteToUDP([]byte("x"), u.LocalAddr().(*net.UDPAddr))
	c.expect(errors.Is(err, fs.ErrPermission), "UDP send = %v, want permission error", err)
	_, err = net.Listen("tcp4", "127.0.0.1:0")
	c.expect(errors.Is(err, fs.ErrPermission), "new listener = %v, want permission error", err)
	return c.err()
}

func childNetNAT() error {
	ws := os.Getenv(childWSEnv)
	inbound, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	u1, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	u2, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	st, err := Apply(Options{Mounts: []HostMount{{Path: ws}}, AllowOutboundNet: true})
	if err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	var c childChecks
	c.expect(!st.NetworkOutboundBlocked, "NetworkOutboundBlocked = true with AllowOutboundNet")

	// New outbound TCP connection to a pre-bound target.
	go func() {
		conn, err := target.Accept()
		if err == nil {
			_, _ = io.Copy(conn, conn)
			_ = conn.Close()
		}
	}()
	conn, err := net.DialTimeout("tcp4", target.Addr().String(), 5*time.Second)
	c.expect(err == nil, "outbound dial: %v", err)
	if err == nil {
		_, werr := conn.Write([]byte("echo\n"))
		line, rerr := bufio.NewReader(conn).ReadString('\n')
		c.expect(werr == nil && rerr == nil && line == "echo\n", "outbound echo = %q, %v, %v", line, werr, rerr)
		_ = conn.Close()
	}

	// Outbound UDP between pre-bound sockets.
	_, err = u1.WriteToUDP([]byte("udp"), u2.LocalAddr().(*net.UDPAddr))
	c.expect(err == nil, "UDP send: %v", err)
	_ = u2.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	n, _, err := u2.ReadFromUDP(buf)
	c.expect(err == nil && string(buf[:n]) == "udp", "UDP receive = %q, %v", buf[:n], err)

	// A new listener needs bind, which no profile rule allows.
	_, err = net.Listen("tcp4", "127.0.0.1:0")
	c.expect(errors.Is(err, fs.ErrPermission), "new listener = %v, want permission error", err)

	if err := c.err(); err != nil {
		return err
	}
	// Accept on the pre-bound listener for a connection from the parent.
	fmt.Println(inbound.Addr().String())
	conn, err = inbound.Accept()
	if err != nil {
		return fmt.Errorf("accept on pre-bound listener: %w", err)
	}
	defer func() { _ = conn.Close() }()
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || line != "ping\n" {
		return fmt.Errorf("inbound read = %q, %v", line, err)
	}
	_, err = conn.Write([]byte("pong\n"))
	return err
}

func childNetUDP() error {
	ws := os.Getenv(childWSEnv)
	peerPort, err := strconv.ParseUint(os.Getenv(childPeerEnv), 10, 16)
	if err != nil {
		return err
	}
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	st, err := Apply(Options{Mounts: []HostMount{{Path: ws}}, OutboundUDPPorts: []uint16{uint16(peerPort)}})
	if err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	var c childChecks
	c.expect(st.NetworkOutboundBlocked, "NetworkOutboundBlocked = false in UDP-peer mode")
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(peerPort)}

	// A datagram to a port outside the allowed list fails.
	_, err = sock.WriteToUDP([]byte("x"), other.LocalAddr().(*net.UDPAddr))
	c.expect(errors.Is(err, fs.ErrPermission), "UDP send to unlisted port = %v, want permission error", err)
	_, err = net.DialTimeout("tcp4", peer.String(), time.Second)
	c.expect(errors.Is(err, fs.ErrPermission), "TCP dial to peer port = %v, want permission error", err)
	if err := c.err(); err != nil {
		return err
	}

	fmt.Println(sock.LocalAddr().String())
	_ = sock.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	n, from, err := sock.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "from-peer" {
		return fmt.Errorf("receive from peer = %q, %v", buf[:n], err)
	}
	if _, err := sock.WriteToUDP([]byte("from-child"), from); err != nil {
		return fmt.Errorf("send to peer: %w", err)
	}
	return nil
}

func childNetFresh() error {
	ws := os.Getenv(childWSEnv)
	if _, err := Apply(Options{Mounts: []HostMount{{Path: ws}}, AllowOutboundNet: true}); err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	var c childChecks
	conn, err := net.DialTimeout("tcp", os.Getenv(childTCPEnv), 5*time.Second)
	c.expect(err == nil, "TCP dial: %v", err)
	if err == nil {
		_, werr := conn.Write([]byte("echo\n"))
		line, rerr := bufio.NewReader(conn).ReadString('\n')
		c.expect(werr == nil && rerr == nil && line == "echo\n", "TCP echo = %q, %v, %v", line, werr, rerr)
		_ = conn.Close()
	}
	conn6, err := net.DialTimeout("tcp", os.Getenv(childTCP6Env), 5*time.Second)
	c.expect(err == nil, "TCP dial over IPv6: %v", err)
	if err == nil {
		_, werr := conn6.Write([]byte("echo\n"))
		line, rerr := bufio.NewReader(conn6).ReadString('\n')
		c.expect(werr == nil && rerr == nil && line == "echo\n", "IPv6 echo = %q, %v, %v", line, werr, rerr)
		_ = conn6.Close()
	}
	uconn, err := net.Dial("udp", os.Getenv(childUDPEnv))
	c.expect(err == nil, "UDP dial: %v", err)
	if err == nil {
		_, werr := uconn.Write([]byte("dgram"))
		_ = uconn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 16)
		n, rerr := uconn.Read(buf)
		c.expect(werr == nil && rerr == nil && string(buf[:n]) == "dgram", "UDP echo = %q, %v, %v", buf[:n], werr, rerr)
		_ = uconn.Close()
	}
	return c.err()
}

func childRuntime() error {
	ws := os.Getenv(childWSEnv)
	if _, err := Apply(Options{Mounts: []HostMount{{Path: ws}}}); err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	var c childChecks

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGUSR1)
	c.expect(syscall.Kill(os.Getpid(), syscall.SIGUSR1) == nil, "kill self")
	select {
	case <-sigs:
	case <-time.After(10 * time.Second):
		c.expect(false, "SIGUSR1 to self not delivered")
	}

	// Blocking syscalls on many pipes force the runtime to start new threads.
	const workers = 24
	writers := make([]int, 0, workers)
	results := make(chan error, workers)
	for range workers {
		var fds [2]int
		if err := unix.Pipe(fds[:]); err != nil {
			return fmt.Errorf("pipe after Apply: %w", err)
		}
		writers = append(writers, fds[1])
		go func() {
			var b [1]byte
			_, err := unix.Read(fds[0], b[:])
			results <- err
		}()
	}
	runtime.GC()
	for _, w := range writers {
		_, err := unix.Write(w, []byte{1})
		c.expect(err == nil, "write pipe: %v", err)
	}
	for range workers {
		select {
		case err := <-results:
			c.expect(err == nil, "blocked read: %v", err)
		case <-time.After(10 * time.Second):
			return errors.Join(c.err(), errors.New("blocked readers did not finish"))
		}
	}

	// Anonymous mappings and protection changes stay available.
	mem, err := unix.Mmap(-1, 0, 1<<20, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	c.expect(err == nil, "mmap anon: %v", err)
	if err == nil {
		mem[0] = 1
		c.expect(unix.Mprotect(mem, unix.PROT_READ) == nil, "mprotect")
		c.expect(unix.Munmap(mem) == nil, "munmap")
	}
	kq, err := unix.Kqueue()
	c.expect(err == nil, "kqueue: %v", err)
	if err == nil {
		_ = unix.Close(kq)
	}

	// Timers and locked OS threads.
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		time.Sleep(5 * time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		c.expect(false, "locked-thread goroutine timed out")
	}
	for range 3 {
		runtime.GC()
	}
	return c.err()
}
