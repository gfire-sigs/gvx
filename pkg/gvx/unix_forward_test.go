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

package gvx

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

func TestParseUnixForwardAndConfigValidation(t *testing.T) {
	uf, err := ParseUnixForward("/run/host-services/ssh-auth.sock=/tmp/agent.sock,uid=1000,gid=2000,mode=0600")
	if err != nil {
		t.Fatalf("ParseUnixForward: %v", err)
	}
	if uf.GuestPath != "/run/host-services/ssh-auth.sock" || uf.HostSocket != "/tmp/agent.sock" || uf.UID != 1000 || uf.GID != 2000 || uf.Mode != 0o600 {
		t.Fatalf("parsed = %+v", uf)
	}

	for _, bad := range []string{
		"",
		"no-equals",
		"relative=/tmp/a.sock",
		"/=/tmp/a.sock",
		"/tmp/s=",
		"/tmp/s=/tmp/a.sock,mode=0",
		"/tmp/s=/tmp/a.sock,mode=01000",
		"/tmp/s=/tmp/a.sock,uid=abc",
		"/tmp/s=/tmp/a.sock,unknown=1",
		"/" + strings.Repeat("a", 108) + "=/tmp/a.sock",
	} {
		if _, err := ParseUnixForward(bad); err == nil {
			t.Fatalf("ParseUnixForward(%q) succeeded, want error", bad)
		}
	}

	// Under lockdown without a pre-lockdown Dial callback, normalize must refuse.
	cfgLocked := Config{
		NetworkMode:  NetModeNone,
		UnixForwards: []UnixForward{{GuestPath: "/tmp/s", HostSocket: "/tmp/h.sock"}},
	}
	if err := cfgLocked.normalize(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("locked UnixForward without Dial err = %v, want ErrInvalidConfig", err)
	}

	// Duplicate guest paths are refused.
	cfgDup := Config{
		NetworkMode:         NetModeNone,
		DisableHostLockdown: true,
		UnixForwards: []UnixForward{
			{GuestPath: "/tmp/s", HostSocket: "/tmp/a.sock"},
			{GuestPath: "/tmp/s", HostSocket: "/tmp/b.sock"},
		},
	}
	if err := cfgDup.normalize(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("duplicate UnixForward err = %v, want ErrInvalidConfig", err)
	}
}

func buildGuestUnixClientELF(t *testing.T) []byte {
	t.Helper()
	srcDir := t.TempDir()
	src := `package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: uclient <sock> <msg|repeat:N>")
		os.Exit(2)
	}
	sockPath := os.Args[1]
	msg := os.Args[2]
	large := false
	if rest, ok := strings.CutPrefix(msg, "repeat:"); ok {
		n, err := strconv.Atoi(rest)
		if err != nil {
			os.Exit(2)
		}
		msg = strings.Repeat("0123456789abcdef", n/16)
		large = true
	}
	fi, err := os.Lstat(sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lstat: %v\n", err)
		os.Exit(3)
	}
	st := fi.Sys().(*syscall.Stat_t)
	fmt.Printf("STAT mode=%04o uid=%d gid=%d type=%v\n", fi.Mode().Perm(), st.Uid, st.Gid, fi.Mode()&os.ModeSocket != 0)
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial: %v\n", err)
		os.Exit(4)
	}
	defer c.Close()
	if _, err := io.WriteString(c, msg+"\n"); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(5)
	}
	if uc, ok := c.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	reply, err := io.ReadAll(c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		os.Exit(6)
	}
	if large {
		sum := sha256.Sum256(reply)
		fmt.Printf("LARGE len=%d sha256=%s\n", len(reply), hex.EncodeToString(sum[:]))
		return
	}
	fmt.Printf("REPLY %s\n", string(reply))
}
`
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module uclient\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	outPath := filepath.Join(srcDir, "uclient")
	cmd := exec.Command("go", "build", "-ldflags=-linkmode=internal", "-o", outPath, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build guest unix client: %v\n%s", err, out)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read uclient: %v", err)
	}
	return data
}

func startHostUnixEchoServer(t *testing.T) string {
	t.Helper()
	sockPath := shortControlSocketPath(t, "agent.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen host unix %q: %v", sockPath, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				req, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil && !errors.Is(err, io.EOF) {
					return
				}
				req = strings.TrimSuffix(req, "\n")
				_, _ = io.WriteString(conn, "host-agent:"+req)
			}(c)
		}
	}()
	return sockPath
}

func TestUnixForwardBootAndRuntimeControlRPC(t *testing.T) {
	hostSock := startHostUnixEchoServer(t)
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	uclientELF := buildGuestUnixClientELF(t)

	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "bin/uclient", Data: uclientELF, Mode: 0o755},
		testimage.File{Name: "etc/ready.txt", Data: []byte("uf-ready\n"), Mode: 0o644},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	regURL := testimage.NewRegistry(t, "ufwd", "latest", testimage.Image{
		Arch:       runtime.GOARCH,
		Layers:     [][]byte{layer},
		Entrypoint: []string{"/bin/cat"},
		Cmd:        []string{"/etc/ready.txt", "/proc/self/fd/0"},
	})

	rs := startControlTestSandbox(t, Config{
		Name:            "ctrl-ufwd",
		OCIImage:        "ufwd:latest",
		RegistryBaseURL: regURL,
		NetworkMode:     NetModeNone,
		UnixForwards: []UnixForward{{
			GuestPath:  "/run/host-services/ssh-auth.sock",
			HostSocket: hostSock,
			UID:        1000,
			GID:        2000,
			Mode:       0o600,
		}},
	})
	rs.stdout.waitForSubstring(t, "uf-ready\n", 15*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Verify net.unix_forward capability is advertised even with -net=none.
	var ping control.PingResponse
	if err := rs.client.Call(ctx, control.MethodPing, nil, &ping); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if !slices.Contains(ping.Capabilities, control.CapUnixForward) {
		t.Fatalf("ping capabilities = %v, want %s", ping.Capabilities, control.CapUnixForward)
	}

	runGuestClient := func(guestSock, msg string) string {
		t.Helper()
		st, err := rs.client.OpenStream(ctx, control.MethodExecStart, control.ExecStartRequest{
			Argv: []string{"/bin/uclient", guestSock, msg},
			Env:  []string{"GODEBUG=asyncpreemptoff=1", "GOMAXPROCS=2"},
		})
		if err != nil {
			t.Fatalf("exec uclient open: %v", err)
		}
		defer st.Close()
		if err := st.WaitResponse(ctx, nil); err != nil {
			t.Fatalf("exec uclient wait: %v", err)
		}
		out, rErr := io.ReadAll(st.ChannelReader(ctx, control.ChannelStdout))
		errOut, _ := io.ReadAll(st.ChannelReader(ctx, control.ChannelStderr))
		ev, eErr := st.RecvEvent(ctx)
		if rErr != nil || eErr != nil || ev.Type != "exec.exit" {
			t.Fatalf("exec uclient: out=%q stderr=%q rErr=%v eErr=%v", out, errOut, rErr, eErr)
		}
		var exitEv control.ExecExitEvent
		if err := json.Unmarshal(ev.Data, &exitEv); err != nil || exitEv.ExitCode != 0 {
			t.Fatalf("exec uclient exit = (%+v, %v), stdout=%q stderr=%q", exitEv, err, out, errOut)
		}
		return string(out)
	}

	// 1. Boot-time Unix forward with uid/gid/mode.
	bootOut := runGuestClient("/run/host-services/ssh-auth.sock", "boot-ssh-ping")
	if !strings.Contains(bootOut, "STAT mode=0600 uid=1000 gid=2000 type=true") {
		t.Fatalf("boot socket stat mismatch: %q", bootOut)
	}
	if !strings.Contains(bootOut, "REPLY host-agent:boot-ssh-ping") {
		t.Fatalf("boot socket reply mismatch: %q", bootOut)
	}

	// 2. Runtime control RPC forward (net.unix_forward + net.unix_accept).
	fwdCtx, fwdCancel := context.WithCancel(ctx)
	fwdStream, err := rs.client.OpenStream(fwdCtx, control.MethodUnixForward, control.UnixForwardRequest{
		GuestPath: "/tmp/runtime-agent.sock",
		UID:       500,
		GID:       501,
		Mode:      0o660,
	})
	if err != nil {
		t.Fatalf("net.unix_forward open: %v", err)
	}
	var fwdResp control.UnixForwardResponse
	if err := fwdStream.WaitResponse(fwdCtx, &fwdResp); err != nil {
		t.Fatalf("net.unix_forward wait: %v", err)
	}
	if fwdResp.GuestPath != "/tmp/runtime-agent.sock" {
		t.Fatalf("fwdResp.GuestPath = %q", fwdResp.GuestPath)
	}

	fwdDone := make(chan struct{})
	go func() {
		defer close(fwdDone)
		for {
			ev, err := fwdStream.RecvEvent(fwdCtx)
			if err != nil {
				return
			}
			if ev.Type != "unix.accept" {
				continue
			}
			var acc control.UnixAcceptEvent
			if json.Unmarshal(ev.Data, &acc) != nil {
				continue
			}
			go func(connID uint64) {
				hc, err := net.Dial("unix", hostSock)
				if err != nil {
					_ = fwdStream.SendEvent(fwdCtx, "unix.reject", control.UnixRejectEvent{ConnID: connID, Error: err.Error()})
					return
				}
				defer hc.Close()
				ds, err := rs.client.OpenStream(fwdCtx, control.MethodUnixAccept, control.UnixAcceptRequest{ConnID: connID})
				if err != nil {
					return
				}
				defer ds.Close()
				if err := ds.WaitResponse(fwdCtx, nil); err != nil {
					return
				}
				doneC := make(chan struct{})
				go func() {
					defer close(doneC)
					w := ds.ChannelWriter(fwdCtx, control.ChannelGeneric, false)
					_, _ = io.Copy(w, hc)
					_ = w.Close()
				}()
				_, _ = io.Copy(hc, ds.ChannelReader(fwdCtx, control.ChannelGeneric))
				if uc, ok := hc.(*net.UnixConn); ok {
					_ = uc.CloseWrite()
				}
				<-doneC
			}(acc.ConnID)
		}
	}()

	rtOut := runGuestClient("/tmp/runtime-agent.sock", "runtime-ssh-ping")
	if !strings.Contains(rtOut, "STAT mode=0660 uid=500 gid=501 type=true") {
		t.Fatalf("runtime socket stat mismatch: %q", rtOut)
	}
	if !strings.Contains(rtOut, "REPLY host-agent:runtime-ssh-ping") {
		t.Fatalf("runtime socket reply mismatch: %q", rtOut)
	}

	// 3. Large transfer (>256 KiB) exercises ErrWouldBlock partial writes.
	const largeSize = 256 * 1024
	wantLarge := "host-agent:" + strings.Repeat("0123456789abcdef", largeSize/16)
	wantSum := sha256.Sum256([]byte(wantLarge))
	largeOut := runGuestClient("/tmp/runtime-agent.sock", "repeat:262144")
	wantMarker := "LARGE len=262155 sha256=" + hex.EncodeToString(wantSum[:])
	if !strings.Contains(largeOut, wantMarker) {
		t.Fatalf("large transfer output = %q, want %q", largeOut, wantMarker)
	}

	// 4. Lifecycle pause/unpause must not deadlock while net.unix_forward is active.
	pauseCtx, pauseCancel := context.WithTimeout(ctx, 5*time.Second)
	defer pauseCancel()
	quiesceFalse := false
	if err := rs.client.Call(pauseCtx, control.MethodPause, control.PauseRequest{QuiesceNet: &quiesceFalse}, nil); err != nil {
		t.Fatalf("pause with active unix forward: %v", err)
	}
	if err := rs.client.Call(pauseCtx, control.MethodUnpause, nil, nil); err != nil {
		t.Fatalf("unpause with active unix forward: %v", err)
	}

	// 5. replace=true must refuse to unlink a non-socket regular file, and
	// replace=false must fail with ALREADY_EXISTS on an existing path.
	for _, tc := range []struct {
		name    string
		req     control.UnixForwardRequest
		wantErr control.ErrorCode
	}{
		{
			name:    "existing_regular_file_replace_false",
			req:     control.UnixForwardRequest{GuestPath: "/etc/ready.txt", Replace: false},
			wantErr: control.CodeAlreadyExists,
		},
		{
			name:    "existing_regular_file_replace_true_refused",
			req:     control.UnixForwardRequest{GuestPath: "/etc/ready.txt", Replace: true},
			wantErr: control.CodeAlreadyExists,
		},
	} {
		st, err := rs.client.OpenStream(ctx, control.MethodUnixForward, tc.req)
		if err != nil {
			t.Fatalf("%s open: %v", tc.name, err)
		}
		err = st.WaitResponse(ctx, nil)
		st.Close()
		var pe *control.ProtoError
		if !errors.As(err, &pe) || pe.Code != tc.wantErr {
			t.Fatalf("%s err = %v, want ProtoError(%s)", tc.name, err, tc.wantErr)
		}
	}
	var readyStat control.FSStatResponse
	if err := rs.client.Call(ctx, control.MethodFSStat, control.FSStatRequest{Path: "/etc/ready.txt"}, &readyStat); err != nil || !readyStat.Exists {
		t.Fatalf("/etc/ready.txt stat after refused replace = (%+v, %v), want exists=true", readyStat, err)
	}

	// 6. Second control client cannot hijack or reject another client's pending conn_id.
	otherClient, err := control.Dial(ctx, control.DialOptions{
		Endpoint:   rs.ep.Address,
		Token:      rs.ep.Token,
		ClientName: "other-client",
	})
	if err != nil {
		t.Fatalf("dial second control client: %v", err)
	}
	defer otherClient.Close()

	isoStream, err := rs.client.OpenStream(ctx, control.MethodUnixForward, control.UnixForwardRequest{
		GuestPath: "/tmp/iso-agent.sock",
	})
	if err != nil {
		t.Fatalf("open iso unix_forward: %v", err)
	}
	if err := isoStream.WaitResponse(ctx, nil); err != nil {
		t.Fatalf("wait iso unix_forward: %v", err)
	}
	// Open a dummy forward on otherClient so it can attempt a cross-client unix.reject.
	otherFwd, err := otherClient.OpenStream(ctx, control.MethodUnixForward, control.UnixForwardRequest{
		GuestPath: "/tmp/other-agent.sock",
	})
	if err != nil {
		t.Fatalf("open other unix_forward: %v", err)
	}
	if err := otherFwd.WaitResponse(ctx, nil); err != nil {
		t.Fatalf("wait other unix_forward: %v", err)
	}
	guestDone := make(chan string, 1)
	go func() {
		guestDone <- runGuestClient("/tmp/iso-agent.sock", "owner-only")
	}()
	accEv, err := isoStream.RecvEvent(ctx)
	if err != nil || accEv.Type != "unix.accept" {
		t.Fatalf("iso RecvEvent = (%+v, %v)", accEv, err)
	}
	var acc control.UnixAcceptEvent
	if err := json.Unmarshal(accEv.Data, &acc); err != nil || acc.ConnID == 0 {
		t.Fatalf("unmarshal iso accept: %v", err)
	}
	// Other client attempts to claim connID -> must get NOT_FOUND without removing it.
	hijackSt, err := otherClient.OpenStream(ctx, control.MethodUnixAccept, control.UnixAcceptRequest{ConnID: acc.ConnID})
	if err != nil {
		t.Fatalf("otherClient OpenStream unix_accept: %v", err)
	}
	hijackErr := hijackSt.WaitResponse(ctx, nil)
	hijackSt.Close()
	var hijackPE *control.ProtoError
	if !errors.As(hijackErr, &hijackPE) || hijackPE.Code != control.CodeNotFound {
		t.Fatalf("cross-client unix_accept err = %v, want NOT_FOUND", hijackErr)
	}
	// Other client attempts to reject connID on its own forward -> must be ignored.
	_ = otherFwd.SendEvent(ctx, "unix.reject", control.UnixRejectEvent{ConnID: acc.ConnID, Error: "spoof"})
	time.Sleep(50 * time.Millisecond)

	// Legitimate owner claims and completes the connection.
	hc, err := net.Dial("unix", hostSock)
	if err != nil {
		t.Fatalf("dial hostSock: %v", err)
	}
	ds, err := rs.client.OpenStream(ctx, control.MethodUnixAccept, control.UnixAcceptRequest{ConnID: acc.ConnID})
	if err != nil {
		t.Fatalf("owner OpenStream unix_accept: %v", err)
	}
	if err := ds.WaitResponse(ctx, nil); err != nil {
		t.Fatalf("owner unix_accept wait: %v", err)
	}
	ownerDone := make(chan struct{})
	go func() {
		defer close(ownerDone)
		w := ds.ChannelWriter(ctx, control.ChannelGeneric, false)
		_, _ = io.Copy(w, hc)
		_ = w.Close()
	}()
	_, _ = io.Copy(hc, ds.ChannelReader(ctx, control.ChannelGeneric))
	if uc, ok := hc.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	<-ownerDone
	ds.Close()
	_ = hc.Close()
	if isoOut := <-guestDone; !strings.Contains(isoOut, "REPLY host-agent:owner-only") {
		t.Fatalf("owner-only guest reply = %q", isoOut)
	}
	otherFwd.Cancel(nil)
	isoStream.Cancel(nil)

	// 7. Canceling the control stream must unlink /tmp/runtime-agent.sock.
	fwdCancel()
	fwdStream.Cancel(nil)
	<-fwdDone
	deadline := time.Now().Add(5 * time.Second)
	for {
		var statResp control.FSStatResponse
		if err := rs.client.Call(ctx, control.MethodFSStat, control.FSStatRequest{Path: "/tmp/runtime-agent.sock"}, &statResp); err == nil && !statResp.Exists {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("/tmp/runtime-agent.sock still exists after canceling net.unix_forward stream")
		}
		time.Sleep(25 * time.Millisecond)
	}
}
