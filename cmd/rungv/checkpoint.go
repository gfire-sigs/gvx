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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"z.gfire.dev/gvx/pkg/gvx"
)

func init() {
	register(command{
		name:    "checkpoint",
		aliases: []string{"snapshot"},
		summary: "Checkpoint a running sandbox over its control socket (alias: snapshot).",
		usage: []string{
			"rungv checkpoint -control-socket=<path> [-checkpoint-dir=<dir>] [-leave-running]",
		},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return checkpointSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
}

// checkpointControlRequest is the JSON payload sent over the control socket.
type checkpointControlRequest struct {
	Dir          string `json:"dir,omitempty"`
	LeaveRunning bool   `json:"leave_running,omitempty"`
}

// checkpointControlResponse is the JSON reply sent from the control socket.
type checkpointControlResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// checkpointArgs holds the parsed flags of `rungv checkpoint`.
type checkpointArgs struct {
	controlSocket string
	checkpointDir string
	leaveRunning  bool
}

func parseCheckpointArgs(args []string, stderr io.Writer) (checkpointArgs, int, bool) {
	fs := flag.NewFlagSet("rungv checkpoint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	usageError := func(format string, a ...any) (checkpointArgs, int, bool) {
		_, _ = fmt.Fprintf(stderr, "rungv checkpoint: "+format+"\n", a...)
		return checkpointArgs{}, 2, true
	}

	var controlSocket, checkpointDir string
	fs.StringVar(&controlSocket, "control-socket", "", "Control socket path or loopback address")
	fs.StringVar(&checkpointDir, "checkpoint-dir", "", "Checkpoint bundle directory (validated against pre-opened -checkpoint-dir)")
	leaveRunningFlag := fs.Bool("leave-running", false, "Keep the sandbox running after the checkpoint completes")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return checkpointArgs{}, 0, true
		}
		return checkpointArgs{}, 2, true
	}
	if fs.NArg() > 0 {
		return usageError("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	sock := strings.TrimSpace(controlSocket)
	if sock == "" {
		return usageError("specify -control-socket=<path>")
	}
	return checkpointArgs{
		controlSocket: sock,
		checkpointDir: strings.TrimSpace(checkpointDir),
		leaveRunning:  *leaveRunningFlag,
	}, 0, false
}

func checkpointSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	ca, exitCode, done := parseCheckpointArgs(args, stderr)
	if done {
		return exitCode
	}

	reqDir := ca.checkpointDir
	if reqDir != "" {
		if abs, err := filepath.Abs(reqDir); err == nil {
			reqDir = abs
		}
	}

	conn, err := dialCheckpointSocket(ctx, ca.controlSocket)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv checkpoint: connect control socket: %v\n", err)
		return 1
	}
	defer func() {
		_ = conn.Close()
	}()

	req := checkpointControlRequest{
		Dir:          reqDir,
		LeaveRunning: ca.leaveRunning,
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv checkpoint: send request: %v\n", err)
		return 1
	}

	var resp checkpointControlResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv checkpoint: read response: %v\n", err)
		return 1
	}
	if !resp.OK {
		msg := resp.Error
		if msg == "" {
			msg = "checkpoint failed"
		}
		_, _ = fmt.Fprintf(stderr, "rungv checkpoint: %s\n", msg)
		return 1
	}
	return 0
}

// parseCheckpointEndpoint resolves a socket flag into a net.Listen or net.Dial
// network and address pair. It accepts paths for Unix sockets and loopback
// TCP addresses.
func parseCheckpointEndpoint(raw string) (network, address string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", errors.New("checkpoint socket address is empty")
	}
	if strings.HasPrefix(s, "tcp://") {
		addr := strings.TrimPrefix(s, "tcp://")
		if err := validateLoopbackTCPAddr(addr); err != nil {
			return "", "", err
		}
		return "tcp", addr, nil
	}
	if strings.HasPrefix(s, "unix://") {
		return "unix", strings.TrimPrefix(s, "unix://"), nil
	}
	if strings.HasPrefix(s, "unix:") {
		return "unix", strings.TrimPrefix(s, "unix:"), nil
	}
	if !strings.ContainsAny(s, `/\`) {
		if host, port, splitErr := net.SplitHostPort(s); splitErr == nil && port != "" {
			if host == "localhost" {
				return "tcp", s, nil
			}
			if ip := net.ParseIP(host); ip != nil {
				if !ip.IsLoopback() {
					return "", "", fmt.Errorf("checkpoint TCP socket must bind a loopback address, got %q", s)
				}
				return "tcp", s, nil
			}
		}
	}
	return "unix", s, nil
}

func validateLoopbackTCPAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return fmt.Errorf("invalid TCP checkpoint socket address %q", addr)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("checkpoint TCP socket must bind a loopback address, got %q", addr)
	}
	return nil
}

// listenCheckpointSocket binds an owner-only control listener before host
// lockdown applies.
func listenCheckpointSocket(raw string) (net.Listener, func(), error) {
	network, address, err := parseCheckpointEndpoint(raw)
	if err != nil {
		return nil, nil, err
	}
	if network == "tcp" {
		ln, err := net.Listen("tcp", address)
		if err != nil {
			return nil, nil, err
		}
		return ln, func() {}, nil
	}

	parent := filepath.Dir(address)
	if parent != "" && parent != "." {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return nil, nil, fmt.Errorf("create checkpoint socket directory %q: %w", parent, err)
		}
	}
	if fi, err := os.Lstat(address); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, nil, fmt.Errorf("checkpoint socket path %q already exists and is not a socket", address)
		}
		if err := os.Remove(address); err != nil {
			return nil, nil, fmt.Errorf("remove stale checkpoint socket %q: %w", address, err)
		}
	}
	ln, err := net.Listen("unix", address)
	if err != nil {
		return nil, nil, err
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	if err := os.Chmod(address, 0o600); err != nil && runtime.GOOS != "windows" {
		_ = ln.Close()
		_ = os.Remove(address)
		return nil, nil, fmt.Errorf("chmod checkpoint socket %q: %w", address, err)
	}
	cleanup := func() {
		_ = os.Remove(address)
	}
	return ln, cleanup, nil
}

func dialCheckpointSocket(ctx context.Context, raw string) (net.Conn, error) {
	network, address, err := parseCheckpointEndpoint(raw)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// resolveCheckpointDirs normalizes the configured checkpoint directory before
// host lockdown restricts host filesystem calls.
func resolveCheckpointDirs(dir string) (cleanDir, absDir string) {
	trimmed := strings.TrimSpace(dir)
	if trimmed == "" {
		return "", ""
	}
	cleanDir = filepath.Clean(trimmed)
	if abs, err := filepath.Abs(cleanDir); err == nil {
		absDir = filepath.Clean(abs)
	}
	return cleanDir, absDir
}

func validateRequestedCheckpointDir(reqDir, cleanConfDir, absConfDir string) error {
	if cleanConfDir == "" {
		return errors.New("sandbox was started without -checkpoint-dir")
	}
	trimmed := strings.TrimSpace(reqDir)
	if trimmed == "" {
		return nil
	}
	reqClean := filepath.Clean(trimmed)
	if reqClean == cleanConfDir || (absConfDir != "" && reqClean == absConfDir) {
		return nil
	}
	return fmt.Errorf("checkpoint directory %q does not match pre-opened -checkpoint-dir %q", trimmed, cleanConfDir)
}

// startCheckpointControl serves checkpoint control requests from sb in a
// background goroutine until the listener closes. The returned stop function
// closes the listener and waits for any in-flight request to finish writing its
// response.
func startCheckpointControl(ctx context.Context, sb *gvx.Sandbox, ln net.Listener, cleanDir, absDir string) func() {
	if ln == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := sb.AcceptCheckpointConn()
			if err != nil {
				return
			}
			handleCheckpointConn(ctx, sb, conn, cleanDir, absDir)
		}
	}()
	return sync.OnceFunc(func() {
		_ = ln.Close()
		<-done
	})
}

func handleCheckpointConn(ctx context.Context, sb *gvx.Sandbox, conn net.Conn, cleanDir, absDir string) {
	defer func() {
		_ = conn.Close()
	}()
	var req checkpointControlRequest
	if err := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(checkpointControlResponse{
			OK:    false,
			Error: fmt.Sprintf("decode checkpoint request: %v", err),
		})
		return
	}
	if err := validateRequestedCheckpointDir(req.Dir, cleanDir, absDir); err != nil {
		_ = json.NewEncoder(conn).Encode(checkpointControlResponse{
			OK:    false,
			Error: err.Error(),
		})
		return
	}
	if err := sb.Checkpoint(ctx, gvx.CheckpointOptions{LeaveRunning: req.LeaveRunning}); err != nil {
		_ = json.NewEncoder(conn).Encode(checkpointControlResponse{
			OK:    false,
			Error: err.Error(),
		})
		return
	}
	_ = json.NewEncoder(conn).Encode(checkpointControlResponse{OK: true})
}
