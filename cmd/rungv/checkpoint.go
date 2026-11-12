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
	"time"

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
	// Token is the per-run secret of the listener. A loopback TCP listener and
	// a Windows AF_UNIX listener reject a request without it.
	Token string `json:"token,omitempty"`
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
	if network, address, perr := parseCheckpointEndpoint(ca.controlSocket); perr == nil {
		token, tErr := readControlToken(network, address)
		if tErr != nil {
			_, _ = fmt.Fprintf(stderr, "rungv checkpoint: warning: %v\n", tErr)
		}
		req.Token = token
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

// controlEndpoint is a bound control listener with its request token and
// cleanup.
type controlEndpoint struct {
	// Listener accepts control connections.
	Listener net.Listener
	// Token is the per-run secret that each request must carry, or empty when
	// the listener relies on the 0600 mode of a POSIX Unix socket.
	Token string
	// Cleanup removes the socket file and the token file. Call it only before
	// host lockdown, because lockdown forbids file removal.
	Cleanup func()
}

// token returns the request token of ep, or empty when ep is nil.
func (ep *controlEndpoint) token() string {
	if ep == nil {
		return ""
	}
	return ep.Token
}

// listenCheckpointSocket binds an owner-only control listener before host
// lockdown applies. A loopback TCP listener and a Windows AF_UNIX listener
// also get a per-run request token, published in a 0600 token file.
func listenCheckpointSocket(raw string) (*controlEndpoint, error) {
	network, address, err := parseCheckpointEndpoint(raw)
	if err != nil {
		return nil, err
	}

	var token, tokenPath string
	if controlTokenRequired(network) {
		if token, err = newControlToken(); err != nil {
			return nil, err
		}
		if tokenPath, err = controlTokenPath(network, address); err != nil {
			return nil, err
		}
	}
	removeToken := func() {
		if tokenPath != "" {
			_ = os.Remove(tokenPath)
		}
	}

	// Every path writes the token file only after the bind succeeds. A second
	// rungv that fails to bind a live sandbox's address must not replace or
	// remove the token of that sandbox.
	if network == "tcp" {
		ln, err := net.Listen("tcp", address)
		if err != nil {
			return nil, err
		}
		if tokenPath != "" {
			if err := writeControlToken(tokenPath, token); err != nil {
				_ = ln.Close()
				return nil, err
			}
		}
		return &controlEndpoint{Listener: ln, Token: token, Cleanup: removeToken}, nil
	}

	parent := filepath.Dir(address)
	if parent != "" && parent != "." {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return nil, fmt.Errorf("create checkpoint socket directory %q: %w", parent, err)
		}
	}
	if fi, err := os.Lstat(address); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("checkpoint socket path %q already exists and is not a socket", address)
		}
		if err := os.Remove(address); err != nil {
			return nil, fmt.Errorf("remove stale checkpoint socket %q: %w", address, err)
		}
	}
	ln, err := net.Listen("unix", address)
	if err != nil {
		return nil, err
	}
	if tokenPath != "" {
		if err := writeControlToken(tokenPath, token); err != nil {
			_ = ln.Close()
			_ = os.Remove(address)
			return nil, err
		}
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	if err := os.Chmod(address, 0o600); err != nil && runtime.GOOS != "windows" {
		_ = ln.Close()
		_ = os.Remove(address)
		removeToken()
		return nil, fmt.Errorf("chmod checkpoint socket %q: %w", address, err)
	}
	cleanup := func() {
		_ = os.Remove(address)
		removeToken()
	}
	return &controlEndpoint{Listener: ln, Token: token, Cleanup: cleanup}, nil
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

// Control connection time limits. A client has controlRequestTimeout to send
// one request, and the server has controlResponseTimeout to write the reply.
// Neither covers the checkpoint itself.
//
// Tests shorten both limits.
var (
	controlRequestTimeout  = 10 * time.Second
	controlResponseTimeout = 10 * time.Second
)

// checkpointer is the part of gvx.Sandbox that the control server calls.
type checkpointer interface {
	Checkpoint(ctx context.Context, opts gvx.CheckpointOptions) error
}

// controlServer serves one control connection at a time and tracks the
// connections that still wait for a request, so stop can close them.
type controlServer struct {
	cp       checkpointer
	token    string
	cleanDir string
	absDir   string

	mu      sync.Mutex
	closing bool
	reading map[net.Conn]struct{}
}

// startCheckpointControl serves checkpoint control requests from sb in a
// background goroutine until the listener closes. The returned stop function
// closes the listener and every connection that has not sent a request, and
// waits for an in-flight request to finish writing its response.
func startCheckpointControl(ctx context.Context, sb *gvx.Sandbox, ln net.Listener, token, cleanDir, absDir string) func() {
	if ln == nil {
		return func() {}
	}
	return serveCheckpointControl(ctx, sb, sb.AcceptCheckpointConn, ln, token, cleanDir, absDir)
}

func serveCheckpointControl(ctx context.Context, cp checkpointer, accept func() (net.Conn, error), ln net.Listener, token, cleanDir, absDir string) func() {
	srv := &controlServer{
		cp:       cp,
		token:    token,
		cleanDir: cleanDir,
		absDir:   absDir,
		reading:  make(map[net.Conn]struct{}),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := accept()
			if err != nil {
				return
			}
			srv.serve(ctx, conn)
		}
	}()
	return sync.OnceFunc(func() {
		_ = ln.Close()
		srv.closeReading()
		<-done
	})
}

// beginRead registers conn as waiting for a request. It reports false when the
// server is stopping.
func (s *controlServer) beginRead(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	s.reading[conn] = struct{}{}
	return true
}

func (s *controlServer) endRead(conn net.Conn) {
	s.mu.Lock()
	delete(s.reading, conn)
	s.mu.Unlock()
}

// closeReading stops the server from accepting new requests and closes the
// connections that wait for one.
func (s *controlServer) closeReading() {
	s.mu.Lock()
	s.closing = true
	conns := make([]net.Conn, 0, len(s.reading))
	for c := range s.reading {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (s *controlServer) reply(conn net.Conn, resp checkpointControlResponse) {
	_ = conn.SetWriteDeadline(time.Now().Add(controlResponseTimeout))
	_ = json.NewEncoder(conn).Encode(resp)
}

func (s *controlServer) serve(ctx context.Context, conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()
	if !s.beginRead(conn) {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(controlRequestTimeout))
	var req checkpointControlRequest
	decodeErr := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&req)
	s.endRead(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if decodeErr != nil {
		s.reply(conn, checkpointControlResponse{
			OK:    false,
			Error: fmt.Sprintf("decode checkpoint request: %v", decodeErr),
		})
		return
	}
	if !controlTokenMatches(s.token, req.Token) {
		s.reply(conn, checkpointControlResponse{
			OK:    false,
			Error: "unauthorized: the request lacks the control token of this sandbox",
		})
		return
	}
	if err := validateRequestedCheckpointDir(req.Dir, s.cleanDir, s.absDir); err != nil {
		s.reply(conn, checkpointControlResponse{OK: false, Error: err.Error()})
		return
	}
	if err := s.cp.Checkpoint(ctx, gvx.CheckpointOptions{LeaveRunning: req.LeaveRunning}); err != nil {
		s.reply(conn, checkpointControlResponse{OK: false, Error: err.Error()})
		return
	}
	s.reply(conn, checkpointControlResponse{OK: true})
}
