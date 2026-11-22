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
	"strings"

	"z.gfire.dev/gvx/pkg/gvx/control"
)

func init() {
	register(command{
		name:    "checkpoint",
		aliases: []string{"snapshot"},
		summary: "Checkpoint a running sandbox over its control socket (alias: snapshot).",
		usage: []string{
			"rungv checkpoint -S <socket>|-n <name> [-checkpoint-dir=<dir>|-o <dir|file.tar|->] [-leave-running] [-z] [--force]",
		},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return checkpointSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
}

// checkpointArgs holds the parsed flags of `rungv checkpoint`.
type checkpointArgs struct {
	target        *controlTargetFlags
	controlSocket string
	checkpointDir string
	output        string
	leaveRunning  bool
	compress      bool
	force         bool
}

func parseCheckpointArgs(args []string, stderr io.Writer) (checkpointArgs, int, bool) {
	fs := flag.NewFlagSet("rungv checkpoint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	usageError := func(format string, a ...any) (checkpointArgs, int, bool) {
		_, _ = fmt.Fprintf(stderr, "rungv checkpoint: "+format+"\n", a...)
		return checkpointArgs{}, 2, true
	}

	target := addControlFlags(fs, 0)
	var checkpointDir, output string
	var leaveRunning, compress, force bool
	fs.StringVar(&checkpointDir, "checkpoint-dir", "", "Checkpoint bundle directory (validated against pre-opened -checkpoint-dir)")
	registerAlias([]string{"o", "output"}, func(n string) {
		fs.StringVar(&output, n, "", "Stream checkpoint bundle to host directory, .tar archive, or '-' stdout")
	})
	fs.BoolVar(&leaveRunning, "leave-running", false, "Keep the sandbox running after the checkpoint completes")
	registerAlias([]string{"z", "compress"}, func(n string) {
		fs.BoolVar(&compress, n, false, "Compress streamed checkpoint frames with zstd")
	})
	fs.BoolVar(&force, "force", false, "Force checkpoint even while exec sessions are active")

	if err := fs.Parse(normalizeCommandArgs(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return checkpointArgs{}, 0, true
		}
		return checkpointArgs{}, 2, true
	}
	if fs.NArg() > 0 {
		return usageError("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	sock, err := target.resolveEndpoint("")
	if err != nil {
		return usageError("%v", err)
	}
	ckptDir := strings.TrimSpace(checkpointDir)
	outSpec := strings.TrimSpace(output)
	if ckptDir != "" && outSpec != "" {
		return usageError("-checkpoint-dir and -o/--output are mutually exclusive")
	}
	if compress && outSpec == "" {
		return usageError("-z/--compress requires -o/--output")
	}
	return checkpointArgs{
		target:        target,
		controlSocket: sock,
		checkpointDir: ckptDir,
		output:        outSpec,
		leaveRunning:  leaveRunning,
		compress:      compress,
		force:         force,
	}, 0, false
}

func isV2HandshakeWireError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "read control hello response") ||
		strings.Contains(msg, "unexpected control hello frame") ||
		strings.Contains(msg, "decode control hello response")
}

func checkpointSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	ca, exitCode, done := parseCheckpointArgs(args, stderr)
	if done {
		return exitCode
	}

	if ca.output != "" {
		return checkpointStreamCLI(ctx, ca, stdout, stderr)
	}

	reqDir := ca.checkpointDir
	if reqDir != "" {
		if abs, err := filepath.Abs(reqDir); err == nil {
			reqDir = abs
		}
	}

	client, err := ca.target.dial(ctx, "")
	if err == nil {
		defer client.Close()
		callCtx, cancel := ca.target.callContext(ctx)
		defer cancel()
		err = client.Call(callCtx, control.MethodCheckpoint, control.CheckpointRequest{
			Dir:          reqDir,
			LeaveRunning: ca.leaveRunning,
			Force:        ca.force,
		}, nil)
		if err != nil {
			return controlFail(stderr, "checkpoint", err)
		}
		return 0
	}
	// Only fall back to legacy v1 JSON checkpoint when the peer rejected the v2
	// wire handshake (not on local token/connect errors or explicit ProtoError).
	var pe *control.ProtoError
	if errors.As(err, &pe) || ca.force || !isV2HandshakeWireError(err) {
		return controlFail(stderr, "checkpoint", err)
	}
	return checkpointLegacyV1(ctx, ca, reqDir, stderr)
}

func checkpointStreamCLI(ctx context.Context, ca checkpointArgs, stdout, stderr io.Writer) int {
	client, err := ca.target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, "checkpoint", err)
	}
	defer client.Close()

	callCtx, cancel := ca.target.callContext(ctx)
	defer cancel()

	stream, err := client.OpenStream(callCtx, control.MethodCheckpointStream, control.CheckpointStreamRequest{
		LeaveRunning: ca.leaveRunning,
		Force:        ca.force,
		Compress:     ca.compress,
	})
	if err != nil {
		return controlFail(stderr, "checkpoint", err)
	}
	defer stream.Close()

	var resp control.CheckpointStreamResponse
	if err := stream.WaitResponse(callCtx, &resp); err != nil {
		return controlFail(stderr, "checkpoint", err)
	}

	tarReader := stream.ChannelReader(callCtx, control.ChannelGeneric)
	if ca.output == "-" {
		if _, err := io.Copy(stdout, tarReader); err != nil {
			return controlFail(stderr, "checkpoint", err)
		}
		return 0
	}
	if strings.HasSuffix(strings.ToLower(ca.output), ".tar") {
		f, err := os.OpenFile(ca.output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return controlFail(stderr, "checkpoint", err)
		}
		_, copyErr := io.Copy(f, tarReader)
		closeErr := f.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return controlFail(stderr, "checkpoint", err)
		}
		return 0
	}
	if err := extractTarToHostDir(tarReader, ca.output, hostExtractOptions{}); err != nil {
		return controlFail(stderr, "checkpoint", err)
	}
	return 0
}

func checkpointLegacyV1(ctx context.Context, ca checkpointArgs, reqDir string, stderr io.Writer) int {
	callCtx, cancel := ca.target.callContext(ctx)
	defer cancel()

	network, address, err := control.ParseEndpoint(ca.controlSocket)
	if err != nil {
		return controlFail(stderr, "checkpoint", err)
	}
	token := ca.target.resolveToken()
	if token == "" {
		token, err = control.ReadToken(network, address, strings.TrimSpace(ca.target.tokenFile))
		if err != nil {
			return controlFail(stderr, "checkpoint", err)
		}
	}

	var d net.Dialer
	conn, err := d.DialContext(callCtx, network, address)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv checkpoint: connect control socket: %v\n", err)
		return 1
	}
	defer func() {
		_ = conn.Close()
	}()
	if dl, ok := callCtx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(callCtx, func() { _ = conn.Close() })
	defer stop()

	req := control.LegacyCheckpointRequest{
		Dir:          reqDir,
		LeaveRunning: ca.leaveRunning,
		Token:        token,
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv checkpoint: send request: %v\n", err)
		return 1
	}

	var resp control.LegacyCheckpointResponse
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
