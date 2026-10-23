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
	"errors"
	"flag"
	"fmt"
	"io"

	"z.gfire.dev/gvx/pkg/gvx"
)

func init() {
	register(command{
		name:    "stub",
		summary: "Start the systrap stub, print its handshake data, and stop it.\nExit code 1 and the engine error mean systrap cannot run on this host.",
		usage:   []string{"rungv stub"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return stubSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
}

// stubSubcommand spawns the systrap stub, completes the handshake, and prints
// what the stub reported. It exits with 1 and the engine error when the host
// has no usable systrap engine.
func stubSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rungv stub", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "rungv stub: unexpected argument %q\n", fs.Arg(0))
		return 2
	}

	info, err := gvx.ProbeStub(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv stub: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "systrap stub ok\n"+
		"architecture: %s\n"+
		"host page size: %d\n"+
		"stub pid: %d\n"+
		"protocol version: %d\n"+
		"syscall round trip: %s\n",
		info.Arch, info.HostPageSize, info.PID, info.ProtocolVersion, info.RoundTrip)
	if info.UserMax != 0 {
		_, _ = fmt.Fprintf(stdout, "guest address range: %#x-%#x\n", info.UserMin, info.UserMax)
	}
	return 0
}
