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
	"io"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/control"
)

func init() {
	register(command{
		name:    "pause",
		summary: "Pause all guest tasks in a running sandbox.",
		usage:   []string{"rungv pause -S <socket>|-n <name> [--quiesce-net=true|false]"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return pauseSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
	register(command{
		name:    "unpause",
		summary: "Resume guest tasks in a paused sandbox.",
		usage:   []string{"rungv unpause -S <socket>|-n <name>"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return unpauseSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
}

func pauseSubcommand(ctx context.Context, args []string, _, stderr io.Writer) int {
	fs := newImageFlagSet("pause", stderr)
	target := addControlFlags(fs, 10*time.Second)
	quiesceNet := fs.Bool("quiesce-net", true, "Quiesce host network forwarders while paused")
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		return controlUsageError(stderr, "pause", "unexpected argument %q", fs.Arg(0))
	}
	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, "pause", err)
	}
	defer client.Close()
	callCtx, cancel := target.callContext(ctx)
	defer cancel()
	q := *quiesceNet
	if err := client.Call(callCtx, control.MethodPause, control.PauseRequest{QuiesceNet: &q}, nil); err != nil {
		return controlFail(stderr, "pause", err)
	}
	return 0
}

func unpauseSubcommand(ctx context.Context, args []string, _, stderr io.Writer) int {
	fs := newImageFlagSet("unpause", stderr)
	target := addControlFlags(fs, 10*time.Second)
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		return controlUsageError(stderr, "unpause", "unexpected argument %q", fs.Arg(0))
	}
	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, "unpause", err)
	}
	defer client.Close()
	callCtx, cancel := target.callContext(ctx)
	defer cancel()
	if err := client.Call(callCtx, control.MethodUnpause, nil, nil); err != nil {
		return controlFail(stderr, "unpause", err)
	}
	return 0
}
