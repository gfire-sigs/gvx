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

// Binary rungv is the standalone CLI runner for gvx on Windows and macOS.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"

	"z.gfire.dev/gvx/pkg/gvx"
)

func workerSubcommand(ctx context.Context, stderr io.Writer) int {
	if err := gvx.ServeProcess(ctx, gvx.WorkerOptions{}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

type runningSandbox interface {
	Run(context.Context) (int, error)
	Close() error
	PlatformName() string
	PublishedPorts() []gvx.PublishedPort
	Limits() gvx.LimitReport
}

func openSandbox(ctx context.Context, cfg gvx.Config) (runningSandbox, error) {
	if runtime.GOOS == "windows" && !cfg.DisableHostLockdown {
		executable, err := os.Executable()
		if err != nil {
			return nil, err
		}
		return gvx.NewProcess(ctx, gvx.WorkerCommand{Executable: executable, Arguments: []string{"worker"}}, cfg)
	}
	return gvx.New(ctx, cfg)
}
