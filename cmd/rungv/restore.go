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
	"strings"

	"z.gfire.dev/gvx/pkg/gvx"
)

func init() {
	register(command{
		name:    "restore",
		aliases: []string{"resume"},
		summary: "Restore and run a sandbox from a checkpoint bundle directory (alias: resume).",
		usage: []string{
			"rungv restore -dir=<dir> [flags]",
		},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return restoreSubcommand(ctx, args, streams.stdin, streams.stdout, streams.stderr)
		},
	})
}

// restoreConfig holds the parsed flags of `rungv restore`.
type restoreConfig struct {
	dir              string
	cfg              gvx.Config
	autoPlatform     bool
	checkpointSocket string
}

// parseRestoreArgs converts `rungv restore` arguments into a restoreConfig.
func parseRestoreArgs(args []string, stdin io.Reader, stdout, stderr io.Writer) (rc restoreConfig, exitCode int, done bool) {
	fs := flag.NewFlagSet("rungv restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	usageError := func(format string, a ...any) (restoreConfig, int, bool) {
		_, _ = fmt.Fprintf(stderr, "rungv restore: "+format+"\n", a...)
		return restoreConfig{}, 2, true
	}

	dirFlag := fs.String("dir", "", "Checkpoint bundle directory")
	flags := registerSandboxFlags(fs, flagDefaults{
		shortWForWorkspace: true,
	})
	if err := fs.Parse(expandShortClusters(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return restoreConfig{}, 0, true
		}
		return restoreConfig{}, 2, true
	}
	if flags.detach {
		return usageError("-d is not supported: rungv runs in the foreground and keeps no container after the guest exits")
	}
	if fs.NArg() > 0 {
		return usageError("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	dir := strings.TrimSpace(*dirFlag)
	if dir == "" {
		return usageError("specify -dir=<path>")
	}

	cfg, autoPlatform, err := flags.buildBaseConfig(fs, stdin, stdout, stderr, true)
	if err != nil {
		return usageError("%v", err)
	}
	return restoreConfig{
		dir:              dir,
		cfg:              cfg,
		autoPlatform:     autoPlatform,
		checkpointSocket: strings.TrimSpace(flags.checkpointSocket),
	}, 0, false
}

func restoreSubcommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	rc, exitCode, done := parseRestoreArgs(args, stdin, stdout, stderr)
	if done {
		return exitCode
	}

	cleanCkptDir, absCkptDir := resolveCheckpointDirs(rc.cfg.CheckpointDir)
	cleanupSocket, ok := bindCheckpointSocket(&rc.cfg, rc.checkpointSocket, "rungv restore", stderr)
	if !ok {
		return 1
	}
	if cleanupSocket != nil {
		defer cleanupSocket()
	}

	sb, err := gvx.Restore(ctx, rc.cfg, gvx.RestoreOptions{Dir: rc.dir})
	if err != nil {
		if rc.cfg.CheckpointListener != nil {
			_ = rc.cfg.CheckpointListener.Close()
		}
		_, _ = fmt.Fprintf(stderr, "rungv restore: %v\n", err)
		if errors.Is(err, gvx.ErrInvalidConfig) {
			return 2
		}
		return 1
	}
	defer func() {
		_ = sb.Close()
	}()
	return executeSandboxWithControl(ctx, sb, &rc.cfg, rc.autoPlatform, cleanCkptDir, absCkptDir, "rungv restore", stderr)
}
