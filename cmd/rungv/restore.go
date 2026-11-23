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
			"rungv restore -checkpoint-dir=<dir> [flags]",
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
	controlSocket    string
	controlTokenFile string
}

// parseRestoreArgs converts `rungv restore` arguments into a restoreConfig.
func parseRestoreArgs(args []string, stdin io.Reader, stdout, stderr io.Writer) (rc restoreConfig, exitCode int, done bool) {
	fs := flag.NewFlagSet("rungv restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	usageError := func(format string, a ...any) (restoreConfig, int, bool) {
		_, _ = fmt.Fprintf(stderr, "rungv restore: "+format+"\n", a...)
		return restoreConfig{}, 2, true
	}

	flags := registerSandboxFlags(fs, flagDefaults{})
	var serveFlags listFlag
	var attachBindFlags listFlag
	fs.Var(&serveFlags, "serve", "Reattach a checkpointed rpcfs proxy mount: HOST_PATH:GUEST_PATH[:ro|rw]")
	fs.Var(&attachBindFlags, "attach-bind", "Reattach a checkpointed host bind mount: HOST_PATH:GUEST_PATH[:ro|rw]")
	if err := fs.Parse(normalizeCommandArgs(fs, args)); err != nil {
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

	dir := strings.TrimSpace(flags.checkpointDir)
	if dir == "" {
		return usageError("specify -checkpoint-dir=<path>")
	}

	cfg, autoPlatform, err := flags.buildBaseConfig(fs, stdin, stdout, stderr, true)
	if err != nil {
		return usageError("%v", err)
	}
	for _, spec := range attachBindFlags {
		m, err := parseAttachBindSpec(spec)
		if err != nil {
			return usageError("--attach-bind: %v", err)
		}
		cfg.Mounts = append(cfg.Mounts, m)
	}
	for _, spec := range serveFlags {
		sm, err := gvx.ParseServeMount(spec)
		if err != nil {
			return usageError("--serve: %v", err)
		}
		cfg.ServeMounts = append(cfg.ServeMounts, sm)
	}
	ctrlSock, err := flags.resolveControlSocket()
	if err != nil {
		return usageError("%v", err)
	}
	return restoreConfig{
		dir:              dir,
		cfg:              cfg,
		autoPlatform:     autoPlatform,
		controlSocket:    ctrlSock,
		controlTokenFile: strings.TrimSpace(flags.controlTokenFile),
	}, 0, false
}

func restoreSubcommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	rc, exitCode, done := parseRestoreArgs(args, stdin, stdout, stderr)
	if done {
		return exitCode
	}

	ctrlEp, ok := bindControlSocket(&rc.cfg, rc.controlSocket, rc.controlTokenFile, "rungv restore", stderr)
	if !ok {
		return 1
	}
	var sb *gvx.Sandbox
	if ctrlEp != nil {
		defer func() {
			if sb == nil || !sb.LockdownStatus().Applied {
				ctrlEp.Cleanup()
			}
		}()
	}

	var err error
	sb, err = gvx.Restore(ctx, rc.cfg, gvx.RestoreOptions{Dir: rc.dir})
	if err != nil {
		if rc.cfg.ControlListener != nil {
			_ = rc.cfg.ControlListener.Close()
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
	errOut := stderr
	if rc.cfg.Stderr != nil {
		errOut = rc.cfg.Stderr
	}
	return executeSandboxWithControl(ctx, sb, &rc.cfg, rc.autoPlatform, "rungv restore", errOut)
}

func parseAttachBindSpec(spec string) (gvx.Mount, error) {
	sm, err := gvx.ParseServeMount(spec)
	if err != nil {
		return gvx.Mount{}, fmt.Errorf("invalid bind mount %q (want HOST_PATH:GUEST_PATH[:ro|rw])", spec)
	}
	return gvx.Mount{
		Kind:      gvx.MountBind,
		HostPath:  sm.HostPath,
		GuestPath: sm.GuestPath,
		ReadOnly:  sm.ReadOnly,
	}, nil
}
