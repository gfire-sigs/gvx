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
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

func init() {
	register(command{
		name:    "exec",
		summary: "Execute a command inside a running sandbox (Docker style: stdin closed unless -i).",
		usage: []string{
			"rungv exec -S <socket>|-n <name> [-i] [-t] [-d] [-e KEY=VAL] [-w DIR] [-u USER] [--] COMMAND [ARG...]",
		},
		run: execSubcommand,
	})
}

func execSubcommand(ctx context.Context, args []string, streams cliIO) int {
	const cmdName = "exec"
	fs := flag.NewFlagSet("rungv exec", flag.ContinueOnError)
	fs.SetOutput(streams.stderr)

	target := addControlFlags(fs, 0)
	var interactive, tty, it, detach, privileged bool
	var workDir, user, detachKeys, pidFile string
	var envFlags, envFileFlags listFlag

	registerAlias([]string{"i", "interactive"}, func(n string) {
		fs.BoolVar(&interactive, n, false, "Keep STDIN open and forward host stdin to the guest process")
	})
	registerAlias([]string{"t", "tty"}, func(n string) {
		fs.BoolVar(&tty, n, false, "Allocate a pseudo-TTY for the guest process")
	})
	fs.BoolVar(&it, "it", false, "Shorthand for -i -t")
	registerAlias([]string{"d", "detach"}, func(n string) {
		fs.BoolVar(&detach, n, false, "Run the command in the background and print its guest PID")
	})
	registerAlias([]string{"e", "env"}, func(n string) {
		fs.Var(&envFlags, n, "Set environment variable: KEY=VALUE or KEY from host (repeatable)")
	})
	fs.Var(&envFileFlags, "env-file", "Read environment variables from a file (repeatable)")
	registerAlias([]string{"w", "workdir"}, func(n string) {
		fs.StringVar(&workDir, n, "", "Working directory inside the sandbox")
	})
	registerAlias([]string{"u", "user"}, func(n string) {
		fs.StringVar(&user, n, "", "Guest user[:group] by name or numeric ID")
	})
	fs.BoolVar(&privileged, "privileged", true, "Pass --privileged=false to drop root capabilities")
	fs.StringVar(&detachKeys, "detach-keys", "ctrl-p,ctrl-q", "Key sequence for detaching a TTY session (empty disables)")
	fs.StringVar(&pidFile, "pid-file", "", "Write the spawned guest PID to a host file")

	if err := fs.Parse(normalizeRunArgs(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if it {
		interactive = true
		tty = true
	}
	if detach && (interactive || tty) {
		return controlUsageError(streams.stderr, cmdName, "-d/--detach cannot be combined with -i or -t")
	}

	guestArgv := fs.Args()
	if len(guestArgv) > 0 && guestArgv[0] == "--" {
		guestArgv = guestArgv[1:]
	}
	if len(guestArgv) == 0 {
		return controlUsageError(streams.stderr, cmdName, "specify a command to execute")
	}

	var detachSeq []byte
	if tty && interactive && strings.TrimSpace(detachKeys) != "" {
		var err error
		detachSeq, err = parseDetachKeys(detachKeys)
		if err != nil {
			return controlUsageError(streams.stderr, cmdName, "--detach-keys: %v", err)
		}
	}

	envv, err := buildExecEnv(envFileFlags, envFlags)
	if err != nil {
		return controlUsageError(streams.stderr, cmdName, "%v", err)
	}

	var rows, cols uint16
	if tty {
		if r, c, ok := gvx.HostTerminalSize(streams.stdin, streams.stdout); ok {
			rows, cols = r, c
		} else {
			rows, cols = 24, 80
		}
	}

	var privPtr *bool
	if flagVisited(fs, "privileged") {
		p := privileged
		privPtr = &p
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(streams.stderr, cmdName, err)
	}
	defer client.Close()

	stream, err := client.OpenStream(ctx, control.MethodExecStart, control.ExecStartRequest{
		Argv:       guestArgv,
		Env:        envv,
		WorkDir:    strings.TrimSpace(workDir),
		User:       strings.TrimSpace(user),
		Stdin:      interactive,
		TTY:        tty,
		Rows:       rows,
		Cols:       cols,
		Detach:     detach,
		Privileged: privPtr,
	})
	if err != nil {
		return controlFail(streams.stderr, cmdName, err)
	}
	defer stream.Close()

	var startResp control.ExecStartResponse
	if err := stream.WaitResponse(ctx, &startResp); err != nil {
		return controlFail(streams.stderr, cmdName, err)
	}
	if pf := strings.TrimSpace(pidFile); pf != "" {
		if err := os.WriteFile(pf, []byte(strconv.Itoa(int(startResp.PID))+"\n"), 0o600); err != nil {
			return controlFail(streams.stderr, cmdName, fmt.Errorf("write --pid-file: %w", err))
		}
	}
	if detach {
		_, _ = fmt.Fprintln(streams.stdout, startResp.PID)
		return 0
	}

	if tty && interactive && gvx.IsHostTerminal(streams.stdin) {
		if restore, ok := gvx.EnterHostRawMode(streams.stdin, streams.stdout); ok {
			defer restore()
		}
	}

	execCtx, execCancel := context.WithCancel(ctx)
	defer execCancel()

	if tty {
		stopWinch := gvx.WatchHostWinch(execCtx, streams.stdin, streams.stdout, func(r, c uint16) {
			_ = stream.SendEvent(execCtx, "exec.resize", control.ExecResizeEvent{Rows: r, Cols: c})
		})
		defer stopWinch()
	}

	// Pump guest stdout and stderr concurrently.
	var outWG sync.WaitGroup
	outWG.Add(1)
	go func() {
		defer outWG.Done()
		if streams.stdout != nil {
			_, _ = io.Copy(streams.stdout, stream.ChannelReader(execCtx, control.ChannelStdout))
		}
	}()
	if !tty {
		outWG.Add(1)
		go func() {
			defer outWG.Done()
			if streams.stderr != nil {
				_, _ = io.Copy(streams.stderr, stream.ChannelReader(execCtx, control.ChannelStderr))
			}
		}()
	}

	// Forward stdin only when -i is requested (Docker semantics).
	detachedCh := make(chan struct{})
	if interactive {
		go func() {
			w := stream.ChannelWriter(execCtx, control.ChannelStdin, false)
			defer func() { _ = w.Close() }()
			if streams.stdin == nil {
				return
			}
			if len(detachSeq) > 0 {
				if copyWithDetach(w, streams.stdin, detachSeq) {
					close(detachedCh)
				}
				return
			}
			_, _ = io.Copy(w, streams.stdin)
		}()
	}

	type exitResult struct {
		ev  control.ExecExitEvent
		err error
	}
	exitCh := make(chan exitResult, 1)
	go func() {
		for {
			ev, err := stream.RecvEvent(execCtx)
			if err != nil {
				exitCh <- exitResult{err: err}
				return
			}
			if ev.Type != "exec.exit" {
				continue
			}
			var exitEv control.ExecExitEvent
			if err := json.Unmarshal(ev.Data, &exitEv); err != nil {
				exitCh <- exitResult{err: err}
				return
			}
			exitCh <- exitResult{ev: exitEv}
			return
		}
	}()

	select {
	case <-detachedCh:
		execCancel()
		stream.Close()
		outWG.Wait()
		return 0
	case res := <-exitCh:
		outWG.Wait()
		if res.err != nil {
			return controlFail(streams.stderr, cmdName, res.err)
		}
		return res.ev.ExitCode
	case <-ctx.Done():
		sigCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = stream.SendEvent(sigCtx, "exec.signal", control.ExecSignalEvent{Signal: "SIGINT"})
		cancel()
		// Wait briefly for the guest process to exit cleanly after receiving the signal.
		select {
		case res := <-exitCh:
			execCancel()
			stream.Close()
			outWG.Wait()
			if res.err == nil {
				return res.ev.ExitCode
			}
		case <-time.After(150 * time.Millisecond):
			execCancel()
			stream.Close()
			outWG.Wait()
		}
		return 130
	}
}

func buildExecEnv(envFiles, envFlags []string) ([]string, error) {
	var envv []string
	for _, path := range envFiles {
		entries, err := readEnvFile(path)
		if err != nil {
			return nil, fmt.Errorf("--env-file %s: %w", path, err)
		}
		envv = append(envv, entries...)
	}
	for _, entry := range envFlags {
		kv, ok, err := resolveEnvEntry(entry, os.LookupEnv)
		if err != nil {
			return nil, fmt.Errorf("-e: %w", err)
		}
		if ok {
			envv = append(envv, kv)
		}
	}
	return envv, nil
}

// parseDetachKeys parses a Docker-style key sequence such as "ctrl-p,ctrl-q".
func parseDetachKeys(spec string) ([]byte, error) {
	parts := strings.Split(spec, ",")
	seq := make([]byte, 0, len(parts))
	for _, raw := range parts {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "ctrl-") && len(lower) == len("ctrl-")+1 {
			ch := lower[len(lower)-1]
			switch {
			case ch >= 'a' && ch <= 'z':
				seq = append(seq, ch-'a'+1)
			case ch == '@':
				seq = append(seq, 0x00)
			case ch == '[':
				seq = append(seq, 0x1b)
			case ch == '\\':
				seq = append(seq, 0x1c)
			case ch == ']':
				seq = append(seq, 0x1d)
			case ch == '^':
				seq = append(seq, 0x1e)
			case ch == '_':
				seq = append(seq, 0x1f)
			default:
				return nil, fmt.Errorf("unsupported detach key %q", raw)
			}
			continue
		}
		if len(trimmed) == 1 {
			seq = append(seq, trimmed[0])
			continue
		}
		return nil, fmt.Errorf("unsupported detach key %q", raw)
	}
	return seq, nil
}

// copyWithDetach forwards r to w and returns true if detachSeq is observed.
func copyWithDetach(w io.Writer, r io.Reader, detachSeq []byte) bool {
	// Precompute KMP longest proper prefix-suffix table for exact partial-match rollback.
	lps := make([]int, len(detachSeq))
	for i, k := 1, 0; i < len(detachSeq); {
		if detachSeq[i] == detachSeq[k] {
			k++
			lps[i] = k
			i++
		} else if k > 0 {
			k = lps[k-1]
		} else {
			lps[i] = 0
			i++
		}
	}
	buf := make([]byte, 4096)
	matched := 0
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out := make([]byte, 0, n+len(detachSeq))
			for _, b := range buf[:n] {
				for matched > 0 && b != detachSeq[matched] {
					nextMatched := lps[matched-1]
					out = append(out, detachSeq[:matched-nextMatched]...)
					matched = nextMatched
				}
				if b == detachSeq[matched] {
					matched++
					if matched == len(detachSeq) {
						if len(out) > 0 {
							_, _ = w.Write(out)
						}
						return true
					}
					continue
				}
				out = append(out, b)
			}
			if len(out) > 0 {
				if _, wErr := w.Write(out); wErr != nil {
					return false
				}
			}
		}
		if err != nil {
			if matched > 0 {
				_, _ = w.Write(detachSeq[:matched])
			}
			return false
		}
	}
}
