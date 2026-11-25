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

package rungvx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

func init() {
	register(command{
		name:    "status",
		summary: "Inspect a running sandbox over its control socket.",
		usage:   []string{"rungvx status -S <socket>|-n <name> [-f|--format table|json|TEMPLATE]"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return statusSubcommand(ctx, "status", args, streams.stdout, streams.stderr)
		},
	})
	register(command{
		name:    "sandbox",
		summary: "Inspect a running sandbox (subcommand: inspect).",
		usage:   []string{"rungvx sandbox inspect -S <socket>|-n <name> [-f|--format table|json|TEMPLATE]"},
		run:     sandboxGroupSubcommand,
	})
	register(command{
		name:    "stats",
		summary: "Display live CPU, memory, network, block I/O, and PID statistics.",
		usage:   []string{"rungvx stats -S <socket>|-n <name> [--no-stream] [--interval 1s] [-f|--format SPEC]"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return statsSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
	register(command{
		name:    "top",
		summary: "Display running processes inside a sandbox.",
		usage:   []string{"rungvx top -S <socket>|-n <name> [-f|--format table|json|TEMPLATE]"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return topSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
	register(command{
		name:    "kill",
		summary: "Send a POSIX signal to a sandbox or a specific guest PID.",
		usage:   []string{"rungvx kill -S <socket>|-n <name> [-s|--signal SIGKILL] [--pid PID] [--all]"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return killSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
	register(command{
		name:    "stop",
		summary: "Gracefully stop a running sandbox with a timeout before SIGKILL.",
		usage:   []string{"rungvx stop -S <socket>|-n <name> [-t|--time 10s] [-s|--signal SIGTERM]"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return stopSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
	register(command{
		name:    "dmesg",
		summary: "Read or follow the guest kernel log ring.",
		usage:   []string{"rungvx dmesg -S <socket>|-n <name> [-f|--follow] [--tail N] [--level N] [--clear]"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return dmesgSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
	register(command{
		name:    "events",
		summary: "Stream real-time lifecycle events from a running sandbox.",
		usage:   []string{"rungvx events -S <socket>|-n <name> [--filter key=val]... [-f|--format json|table]"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return eventsSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
	register(command{
		name:    "ping",
		summary: "Verify control socket liveness and advertised capabilities.",
		usage:   []string{"rungvx ping -S <socket>|-n <name> [--wait DURATION] [-f|--format json|table]"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return pingSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
	register(command{
		name:    "debug",
		summary: "Adjust runtime diagnostics for a sandbox.",
		usage:   []string{"rungvx debug -S <socket>|-n <name> --log-level warning|info|debug"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return debugSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
}

func sandboxGroupSubcommand(ctx context.Context, args []string, streams cliIO) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		w := streams.stdout
		code := 0
		if len(args) == 0 {
			w = streams.stderr
			code = 2
		}
		_, _ = fmt.Fprintln(w, "Usage: rungvx sandbox inspect -S <socket>|-n <name> [-f|--format table|json|TEMPLATE]")
		return code
	}
	if args[0] == "inspect" {
		return statusSubcommand(ctx, "sandbox inspect", args[1:], streams.stdout, streams.stderr)
	}
	return controlUsageError(streams.stderr, "sandbox", "unknown subcommand %q (want inspect)", args[0])
}

func statusSubcommand(ctx context.Context, cmdName string, args []string, stdout, stderr io.Writer) int {
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 10*time.Second)
	var format string
	registerAlias([]string{"f", "format"}, func(n string) {
		fs.StringVar(&format, n, "", "Format output using table (default), json, or a Go template")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		return controlUsageError(stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()
	callCtx, cancel := target.callContext(ctx)
	defer cancel()

	var info control.InspectResponse
	if err := client.Call(callCtx, control.MethodInspect, nil, &info); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	usageErr, writeErr := renderSingleFormat(stdout, format, info, func(w io.Writer) error {
		tw := tabwriter.NewWriter(w, 18, 1, 2, ' ', 0)
		_, _ = fmt.Fprintf(tw, "Sandbox:\t%s\n", info.ID)
		_, _ = fmt.Fprintf(tw, "State:\t%s\n", info.State)
		_, _ = fmt.Fprintf(tw, "Uptime:\t%s\n", formatUptime(time.Duration(info.UptimeNanos)))
		_, _ = fmt.Fprintf(tw, "Platform:\t%s (%s)\n", info.Platform, info.Architecture)
		_, _ = fmt.Fprintf(tw, "Lockdown:\t%v (%s)\n", info.LockdownApplied, info.SyscallIsolation)
		_, _ = fmt.Fprintf(tw, "Network:\t%s (eth0=%s mtu=%d isolate-lan=%v)\n", info.NetworkMode, info.Eth0IP, info.Eth0MTU, info.Resources.IsolateLAN)
		if info.NetworkMode == string(gvx.NetModeNAT) && client.HasFeature(control.FeatureNetQoS) {
			_, _ = fmt.Fprintf(tw, "Network TX:\t%s\n", formatBandwidth(info.Resources.NetTXBPS))
			_, _ = fmt.Fprintf(tw, "Network RX:\t%s\n", formatBandwidth(info.Resources.NetRXBPS))
		}
		_, _ = fmt.Fprintf(tw, "Memory:\t%s / %s\n", humanBytes(info.MemoryUsedBytes), formatLimitBytes(info.Resources.MemoryBytes))
		_, _ = fmt.Fprintf(tw, "CPU:\t%d guest CPUs (quota=%dus period=%dus)\n", info.Resources.GuestCPUs, info.Resources.CPUQuotaUSec, info.Resources.CPUPeriodUSec)
		_, _ = fmt.Fprintf(tw, "PIDs:\t%d (limit=%d)\n", info.PIDCount, info.Resources.PidsLimit)
		_, _ = fmt.Fprintf(tw, "Exec Sessions:\t%d\n", info.ActiveExecSessions)
		_, _ = fmt.Fprintf(tw, "Ports:\t%d\n", len(info.Ports))
		if len(info.DynamicBindAddrs) > 0 {
			_, _ = fmt.Fprintf(tw, "Dynamic Bind:\t%s\n", strings.Join(info.DynamicBindAddrs, ", "))
		}
		if info.AutoPublishAddr != "" {
			_, _ = fmt.Fprintf(tw, "Auto Publish:\t%s\n", info.AutoPublishAddr)
		}
		_, _ = fmt.Fprintf(tw, "Mounts:\t%d\n", len(info.Mounts))
		_, _ = fmt.Fprintf(tw, "Capabilities:\t%s\n", strings.Join(info.Capabilities, ", "))
		return tw.Flush()
	})
	if usageErr != nil {
		return controlUsageError(stderr, cmdName, "%v", usageErr)
	}
	if writeErr != nil {
		return controlFail(stderr, cmdName, writeErr)
	}
	return 0
}

func statsSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "stats"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 0)
	noStream := fs.Bool("no-stream", false, "Print a single stats snapshot and exit")
	interval := fs.Duration("interval", time.Second, "Sampling interval for streaming stats")
	var format string
	registerAlias([]string{"f", "format"}, func(n string) {
		fs.StringVar(&format, n, "", "Format output using table (default), json, or a Go template")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		return controlUsageError(stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()

	tw := tabwriter.NewWriter(stdout, 12, 1, 2, ' ', 0)
	if *noStream {
		callCtx, cancel := target.callContext(ctx)
		defer cancel()
		var sample control.StatsSample
		if err := client.Call(callCtx, control.MethodStats, control.StatsRequest{Stream: false}, &sample); err != nil {
			return controlFail(stderr, cmdName, err)
		}
		return printStatsSample(stdout, tw, stderr, cmdName, format, sample, true)
	}

	stream, err := client.OpenStream(ctx, control.MethodStats, control.StatsRequest{
		Stream:     true,
		IntervalMS: interval.Milliseconds(),
	})
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer stream.Close()

	var first control.StatsSample
	if err := stream.WaitResponse(ctx, &first); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	if code := printStatsSample(stdout, tw, stderr, cmdName, format, first, true); code != 0 {
		return code
	}
	for {
		ev, err := stream.RecvEvent(ctx)
		if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			return 0
		}
		if err != nil {
			return controlFail(stderr, cmdName, err)
		}
		if ev.Type != "stats" {
			continue
		}
		var sample control.StatsSample
		if err := json.Unmarshal(ev.Data, &sample); err != nil {
			continue
		}
		if code := printStatsSample(stdout, tw, stderr, cmdName, format, sample, false); code != 0 {
			return code
		}
	}
}

func printStatsSample(stdout io.Writer, tw *tabwriter.Writer, stderr io.Writer, cmdName, format string, s control.StatsSample, header bool) int {
	spec := strings.TrimSpace(format)
	if spec == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(s); err != nil {
			return controlFail(stderr, cmdName, err)
		}
		return 0
	}
	if spec != "" && spec != "table" {
		usageErr, writeErr := renderSingleFormat(stdout, spec, s, func(io.Writer) error { return nil })
		if usageErr != nil {
			return controlUsageError(stderr, cmdName, "%v", usageErr)
		}
		if writeErr != nil {
			return controlFail(stderr, cmdName, writeErr)
		}
		return 0
	}
	var rx, tx uint64
	for _, n := range s.Network {
		rx += n.RxBytes
		tx += n.TxBytes
	}
	if header {
		_, _ = fmt.Fprintln(tw, "CPU_USER\tCPU_SYS\tMEM_USAGE / LIMIT\tNET_IO\tPIDS")
	}
	limitStr := "unlimited"
	if s.Memory.LimitBytes > 0 {
		limitStr = humanBytes(s.Memory.LimitBytes)
	}
	_, _ = fmt.Fprintf(tw, "%s\t%s\t%s / %s\t%s / %s\t%d\n",
		time.Duration(s.CPU.UserNanos).Truncate(time.Millisecond),
		time.Duration(s.CPU.SystemNanos).Truncate(time.Millisecond),
		humanBytes(s.Memory.TotalBytes),
		limitStr,
		humanBytes(rx),
		humanBytes(tx),
		s.PIDs,
	)
	if err := tw.Flush(); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	return 0
}

func topSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "top"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 10*time.Second)
	var format string
	registerAlias([]string{"f", "format"}, func(n string) {
		fs.StringVar(&format, n, "", "Format output using table (default), json, or a Go template")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		return controlUsageError(stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()
	callCtx, cancel := target.callContext(ctx)
	defer cancel()

	var resp control.ProcListResponse
	if err := client.Call(callCtx, control.MethodProcList, nil, &resp); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	usageErr, writeErr := renderListFormat(stdout, format, resp.Processes, func(w io.Writer) error {
		tw := tabwriter.NewWriter(w, 6, 1, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "PID\tPPID\tUID\tSTATE\tTHR\tCPU\tRSS\tCOMMAND")
		for _, p := range resp.Processes {
			cmd := p.Comm
			if len(p.Cmdline) > 0 {
				cmd = strings.Join(p.Cmdline, " ")
			}
			_, _ = fmt.Fprintf(tw, "%d\t%d\t%d\t%s\t%d\t%s\t%s\t%s\n",
				p.PID, p.PPID, p.UID, p.State, p.Threads,
				time.Duration(p.CPUNanos).Truncate(time.Millisecond),
				humanBytes(p.RSSBytes),
				cmd,
			)
		}
		return tw.Flush()
	})
	if usageErr != nil {
		return controlUsageError(stderr, cmdName, "%v", usageErr)
	}
	if writeErr != nil {
		return controlFail(stderr, cmdName, writeErr)
	}
	return 0
}

func killSubcommand(ctx context.Context, args []string, _, stderr io.Writer) int {
	const cmdName = "kill"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 10*time.Second)
	var sig string
	registerAlias([]string{"s", "signal"}, func(n string) {
		fs.StringVar(&sig, n, "SIGKILL", "Signal name or number (default SIGKILL)")
	})
	pid := fs.Int("pid", 0, "Target guest PID (0 targets PID 1)")
	all := fs.Bool("all", false, "Send the signal to all processes in the sandbox")
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		return controlUsageError(stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}
	if *pid < 0 {
		return controlUsageError(stderr, cmdName, "--pid must be non-negative")
	}
	if *all && *pid > 0 {
		return controlUsageError(stderr, cmdName, "--pid cannot be combined with --all")
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()
	callCtx, cancel := target.callContext(ctx)
	defer cancel()

	if err := client.Call(callCtx, control.MethodProcSignal, control.ProcSignalRequest{
		Signal: strings.TrimSpace(sig),
		PID:    int32(*pid),
		All:    *all,
	}, nil); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	return 0
}

func stopSubcommand(ctx context.Context, args []string, _, stderr io.Writer) int {
	const cmdName = "stop"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 0)
	var sig string
	registerAlias([]string{"s", "signal"}, func(n string) {
		fs.StringVar(&sig, n, "SIGTERM", "Graceful stop signal (default SIGTERM)")
	})
	var grace time.Duration
	registerAlias([]string{"t", "time"}, func(n string) {
		fs.DurationVar(&grace, n, 10*time.Second, "Wait duration before sending SIGKILL")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		return controlUsageError(stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}
	if grace < 0 {
		return controlUsageError(stderr, cmdName, "-t/--time must be non-negative")
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()
	callCtx, cancel := target.callContext(ctx)
	defer cancel()

	timeoutMS := grace.Milliseconds()
	if err := client.Call(callCtx, control.MethodStop, control.StopRequest{
		Signal:    strings.TrimSpace(sig),
		TimeoutMS: &timeoutMS,
	}, nil); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	return 0
}

func dmesgSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "dmesg"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 0)
	var follow, clearBuf bool
	var tail, level int
	registerAlias([]string{"f", "follow"}, func(n string) {
		fs.BoolVar(&follow, n, false, "Follow new kernel log entries")
	})
	fs.IntVar(&tail, "tail", 0, "Show only the last N buffered entries")
	fs.IntVar(&level, "level", 0, "Maximum syslog severity level (1..8, 0 means all)")
	registerAlias([]string{"c", "clear"}, func(n string) {
		fs.BoolVar(&clearBuf, n, false, "Clear the kernel log ring after reading")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		return controlUsageError(stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}
	if tail < 0 {
		return controlUsageError(stderr, cmdName, "--tail must be non-negative")
	}
	if level < 0 || level > 8 {
		return controlUsageError(stderr, cmdName, "--level must be between 0 and 8")
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()

	req := control.KernelLogRequest{
		Follow:   follow,
		Tail:     tail,
		MaxLevel: level,
		Clear:    clearBuf,
	}
	if !follow {
		callCtx, cancel := target.callContext(ctx)
		defer cancel()
		var resp control.KernelLogResponse
		if err := client.Call(callCtx, control.MethodKernelLog, req, &resp); err != nil {
			return controlFail(stderr, cmdName, err)
		}
		for _, r := range resp.Records {
			writeKernelLogRecord(stdout, r)
		}
		return 0
	}

	stream, err := client.OpenStream(ctx, control.MethodKernelLog, req)
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer stream.Close()

	var initial control.KernelLogResponse
	if err := stream.WaitResponse(ctx, &initial); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	for _, r := range initial.Records {
		writeKernelLogRecord(stdout, r)
	}
	for {
		ev, err := stream.RecvEvent(ctx)
		if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			return 0
		}
		if err != nil {
			return controlFail(stderr, cmdName, err)
		}
		if ev.Type != "log" {
			continue
		}
		var r control.KernelLogRecord
		if json.Unmarshal(ev.Data, &r) == nil {
			writeKernelLogRecord(stdout, r)
		}
	}
}

func writeKernelLogRecord(w io.Writer, r control.KernelLogRecord) {
	sec := r.USec / 1_000_000
	rem := r.USec % 1_000_000
	if rem < 0 {
		rem = -rem
	}
	_, _ = fmt.Fprintf(w, "[%5d.%06d] <%d> %s\n", sec, rem, r.Level, r.Text)
}

func eventsSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "events"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 0)
	var filters listFlag
	var format string
	fs.Var(&filters, "filter", "Filter events (e.g. type=exec, action=pause; repeatable)")
	registerAlias([]string{"f", "format"}, func(n string) {
		fs.StringVar(&format, n, "", "Output format: table (default) or json")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		return controlUsageError(stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}
	fmtMode := strings.ToLower(strings.TrimSpace(format))
	if fmtMode != "" && fmtMode != "table" && fmtMode != "json" {
		return controlUsageError(stderr, cmdName, "unsupported --format %q (want table or json)", format)
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()

	stream, err := client.OpenStream(ctx, control.MethodEvents, control.EventsRequest{
		Filters: append([]string(nil), filters...),
	})
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer stream.Close()

	if err := stream.WaitResponse(ctx, nil); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	asJSON := fmtMode == "json"
	for {
		ev, err := stream.RecvEvent(ctx)
		if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			return 0
		}
		if err != nil {
			return controlFail(stderr, cmdName, err)
		}
		if ev.Type != "event" {
			continue
		}
		var se control.SandboxEvent
		if json.Unmarshal(ev.Data, &se) != nil {
			continue
		}
		if asJSON {
			if err := enc.Encode(se); err != nil {
				return controlFail(stderr, cmdName, err)
			}
			continue
		}
		var attrs []string
		for k, v := range se.Attributes {
			attrs = append(attrs, k+"="+v)
		}
		slices.Sort(attrs)
		_, _ = fmt.Fprintf(stdout, "%s %s %s %s\n", se.Timestamp.Format(time.RFC3339), se.Type, se.Action, strings.Join(attrs, " "))
	}
}

func pingSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "ping"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 10*time.Second)
	waitDur := fs.Duration("wait", 0, "Retry connecting until the sandbox responds or duration elapses")
	var format string
	registerAlias([]string{"f", "format"}, func(n string) {
		fs.StringVar(&format, n, "", "Output format: table (default), json, or a Go template")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		return controlUsageError(stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}
	if *waitDur < 0 {
		return controlUsageError(stderr, cmdName, "--wait must be non-negative")
	}
	endpoint, err := target.resolveEndpoint("")
	if err != nil {
		return controlUsageError(stderr, cmdName, "%v", err)
	}
	if _, _, err := control.ParseEndpoint(endpoint); err != nil {
		return controlUsageError(stderr, cmdName, "%v", err)
	}

	deadline := time.Now().Add(*waitDur)
	var client *control.Client
	for {
		dialCtx := ctx
		var dialCancel context.CancelFunc
		if *waitDur > 0 {
			dialCtx, dialCancel = context.WithDeadline(ctx, deadline)
		}
		client, err = target.dial(dialCtx, "")
		if dialCancel != nil {
			dialCancel()
		}
		if err == nil {
			break
		}
		var pe *control.ProtoError
		if errors.As(err, &pe) || *waitDur <= 0 || time.Now().After(deadline) {
			return controlFail(stderr, cmdName, err)
		}
		select {
		case <-ctx.Done():
			return controlFail(stderr, cmdName, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	defer client.Close()

	callCtx, cancel := target.callContext(ctx)
	defer cancel()
	var resp control.PingResponse
	if err := client.Call(callCtx, control.MethodPing, nil, &resp); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	usageErr, writeErr := renderSingleFormat(stdout, format, resp, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "ok sandbox=%s state=%s version=%d uptime=%s capabilities=%d\n",
			resp.SandboxID, resp.State, resp.Version, formatUptime(time.Duration(resp.UptimeNanos)), len(resp.Capabilities))
		return err
	})
	if usageErr != nil {
		return controlUsageError(stderr, cmdName, "%v", usageErr)
	}
	if writeErr != nil {
		return controlFail(stderr, cmdName, writeErr)
	}
	return 0
}

func debugSubcommand(ctx context.Context, args []string, _, stderr io.Writer) int {
	const cmdName = "debug"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 10*time.Second)
	logLevel := fs.String("log-level", "", "Sentry log level: warning, info, or debug")
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		return controlUsageError(stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}
	lvl := strings.TrimSpace(*logLevel)
	if lvl == "" {
		return controlUsageError(stderr, cmdName, "specify --log-level warning|info|debug")
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()
	callCtx, cancel := target.callContext(ctx)
	defer cancel()

	if err := client.Call(callCtx, control.MethodDebugLogLevel, control.DebugLogLevelRequest{Level: lvl}, nil); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	return 0
}
