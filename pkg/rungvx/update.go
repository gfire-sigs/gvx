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
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

func init() {
	register(command{
		name:    "update",
		summary: "Update live resource limits, NAT settings, or mutable tunables of a running sandbox.",
		usage:   []string{"rungvx update -S <socket>|-n <name> [-m SIZE] [--cpus N] [--cpu-quota USEC] [--cpu-period USEC] [--pids-limit N] [--isolate-lan=BOOL] [--net-tx-bps BPS] [--net-rx-bps BPS] [--tune KEY=VAL]..."},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return updateSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
}

func updateSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "update"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 10*time.Second)

	var memory, cpus, pidsLimit, cpuQuotaStr, format string
	var forceMemory, isolateLAN bool
	var cpuPeriod int64
	var netTXBPS, netRXBPS uint64
	var tunePairs listFlag

	registerAlias([]string{"m", "memory"}, func(n string) {
		fs.StringVar(&memory, n, "", "Memory limit (e.g. 512m, 2g, or 0 for unlimited)")
	})
	fs.BoolVar(&forceMemory, "force-memory", false, "Allow lowering -m below current sandbox memory usage")
	fs.StringVar(&cpus, "cpus", "", "CPU bandwidth quota (e.g. 0.5, 2.0, or 0 for unlimited)")
	fs.Int64Var(&cpuPeriod, "cpu-period", 0, "CFS CPU bandwidth period in microseconds (1000..1000000)")
	fs.StringVar(&cpuQuotaStr, "cpu-quota", "", "CFS CPU quota per period in microseconds (-1 or max for unlimited)")
	fs.StringVar(&pidsLimit, "pids-limit", "", "Maximum guest processes/tasks (0 or -1 for unlimited)")
	fs.BoolVar(&isolateLAN, "isolate-lan", false, "Block RFC1918 and loopback LAN destinations in NAT mode")
	registerNetworkBandwidthFlags(fs, &netTXBPS, &netRXBPS)
	fs.Var(&tunePairs, "tune", "Update a mutable host-side tunable (KEY=VALUE, repeatable)")
	registerAlias([]string{"f", "format"}, func(n string) {
		fs.StringVar(&format, n, "", "Format applied snapshot using table, json, or a Go template")
	})

	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		return controlUsageError(stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}

	var req control.ResourceUpdateRequest
	req.ForceMemory = forceMemory
	changed := false

	if flagVisited(fs, "m") || flagVisited(fs, "memory") {
		bytes, err := gvx.ParseMemory(memory)
		if err != nil {
			return controlUsageError(stderr, cmdName, "-m: %v", err)
		}
		req.MemoryBytes = &bytes
		changed = true
	}

	hasCPUs := flagVisited(fs, "cpus")
	hasQuota := flagVisited(fs, "cpu-quota")
	hasPeriod := flagVisited(fs, "cpu-period")
	if hasCPUs && (hasQuota || hasPeriod) {
		return controlUsageError(stderr, cmdName, "--cpus cannot be combined with --cpu-quota or --cpu-period")
	}
	if hasCPUs {
		millis, err := gvx.ParseCPUs(cpus, runtime.NumCPU())
		if err != nil {
			return controlUsageError(stderr, cmdName, "--cpus: %v", err)
		}
		req.CPUMillis = &millis
		changed = true
	}
	if hasPeriod {
		if cpuPeriod < 1000 || cpuPeriod > 1_000_000 {
			return controlUsageError(stderr, cmdName, "--cpu-period must be between 1000 and 1000000 microseconds")
		}
		req.CPUPeriodUSec = &cpuPeriod
		changed = true
	}
	if hasQuota {
		qRaw := strings.ToLower(strings.TrimSpace(cpuQuotaStr))
		var q int64
		if qRaw == "max" || qRaw == "-1" || qRaw == "0" {
			q = 0
		} else {
			parsed, err := strconv.ParseInt(qRaw, 10, 64)
			if err != nil || parsed < 1000 {
				return controlUsageError(stderr, cmdName, "--cpu-quota must be >= 1000, -1, or max")
			}
			q = parsed
		}
		req.CPUQuotaUSec = &q
		changed = true
	}
	if flagVisited(fs, "pids-limit") {
		raw := strings.ToLower(strings.TrimSpace(pidsLimit))
		var limit int64
		if raw == "max" || raw == "-1" || raw == "0" {
			limit = 0
		} else {
			parsed, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || parsed < 0 {
				return controlUsageError(stderr, cmdName, "--pids-limit must be >= 0, -1, or max")
			}
			limit = parsed
		}
		req.PidsLimit = &limit
		changed = true
	}
	if flagVisited(fs, "isolate-lan") {
		v := isolateLAN
		req.IsolateLAN = &v
		changed = true
	}
	if flagVisited(fs, "net-tx-bps") {
		req.NetTXBPS = &netTXBPS
		changed = true
	}
	if flagVisited(fs, "net-rx-bps") {
		req.NetRXBPS = &netRXBPS
		changed = true
	}
	if len(tunePairs) > 0 {
		req.Tuning = make(map[string]string, len(tunePairs))
		for _, pair := range tunePairs {
			k, v, ok := strings.Cut(pair, "=")
			if !ok || strings.TrimSpace(k) == "" {
				return controlUsageError(stderr, cmdName, "--tune %q: want KEY=VALUE", pair)
			}
			req.Tuning[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
		changed = true
	}
	if !changed {
		return controlUsageError(stderr, cmdName, "specify at least one setting to update")
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()

	callCtx, cancel := target.callContext(ctx)
	defer cancel()

	var snap control.ResourceSnapshot
	if err := client.Call(callCtx, control.MethodResourceUpdate, req, &snap); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	if strings.TrimSpace(format) == "" {
		return 0
	}
	usageErr, writeErr := renderSingleFormat(stdout, format, snap, func(w io.Writer) error {
		tw := tabwriter.NewWriter(w, 16, 1, 2, ' ', 0)
		_, _ = fmt.Fprintf(tw, "Memory Limit:\t%s\n", formatLimitBytes(snap.MemoryBytes))
		_, _ = fmt.Fprintf(tw, "CPU Quota:\t%d us / %d us (%d mCPU, %d guest CPUs)\n", snap.CPUQuotaUSec, snap.CPUPeriodUSec, snap.CPUMillis, snap.GuestCPUs)
		_, _ = fmt.Fprintf(tw, "PIDs Limit:\t%d\n", snap.PidsLimit)
		_, _ = fmt.Fprintf(tw, "Isolate LAN:\t%v\n", snap.IsolateLAN)
		if client.HasFeature(control.FeatureNetQoS) {
			_, _ = fmt.Fprintf(tw, "Network TX:\t%s\n", formatBandwidth(snap.NetTXBPS))
			_, _ = fmt.Fprintf(tw, "Network RX:\t%s\n", formatBandwidth(snap.NetRXBPS))
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

func formatLimitBytes(n int64) string {
	if n <= 0 {
		return "unlimited"
	}
	return humanBytes(uint64(n))
}

func formatBandwidth(bps uint64) string {
	if bps == 0 {
		return "unlimited"
	}
	return strconv.FormatUint(bps, 10) + " bps"
}
