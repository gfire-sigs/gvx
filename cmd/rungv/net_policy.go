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
	"strings"
	"unicode/utf8"

	"z.gfire.dev/gvx/pkg/gvx"
)

const (
	netPolicyGet     = "net-policy.get"
	netPolicyReplace = "net-policy.replace"
)

var netPolicyUsage = []string{
	"rungv net-policy get -control-socket=<address>",
	"rungv net-policy replace -control-socket=<address> --file=<rules.v4> --file6=<rules.v6> --qos-tx=<limit> --qos-rx=<limit>",
}

func init() {
	register(command{
		name:    "net-policy",
		summary: "Read or replace the host NAT policy of a running sandbox.",
		usage:   netPolicyUsage,
		run:     netPolicySubcommand,
	})
}

type netPolicyStartupFlags struct {
	live   bool
	config netPolicyConfigFlags
}

func (f *netPolicyStartupFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&f.live, "net-policy-live", false, "Allow live NAT policy control; requires both rule files and -control-socket")
	f.config.register(fs, "nat-iptables-file", "nat-ip6tables-file", "unlimited")
}

func (f netPolicyStartupFlags) options(fs *flag.FlagSet, mode gvx.NetworkMode, socket string) (*gvx.NetPolicyOptions, error) {
	configured := f.live
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "nat-iptables-file", "nat-ip6tables-file", "qos-tx", "qos-rx":
			configured = true
		}
	})
	if !configured {
		return nil, nil
	}
	if mode != "" && mode != gvx.NetModeNAT {
		return nil, errors.New("unsupported_mode: network policy requires NAT")
	}
	if f.live && strings.TrimSpace(socket) == "" {
		return nil, errors.New("--net-policy-live requires -control-socket")
	}
	config, err := f.config.load("nat-iptables-file", "nat-ip6tables-file")
	if err != nil {
		return nil, err
	}
	return &gvx.NetPolicyOptions{Policy: config}, nil
}

type netPolicyConfigFlags struct {
	file4, file6 string
	tx, rx       string
}

func (f *netPolicyConfigFlags) register(fs *flag.FlagSet, file4Flag, file6Flag, qosDefault string) {
	fs.StringVar(&f.file4, file4Flag, "", "Host file with IPv4 filter rules (required with IPv6 rules)")
	fs.StringVar(&f.file6, file6Flag, "", "Host file with IPv6 filter rules (required with IPv4 rules)")
	fs.StringVar(&f.tx, "qos-tx", qosDefault, "Guest transmit limit: unlimited or rate-bps=N,burst-bytes=B,queue-bytes=Q")
	fs.StringVar(&f.rx, "qos-rx", qosDefault, "Guest receive limit: unlimited or rate-bps=N,burst-bytes=B,queue-bytes=Q")
}

func (f netPolicyConfigFlags) load(file4Flag, file6Flag string) (gvx.NetPolicyConfig, error) {
	if f.file4 == "" || f.file6 == "" {
		return gvx.NetPolicyConfig{}, fmt.Errorf("specify both --%s and --%s with nonempty paths", file4Flag, file6Flag)
	}
	if f.tx == "" {
		return gvx.NetPolicyConfig{}, errors.New("specify a nonempty --qos-tx limit")
	}
	if f.rx == "" {
		return gvx.NetPolicyConfig{}, errors.New("specify a nonempty --qos-rx limit")
	}
	tx, err := gvx.ParseNetPolicyLimit(f.tx)
	if err != nil {
		return gvx.NetPolicyConfig{}, fmt.Errorf("--qos-tx: %w", err)
	}
	rx, err := gvx.ParseNetPolicyLimit(f.rx)
	if err != nil {
		return gvx.NetPolicyConfig{}, fmt.Errorf("--qos-rx: %w", err)
	}
	v4, err := readNetPolicyRules(f.file4)
	if err != nil {
		return gvx.NetPolicyConfig{}, fmt.Errorf("--%s: %w", file4Flag, err)
	}
	v6, err := readNetPolicyRules(f.file6)
	if err != nil {
		return gvx.NetPolicyConfig{}, fmt.Errorf("--%s: %w", file6Flag, err)
	}
	return gvx.NetPolicyConfig{RulesV4: v4, RulesV6: v6, TX: tx, RX: rx}, nil
}

func readNetPolicyRules(path string) (string, error) {
	f, err := openControlInput(path, false)
	if err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(f, gvx.MaxNetPolicyRules+1))
	if err := errors.Join(err, f.Close()); err != nil {
		return "", err
	}
	if len(data) > gvx.MaxNetPolicyRules {
		return "", fmt.Errorf("too_large: rule file exceeds %d bytes", gvx.MaxNetPolicyRules)
	}
	if !utf8.Valid(data) {
		return "", errors.New("invalid_policy: rule file is not UTF-8")
	}
	return string(data), nil
}

func netPolicySubcommand(ctx context.Context, args []string, streams cliIO) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		for _, usage := range netPolicyUsage {
			_, _ = fmt.Fprintln(streams.stderr, usage)
		}
		if len(args) > 0 {
			return 0
		}
		return 2
	}
	op := args[0]
	if op != "get" && op != "replace" {
		_, _ = fmt.Fprintf(streams.stderr, "rungv net-policy: unknown operation %q\n", op)
		return 2
	}
	fs := flag.NewFlagSet("rungv net-policy "+op, flag.ContinueOnError)
	fs.SetOutput(streams.stderr)
	socket := fs.String("control-socket", "", "Host path or loopback address for the control listener")
	var configFlags netPolicyConfigFlags
	if op == "replace" {
		configFlags.register(fs, "file", "file6", "")
	}
	if err := fs.Parse(normalizeCommandArgs(fs, args[1:])); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	fail := func(err error, code int) int {
		_, _ = fmt.Fprintf(streams.stderr, "rungv net-policy %s: %v\n", op, err)
		return code
	}
	if fs.NArg() != 0 {
		return fail(errors.New("unexpected positional arguments"), 2)
	}
	if strings.TrimSpace(*socket) == "" {
		return fail(errors.New("specify -control-socket"), 2)
	}
	req := netPolicyRequest{Op: netPolicyGet}
	if op == "replace" {
		config, err := configFlags.load("file", "file6")
		if err != nil {
			return fail(err, 2)
		}
		req.Op = netPolicyReplace
		req.NetPolicyConfig = &config
	}
	result, err := requestNetPolicy(ctx, *socket, req)
	if err != nil {
		return fail(err, 1)
	}
	if err := json.NewEncoder(streams.stdout).Encode(result); err != nil {
		return fail(fmt.Errorf("write response: %w", err), 1)
	}
	return 0
}
