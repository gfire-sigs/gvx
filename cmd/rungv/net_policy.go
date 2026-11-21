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
	"rungv net-policy replace -control-socket=<address> --expected-revision=<revision> --file=<rules.v4> --file6=<rules.v6> --qos-tx=<limit> --qos-rx=<limit>",
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
	statePath string
	live      bool
	config    netPolicyConfigFlags
}

func (f *netPolicyStartupFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.statePath, "net-policy-state", "", "Host path to persistent NAT policy state")
	fs.BoolVar(&f.live, "net-policy-live", false, "Allow live policy changes over the host control socket")
	f.config.register(fs, "nat-iptables-file", "nat-ip6tables-file")
}

func (f netPolicyStartupFlags) options(fs *flag.FlagSet, mode gvx.NetworkMode, socket string) (*gvx.NetPolicyOptions, error) {
	path := strings.TrimSpace(f.statePath)
	seed := flagVisited(fs, "nat-iptables-file") || flagVisited(fs, "nat-ip6tables-file") || flagVisited(fs, "qos-tx") || flagVisited(fs, "qos-rx")
	if path == "" && !seed && !f.live && !flagVisited(fs, "net-policy-state") {
		return nil, nil
	}
	if mode != "" && mode != gvx.NetModeNAT {
		return nil, errors.New("unsupported_mode: network policy requires NAT")
	}
	if path == "" {
		return nil, errors.New("specify --net-policy-state with a nonempty host path")
	}
	if f.live && strings.TrimSpace(socket) == "" {
		return nil, errors.New("--net-policy-live requires -control-socket")
	}
	opts := &gvx.NetPolicyOptions{Path: path}
	if seed {
		config, err := f.config.load("nat-iptables-file", "nat-ip6tables-file")
		if err != nil {
			return nil, err
		}
		opts.Seed = &config
	}
	return opts, nil
}

type netPolicyConfigFlags struct {
	file4, file6 string
	tx, rx       string
}

func (f *netPolicyConfigFlags) register(fs *flag.FlagSet, file4Flag, file6Flag string) {
	fs.StringVar(&f.file4, file4Flag, "", "Host file with IPv4 filter rules")
	fs.StringVar(&f.file6, file6Flag, "", "Host file with IPv6 filter rules")
	fs.StringVar(&f.tx, "qos-tx", "", "Guest transmit limit: unlimited or rate-bps=N,burst-bytes=B,queue-bytes=Q")
	fs.StringVar(&f.rx, "qos-rx", "", "Guest receive limit: unlimited or rate-bps=N,burst-bytes=B,queue-bytes=Q")
}

func (f netPolicyConfigFlags) load(file4Flag, file6Flag string) (gvx.NetPolicyConfig, error) {
	if f.file4 == "" || f.file6 == "" || f.tx == "" || f.rx == "" {
		return gvx.NetPolicyConfig{}, fmt.Errorf("specify both --%s and --%s and both --qos-tx and --qos-rx", file4Flag, file6Flag)
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
	var replacement netPolicyReplacement
	if op == "replace" {
		fs.StringVar(&replacement.ExpectedRevision, "expected-revision", "", "Current revision from net-policy get")
		configFlags.register(fs, "file", "file6")
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
		if replacement.ExpectedRevision == "" {
			return fail(errors.New("specify --expected-revision"), 2)
		}
		var err error
		replacement.NetPolicyConfig, err = configFlags.load("file", "file6")
		if err != nil {
			return fail(err, 2)
		}
		req.Op = netPolicyReplace
		req.netPolicyReplacement = &replacement
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
