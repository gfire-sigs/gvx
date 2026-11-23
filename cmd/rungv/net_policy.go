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
	"fmt"
	"os"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

const (
	netPolicyGetUsage     = "rungv net-policy get -S <socket>|-n <name>"
	netPolicyReplaceUsage = "rungv net-policy replace -S <socket>|-n <name> --file FILE"
)

func init() {
	register(command{
		name:    "net-policy",
		summary: "Read or replace the host NAT firewall policy of a running sandbox.",
		usage:   []string{netPolicyGetUsage, netPolicyReplaceUsage},
		run:     netPolicySubcommand,
	})
}

func netPolicySubcommand(ctx context.Context, args []string, streams cliIO) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		w, code := streams.stdout, 0
		if len(args) == 0 {
			w, code = streams.stderr, 2
		}
		_, _ = fmt.Fprintf(w, "Usage: %s\n       %s\n", netPolicyGetUsage, netPolicyReplaceUsage)
		return code
	}

	cmdName := "net-policy " + args[0]
	fs := newImageFlagSet(cmdName, streams.stderr)
	target := addControlFlags(fs, 10*time.Second)
	var method, capability, file string
	switch args[0] {
	case "get":
		method, capability = control.MethodNATPolicyGet, control.CapNATPolicyRead
	case "replace":
		method, capability = control.MethodNATPolicySet, control.CapNATPolicyWrite
		fs.StringVar(&file, "file", "", "Path to the replacement NAT firewall policy JSON file")
	default:
		return controlUsageError(streams.stderr, "net-policy", "unknown subcommand %q (want get or replace)", args[0])
	}
	if code, stop := parseImageFlags(fs, args[1:]); stop {
		return code
	}
	if fs.NArg() > 0 {
		return controlUsageError(streams.stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}

	var params any
	if method == control.MethodNATPolicySet {
		if file == "" {
			return controlUsageError(streams.stderr, cmdName, "specify --file FILE")
		}
		policy, err := readNATPolicyFile(file)
		if err != nil {
			return controlUsageError(streams.stderr, cmdName, "--file: %v", err)
		}
		raw, err := json.Marshal(policy)
		if err != nil {
			return controlFail(streams.stderr, cmdName, err)
		}
		params = control.NATPolicyState{Policy: raw}
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(streams.stderr, cmdName, err)
	}
	defer client.Close()
	if !client.HasCapability(capability) {
		return controlFail(streams.stderr, cmdName, control.NewErrorf(control.CodeForbiddenByPolicy, "control server did not advertise %q", capability))
	}
	callCtx, cancel := target.callContext(ctx)
	defer cancel()
	var state control.NATPolicyState
	if err := client.Call(callCtx, method, params, &state); err != nil {
		return controlFail(streams.stderr, cmdName, err)
	}
	if len(state.Policy) == 0 {
		return controlFail(streams.stderr, cmdName, control.NewError(control.CodeInternal, "control response has no policy field"))
	}
	// A trailing newline could put a reusable policy file over the size limit.
	if _, err := streams.stdout.Write(state.Policy); err != nil {
		return controlFail(streams.stderr, cmdName, err)
	}
	return 0
}

func readNATPolicyFile(path string) (gvx.NATPolicyConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return gvx.NATPolicyConfig{}, err
	}
	policy, parseErr := gvx.ParseNATPolicy(f)
	if err := errors.Join(parseErr, f.Close()); err != nil {
		return gvx.NATPolicyConfig{}, fmt.Errorf("read %q: %w", path, err)
	}
	return policy, nil
}
