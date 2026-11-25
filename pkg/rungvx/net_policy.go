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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

const (
	netPolicyGetUsage     = "rungvx net-policy get -S <socket>|-n <name>"
	netPolicyReplaceUsage = "rungvx net-policy replace -S <socket>|-n <name> --file FILE"
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
		fs.StringVar(&file, "file", "", "Replacement NAT firewall policy file (.json, .yaml, or .yml)")
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
	parse := gvx.ParseNATPolicy
	ext := filepath.Ext(path)
	switch strings.ToLower(ext) {
	case ".json":
	case ".yaml", ".yml":
		parse = parseYAMLNATPolicy
	case "":
		return gvx.NATPolicyConfig{}, fmt.Errorf("policy file %q has no extension; expected .json, .yaml, or .yml", path)
	default:
		return gvx.NATPolicyConfig{}, fmt.Errorf("unsupported policy file extension %q; expected .json, .yaml, or .yml", ext)
	}
	f, err := os.Open(path)
	if err != nil {
		return gvx.NATPolicyConfig{}, err
	}
	policy, parseErr := parse(f)
	if err := errors.Join(parseErr, f.Close()); err != nil {
		return gvx.NATPolicyConfig{}, fmt.Errorf("read %q: %w", path, err)
	}
	return policy, nil
}

func parseYAMLNATPolicy(r io.Reader) (gvx.NATPolicyConfig, error) {
	const maxYAMLBytes = 64 << 10
	data, err := io.ReadAll(io.LimitReader(r, maxYAMLBytes+1))
	if err != nil {
		return gvx.NATPolicyConfig{}, err
	}
	if len(data) > maxYAMLBytes {
		return gvx.NATPolicyConfig{}, errors.New("NAT policy exceeds 64 KiB")
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := d.Decode(&doc); err != nil {
		return gvx.NATPolicyConfig{}, fmt.Errorf("parse YAML policy: %w", err)
	}
	if err := d.Decode(new(yaml.Node)); err != io.EOF {
		if err != nil {
			return gvx.NATPolicyConfig{}, fmt.Errorf("parse YAML policy: %w", err)
		}
		return gvx.NATPolicyConfig{}, errors.New("NAT policy must contain one YAML document")
	}
	value, err := policyYAMLValue(doc.Content[0], 0)
	if err != nil {
		return gvx.NATPolicyConfig{}, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return gvx.NATPolicyConfig{}, err
	}
	return gvx.ParseNATPolicy(bytes.NewReader(raw))
}

func policyYAMLValue(n *yaml.Node, depth int) (any, error) {
	// The deepest values are fields in rules: document, direction, rules, rule, field.
	if depth > 4 {
		return nil, fmt.Errorf("YAML line %d: policy nesting exceeds four levels", n.Line)
	}
	switch n.Kind {
	case yaml.MappingNode:
		if n.ShortTag() == "!!map" {
			fields := make(map[string]any, len(n.Content)/2)
			for i := 0; i < len(n.Content); i += 2 {
				key := n.Content[i]
				if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" {
					return nil, fmt.Errorf("YAML line %d: expected a string field name", key.Line)
				}
				if _, exists := fields[key.Value]; exists {
					return nil, fmt.Errorf("YAML line %d: duplicate field %q", key.Line, key.Value)
				}
				value, err := policyYAMLValue(n.Content[i+1], depth+1)
				if err != nil {
					return nil, err
				}
				fields[key.Value] = value
			}
			return fields, nil
		}
	case yaml.SequenceNode:
		if n.ShortTag() == "!!seq" {
			items := make([]any, len(n.Content))
			for i, item := range n.Content {
				value, err := policyYAMLValue(item, depth+1)
				if err != nil {
					return nil, err
				}
				items[i] = value
			}
			return items, nil
		}
	case yaml.ScalarNode:
		if n.ShortTag() == "!!str" {
			return n.Value, nil
		}
	}
	return nil, fmt.Errorf("YAML line %d: expected a mapping, sequence, or string", n.Line)
}
