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

package gvx

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"z.gfire.dev/gvx/pkg/gvx/control"
	"z.gfire.dev/gvx/pkg/netbackend"
)

// NATPolicyConfig describes the operator's ingress and egress rules.
type NATPolicyConfig = netbackend.NATPolicyConfig

// ParseNATPolicy decodes one bounded NAT policy document.
func ParseNATPolicy(r io.Reader) (NATPolicyConfig, error) {
	return netbackend.ParseNATPolicy(r)
}

func (s *Sandbox) handleNATPolicyGet(_ context.Context, stream *control.Stream) error {
	if s.natPolicy == nil {
		return control.NewError(control.CodeUnsupported, "NAT policy is unavailable for this sandbox")
	}
	return replyNATPolicy(stream, s.natPolicy.Config())
}

func (s *Sandbox) handleNATPolicySet(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	if s.natPolicy == nil {
		return control.NewError(control.CodeUnsupported, "NAT policy is unavailable for this sandbox")
	}
	var req control.NATPolicyState
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	cfg, err := ParseNATPolicy(bytes.NewReader(req.Policy))
	if err != nil {
		return control.NewError(control.CodeInvalidArgument, err.Error())
	}
	compiled, err := netbackend.CompileNATPolicy(&cfg)
	if err != nil {
		return control.NewError(control.CodeInvalidArgument, err.Error())
	}
	if err := s.replaceNATPolicy(ctx, compiled); err != nil {
		return err
	}
	return replyNATPolicy(stream, &cfg)
}

func (s *Sandbox) replaceNATPolicy(ctx context.Context, policy *netbackend.CompiledNATPolicy) error {
	// The checkpoint records whether the sandbox requires an external policy.
	s.opMu.RLock()
	defer s.opMu.RUnlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.natPolicy.Replace(policy); err != nil {
		return mapControlErr(err)
	}
	return nil
}

func replyNATPolicy(stream *control.Stream, cfg *NATPolicyConfig) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return stream.Reply(control.NATPolicyState{Policy: raw})
}
