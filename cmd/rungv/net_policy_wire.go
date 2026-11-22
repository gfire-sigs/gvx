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
	"encoding/binary"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
)

const (
	netPolicyFrameTag = "GVXNP/2\n"
	maxNetPolicyFrame = 1 << 20
)

type netPolicyRequest struct {
	Op    string `json:"op"`
	Token string `json:"token,omitempty"`
	*gvx.NetPolicyConfig
}

type netPolicySuccess struct {
	OK bool `json:"ok"`
}

type netPolicyFailure struct {
	Code   string `json:"code"`
	Family string `json:"family,omitempty"`
	Line   int    `json:"line,omitempty"`
	Option string `json:"option,omitempty"`
	Detail string `json:"detail,omitempty"`
}

func (e *netPolicyFailure) Error() string {
	var message strings.Builder
	message.WriteString(e.Code)
	if e.Family != "" {
		_, _ = fmt.Fprintf(&message, " (%s", e.Family)
		if e.Line != 0 {
			_, _ = fmt.Fprintf(&message, ":%d", e.Line)
		}
		message.WriteByte(')')
	}
	if e.Option != "" {
		_, _ = fmt.Fprintf(&message, " %s", e.Option)
	}
	if e.Detail != "" {
		_, _ = fmt.Fprintf(&message, ": %s", e.Detail)
	}
	return message.String()
}

var (
	errPolicyFrameVersion     = &netPolicyFailure{Code: "incompatible_protocol"}
	errPolicyFrameTooLarge    = &netPolicyFailure{Code: "too_large"}
	errPolicyWireInvalid      = &netPolicyFailure{Code: "invalid_policy"}
	errPolicyWireUnauthorized = &netPolicyFailure{Code: "unauthorized"}
	errPolicyWireDisabled     = &netPolicyFailure{Code: "policy_disabled"}
)

func readNetPolicyFrame(r io.Reader) ([]byte, error) {
	var tag [len(netPolicyFrameTag)]byte
	if _, err := io.ReadFull(r, tag[:]); err != nil || string(tag[:]) != netPolicyFrameTag {
		return nil, errPolicyFrameVersion
	}
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, errPolicyWireInvalid
	}
	size := binary.BigEndian.Uint32(length[:])
	if size > maxNetPolicyFrame {
		return nil, errPolicyFrameTooLarge
	}
	if size == 0 {
		return nil, errPolicyWireInvalid
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, errPolicyWireInvalid
	}
	return payload, nil
}

func writeNetPolicyFrame(w io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) > maxNetPolicyFrame {
		return errPolicyFrameTooLarge
	}
	var header [len(netPolicyFrameTag) + 4]byte
	copy(header[:], netPolicyFrameTag)
	binary.BigEndian.PutUint32(header[len(netPolicyFrameTag):], uint32(len(payload)))
	buffers := net.Buffers{header[:], payload}
	_, err = buffers.WriteTo(w)
	return err
}

type netPolicyRequestFields struct {
	Op      *string        `json:"op"`
	Token   jsontext.Value `json:"token"`
	RulesV4 *string        `json:"rules_v4"`
	RulesV6 *string        `json:"rules_v6"`
	TX      jsontext.Value `json:"qos_tx"`
	RX      jsontext.Value `json:"qos_rx"`
}

func (s *controlServer) serveNetPolicy(conn net.Conn, reader io.Reader) {
	payload, err := readNetPolicyFrame(reader)
	s.endRead(conn)
	var result any
	if err != nil {
		result = err
	} else {
		result = s.dispatchNetPolicy(payload)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(controlResponseTimeout)); err != nil {
		return
	}
	_ = writeNetPolicyFrame(conn, result)
}

func (s *controlServer) dispatchNetPolicy(payload []byte) any {
	var req netPolicyRequestFields
	if err := jsonv2.Unmarshal(payload, &req, jsonv2.RejectUnknownMembers(true)); err != nil {
		return errPolicyWireInvalid
	}
	var token string
	if len(req.Token) != 0 && (req.Token.Kind() != '"' || jsonv2.Unmarshal(req.Token, &token) != nil) || !controlTokenMatches(s.token, token) {
		return errPolicyWireUnauthorized
	}
	if s.policy == nil {
		return errPolicyWireDisabled
	}
	if req.Op == nil {
		return errPolicyWireInvalid
	}
	switch *req.Op {
	case netPolicyGet:
		// GET permits only op and token, including when a replacement field is null.
		var get struct {
			Op    string         `json:"op"`
			Token jsontext.Value `json:"token"`
		}
		if err := jsonv2.Unmarshal(payload, &get, jsonv2.RejectUnknownMembers(true)); err != nil {
			return errPolicyWireInvalid
		}
		config, err := s.policy.NetPolicy()
		if err != nil {
			return s.netPolicyError(err)
		}
		return config
	case netPolicyReplace:
		config, failure := req.replacementConfig()
		if failure != nil {
			return failure
		}
		if err := s.policy.ReplaceNetPolicy(config); err != nil {
			return s.netPolicyError(err)
		}
		return netPolicySuccess{OK: true}
	default:
		return errPolicyWireInvalid
	}
}

func (req netPolicyRequestFields) replacementConfig() (gvx.NetPolicyConfig, *netPolicyFailure) {
	if req.RulesV4 == nil || req.RulesV6 == nil || len(req.TX) == 0 || len(req.RX) == 0 {
		return gvx.NetPolicyConfig{}, errPolicyWireInvalid
	}
	if len(*req.RulesV4) > gvx.MaxNetPolicyRules || len(*req.RulesV6) > gvx.MaxNetPolicyRules {
		return gvx.NetPolicyConfig{}, errPolicyFrameTooLarge
	}
	config := gvx.NetPolicyConfig{RulesV4: *req.RulesV4, RulesV6: *req.RulesV6}
	if err := jsonv2.Unmarshal(req.TX, &config.TX); req.TX.Kind() == 'n' || err != nil {
		return gvx.NetPolicyConfig{}, &netPolicyFailure{Code: "invalid_policy", Option: "qos_tx"}
	}
	if err := jsonv2.Unmarshal(req.RX, &config.RX); req.RX.Kind() == 'n' || err != nil {
		return gvx.NetPolicyConfig{}, &netPolicyFailure{Code: "invalid_policy", Option: "qos_rx"}
	}
	return config, nil
}

func (s *controlServer) netPolicyError(err error) *netPolicyFailure {
	failure := &netPolicyFailure{Code: gvx.NetPolicyErrorCode(err)}
	var detail *gvx.NetPolicyError
	if errors.As(err, &detail) {
		failure.Family, failure.Line = detail.Family, detail.Line
		failure.Option, failure.Detail = detail.Option, detail.Detail
		if s.token != "" {
			failure.Option = strings.ReplaceAll(failure.Option, s.token, "[redacted]")
			failure.Detail = strings.ReplaceAll(failure.Detail, s.token, "[redacted]")
		}
	}
	return failure
}

func requestNetPolicy(ctx context.Context, raw string, req netPolicyRequest) (any, error) {
	network, address, err := parseCheckpointEndpoint(raw)
	if err != nil {
		return nil, err
	}
	address, err = policyControlAddress(network, address, false)
	if err != nil {
		return nil, err
	}
	if network == "unix" {
		if err := validatePolicySocket(address); err != nil {
			return nil, err
		}
	}
	if controlTokenRequired(network) {
		req.Token, err = readControlToken(network, address)
		if err != nil {
			return nil, fmt.Errorf("unauthorized: %w", err)
		}
		if req.Token == "" {
			return nil, errPolicyWireUnauthorized
		}
	}
	dialer := net.Dialer{Timeout: controlRequestTimeout}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("connect control socket: %w", err)
	}
	defer conn.Close()
	if network == "unix" && !controlTokenRequired(network) && !controlUnixPeerOwned(conn) {
		return nil, errPolicyWireUnauthorized
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := conn.SetWriteDeadline(time.Now().Add(controlRequestTimeout)); err != nil {
		return nil, err
	}
	if err := writeNetPolicyFrame(conn, req); err != nil {
		return nil, netPolicyExchangeError(req.Op, "send request", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(controlResponseTimeout)); err != nil {
		return nil, netPolicyExchangeError(req.Op, "set response deadline", err)
	}
	payload, err := readNetPolicyFrame(conn)
	if err != nil {
		return nil, netPolicyExchangeError(req.Op, "read response", err)
	}
	result, err := decodeNetPolicyReply(payload, req.Op)
	if err != nil {
		return nil, netPolicyExchangeError(req.Op, "decode response", err)
	}
	if failure, ok := result.(*netPolicyFailure); ok {
		return nil, failure
	}
	return result, nil
}

func netPolicyExchangeError(op, stage string, err error) error {
	if op == netPolicyReplace {
		return fmt.Errorf("%s: %w; run net-policy get before retrying replace", stage, err)
	}
	return fmt.Errorf("%s: %w", stage, err)
}

func decodeNetPolicyReply(payload []byte, op string) (any, error) {
	var fields map[string]jsontext.Value
	if err := jsonv2.Unmarshal(payload, &fields); err != nil || len(fields) == 0 {
		return nil, errPolicyFrameVersion
	}
	if _, ok := fields["code"]; ok {
		var failure netPolicyFailure
		if err := jsonv2.Unmarshal(payload, &failure, jsonv2.RejectUnknownMembers(true)); err != nil || failure.Code == "" {
			return nil, errPolicyFrameVersion
		}
		for _, value := range fields {
			if value.Kind() == 'n' {
				return nil, errPolicyFrameVersion
			}
		}
		return &failure, nil
	}
	if op == netPolicyReplace {
		if len(fields) != 1 || fields["ok"].Kind() != 't' {
			return nil, errPolicyFrameVersion
		}
		return netPolicySuccess{OK: true}, nil
	}
	if len(fields) != 4 || fields["rules_v4"].Kind() != '"' || fields["rules_v6"].Kind() != '"' {
		return nil, errPolicyFrameVersion
	}
	for _, name := range [...]string{"qos_tx", "qos_rx"} {
		switch fields[name].Kind() {
		case '"', '{':
		default:
			return nil, errPolicyFrameVersion
		}
	}
	var config gvx.NetPolicyConfig
	if err := jsonv2.Unmarshal(payload, &config, jsonv2.RejectUnknownMembers(true)); err != nil || len(config.RulesV4) > gvx.MaxNetPolicyRules || len(config.RulesV6) > gvx.MaxNetPolicyRules {
		return nil, errPolicyFrameVersion
	}
	return config, nil
}
