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

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"time"
)

// DialOptions configures Dial.
type DialOptions struct {
	Endpoint         string
	Token            string
	TokenFile        string
	ClientName       string
	HandshakeTimeout time.Duration
}

// Client is an authenticated gvx-ctrl/2 client session.
type Client struct {
	conn         *Conn
	sandboxID    string
	capabilities []string
	features     []string
	maxFrame     int
	network      string
	address      string
}

// Dial connects to a control endpoint, performs the v2 HELLO handshake, and
// returns a multiplexed Client.
func Dial(ctx context.Context, opts DialOptions) (*Client, error) {
	network, address, err := ParseEndpoint(opts.Endpoint)
	if err != nil {
		return nil, err
	}
	token := opts.Token
	if token == "" {
		token, err = ReadToken(network, address, opts.TokenFile)
		if err != nil {
			return nil, err
		}
	}
	timeout := opts.HandshakeTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	var dialer net.Dialer
	nc, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("connect control socket %s://%s: %w", network, address, err)
	}
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = nc.SetDeadline(deadline)

	if _, err := nc.Write([]byte(Preface)); err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("write control preface: %w", err)
	}
	helloReq := HelloRequest{
		Version:  ProtocolVersion,
		Token:    token,
		Client:   opts.ClientName,
		Features: []string{"zstd", "scm_rights"},
	}
	reqBytes, err := json.Marshal(helloReq)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	if err := WriteFrame(nc, Frame{
		Type:     FrameHello,
		StreamID: 0,
		Payload:  reqBytes,
	}, HandshakeMaxFrameBytes); err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("write control hello: %w", err)
	}

	respFrame, err := ReadFrame(nc, HandshakeMaxFrameBytes)
	if err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("read control hello response: %w", err)
	}
	if respFrame.Type != FrameHello || respFrame.StreamID != 0 {
		_ = nc.Close()
		return nil, fmt.Errorf("unexpected control hello frame type 0x%02x", byte(respFrame.Type))
	}
	var helloResp HelloResponse
	if err := json.Unmarshal(respFrame.Payload, &helloResp); err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("decode control hello response: %w", err)
	}
	if !helloResp.OK {
		_ = nc.Close()
		if helloResp.Error != nil {
			return nil, helloResp.Error
		}
		return nil, NewError(CodeUnauthorized, "control handshake rejected")
	}

	_ = nc.SetDeadline(time.Time{})
	maxFrame := helloResp.MaxFrameBytes
	if maxFrame <= 0 || maxFrame > AbsoluteMaxFrameBytes {
		maxFrame = DefaultMaxFrameBytes
	}
	c := newConn(nc, nil, maxFrame, false, false, nil)
	c.startReadLoop()
	return &Client{
		conn:         c,
		sandboxID:    helloResp.SandboxID,
		capabilities: helloResp.Capabilities,
		features:     helloResp.Features,
		maxFrame:     maxFrame,
		network:      network,
		address:      address,
	}, nil
}

// SandboxID returns the sandbox identifier reported in HELLO.
func (c *Client) SandboxID() string {
	return c.sandboxID
}

// Capabilities returns the server-advertised capabilities.
func (c *Client) Capabilities() []string {
	return slices.Clone(c.capabilities)
}

// HasCapability reports whether capName was advertised by the server.
func (c *Client) HasCapability(capName string) bool {
	return slices.Contains(c.capabilities, capName)
}

// HasFeature reports whether feature was negotiated during HELLO.
func (c *Client) HasFeature(feature string) bool {
	return slices.Contains(c.features, feature)
}

// Network returns the transport network ("unix" or "tcp").
func (c *Client) Network() string {
	return c.network
}

// MaxFrameBytes returns the negotiated maximum payload length per wire frame.
func (c *Client) MaxFrameBytes() int {
	return c.maxFrame
}

// Done returns a channel closed when the underlying control connection ends.
func (c *Client) Done() <-chan struct{} {
	return c.conn.Done()
}

// Ping executes a wire-level ping/pong round-trip.
func (c *Client) Ping(ctx context.Context) error {
	return c.conn.Ping(ctx)
}

// Close closes the underlying control connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// OpenStream opens a new multiplexed RPC stream, sends FrameRequest (plus any
// SCM_RIGHTS fds), and returns the active stream before waiting for FrameResponse.
func (c *Client) OpenStream(ctx context.Context, method string, params any, fds ...int) (*Stream, error) {
	stream, err := c.conn.allocStream(ctx)
	if err != nil {
		return nil, err
	}
	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			stream.Close()
			return nil, fmt.Errorf("control: marshal params for %q: %w", method, err)
		}
		rawParams = b
	}
	payload, err := json.Marshal(RequestEnvelope{
		Method: method,
		Params: rawParams,
	})
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("control: marshal request %q: %w", method, err)
	}
	if err := c.conn.writeFrame(Frame{
		Type:     FrameRequest,
		StreamID: stream.id,
		Payload:  payload,
		FDs:      fds,
	}); err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
}

// Call executes a unary RPC and decodes the JSON result into out when non-nil.
func (c *Client) Call(ctx context.Context, method string, params, out any, fds ...int) error {
	stream, err := c.OpenStream(ctx, method, params, fds...)
	if err != nil {
		return err
	}
	defer stream.Close()
	return stream.WaitResponse(ctx, out)
}
