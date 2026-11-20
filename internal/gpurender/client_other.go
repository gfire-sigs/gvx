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

//go:build !darwin

package gpurender

import (
	"context"

	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
)

// Client is a stub on non-darwin hosts. Start always returns ErrUnsupported.
type Client struct{}

// Start returns ErrUnsupported on non-darwin hosts.
func Start(ctx context.Context, opts Options) (*Client, error) {
	return nil, ErrUnsupported
}

// Mode returns 0 on non-darwin hosts.
func (c *Client) Mode() gpuproto.Mode {
	return 0
}

// CreateResource returns ErrUnsupported on non-darwin hosts.
func (c *Client) CreateResource(ctx context.Context, req gpuproto.ResourceCreate) (gpuproto.Blob, error) {
	return gpuproto.Blob{}, ErrUnsupported
}

// Transfer returns ErrUnsupported on non-darwin hosts.
func (c *Client) Transfer(ctx context.Context, req gpuproto.Transfer) error {
	return ErrUnsupported
}

// Capset returns nil and false on non-darwin hosts.
func (c *Client) Capset(id, version uint32) ([]byte, bool) {
	return nil, false
}

// CreateContext returns ErrUnsupported on non-darwin hosts.
func (c *Client) CreateContext(ctx context.Context, ctxID, capsetID uint32, name string) error {
	return ErrUnsupported
}

// DestroyContext returns ErrUnsupported on non-darwin hosts.
func (c *Client) DestroyContext(ctxID uint32) error {
	return ErrUnsupported
}

// CreateBlob returns ErrUnsupported on non-darwin hosts.
func (c *Client) CreateBlob(ctx context.Context, req gpuproto.BlobCreate) (gpuproto.Blob, error) {
	return gpuproto.Blob{}, ErrUnsupported
}

// UnrefResource returns ErrUnsupported on non-darwin hosts.
func (c *Client) UnrefResource(ctxID, resID uint32) error {
	return ErrUnsupported
}

// Submit returns ErrUnsupported on non-darwin hosts.
func (c *Client) Submit(ctxID uint32, cmd []byte, fence *gpuproto.Fence) error {
	return ErrUnsupported
}

// TestConfinement returns ErrUnsupported on non-darwin hosts.
func (c *Client) TestConfinement(ctx context.Context) (gpuproto.TestConfineReply, error) {
	return gpuproto.TestConfineReply{}, ErrUnsupported
}

// SetEventSink panics with ErrUnsupported on non-darwin hosts.
func (c *Client) SetEventSink(sink gpuproto.EventSink) {
	panic(ErrUnsupported)
}

// Close returns ErrUnsupported on non-darwin hosts.
func (c *Client) Close() error {
	return ErrUnsupported
}

// PID returns 0 on non-darwin hosts.
func (c *Client) PID() int {
	return 0
}

// Build returns an empty string on non-darwin hosts.
func (c *Client) Build() string {
	return ""
}
