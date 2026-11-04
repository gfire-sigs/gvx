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

package wireguard

import (
	"errors"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// newLink creates the link endpoint and the wireguard-go device of a new
// "wireguard" link. The device starts up, so it owns a UDP port at once. On
// Linux the port appears when the link goes up, but a netstack link has no
// down state.
func newLink(_ context.Context, req *netstack.NewLinkRequest) (stack.LinkEndpoint, *syserr.Error) {
	ch := channel.New(queueSize, defaultMTU, "")
	tunDev := newTUN(ch, req.Name)
	ep := &linkEndpoint{Endpoint: ch, tun: tunDev}
	ep.dev = device.NewDevice(tunDev, newBind(req.Stack.Stack), newLogger(req.Name))
	if err := ep.dev.Up(); err != nil {
		ep.Close()
		return nil, bindSyserr(err)
	}
	return ep, nil
}

// bindSyserr returns the errno of an error from wireguard-go. An error of the
// UDP bind keeps its own errno.
func bindSyserr(err error) *syserr.Error {
	var be *bindError
	if errors.As(err, &be) {
		return be.err
	}
	var ie *device.IPCError
	if errors.As(err, &ie) {
		switch ie.ErrorCode() {
		case ipc.IpcErrorPortInUse:
			return syserr.ErrPortInUse
		case ipc.IpcErrorIO:
			return syserr.ErrIO
		}
	}
	return syserr.ErrInvalidArgument
}
