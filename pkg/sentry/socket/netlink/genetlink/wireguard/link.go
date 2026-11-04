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
	"sync"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const (
	// maxLinks is the largest count of wireguard links in one sandbox. A
	// device runs one goroutine for each CPU for each of three workers, and it
	// owns two UDP endpoints.
	maxLinks = 256

	// maxPeers is the largest count of peers of one device. A peer owns
	// timers and goroutines. A dump of more than about 1,100 peers is larger
	// than the receive queue of a netlink socket, so it fails with ENOBUFS.
	maxPeers = 4096
)

// linkCounts counts the live wireguard links of each kernel, so that one
// sandbox cannot exhaust the host. A sandbox is one kernel.
var linkCounts struct {
	sync.Mutex
	n map[*kernel.Kernel]int
}

// acquireLink counts one more link of the kernel. It reports false at the limit.
func acquireLink(k *kernel.Kernel) bool {
	linkCounts.Lock()
	defer linkCounts.Unlock()
	if linkCounts.n[k] >= maxLinks {
		return false
	}
	if linkCounts.n == nil {
		linkCounts.n = make(map[*kernel.Kernel]int)
	}
	linkCounts.n[k]++
	return true
}

// releaseLink counts one link of the kernel less.
func releaseLink(k *kernel.Kernel) {
	linkCounts.Lock()
	defer linkCounts.Unlock()
	if linkCounts.n[k]--; linkCounts.n[k] <= 0 {
		delete(linkCounts.n, k)
	}
}

// newLink creates the link endpoint and the wireguard-go device of a new
// "wireguard" link. The device starts up, so it owns a UDP port at once. On
// Linux the port appears when the link goes up, but a netstack link has no
// down state. It fails with ENOMEM beyond maxLinks links in one sandbox.
func newLink(ctx context.Context, req *netstack.NewLinkRequest) (stack.LinkEndpoint, *syserr.Error) {
	var k *kernel.Kernel
	if t := kernel.TaskFromContext(ctx); t != nil {
		k = t.Kernel()
	}
	if !acquireLink(k) {
		return nil, syserr.ErrNoMemory
	}
	ch := channel.New(queueSize, defaultMTU, "")
	tunDev := newTUN(ch, req.Name)
	bind := newBind(req.Stack.Stack)
	ep := &linkEndpoint{Endpoint: ch, tun: tunDev, bind: bind, userNS: req.UserNS, kernel: k}
	ep.dev = device.NewDevice(tunDev, bind, newLogger(req.Name))
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
