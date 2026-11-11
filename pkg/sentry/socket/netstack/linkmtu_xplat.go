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

package netstack

import (
	goContext "context"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/ethernet"
	"z.gfire.dev/gvx/pkg/tcpip/link/packetsocket"
	"z.gfire.dev/gvx/pkg/tcpip/link/veth"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const (
	// ethernetMinMTU is the smallest MTU that a Linux Ethernet link accepts
	// (ETH_MIN_MTU), which is the IPv4 minimum of RFC 791.
	ethernetMinMTU = header.IPv4MinimumMTU
	// ethernetMaxMTU is the largest MTU of a Linux veth or bridge link
	// (ETH_MAX_MTU), which is the largest IPv4 packet.
	ethernetMaxMTU = 65535
)

// vethLink is the link end that the Ethernet wrapper of a veth link sits on.
// It embeds the veth endpoint, so the link keeps every method of the endpoint,
// among them the GSO methods that TCP uses to send large segments.
//
// The two ends of a Linux veth pair have one MTU each. The veth endpoint keeps
// one MTU for both ends, so the link keeps its own MTU and hides the one of the
// endpoint. The pair carries Ethernet frames, so the MTU of the link counts the
// 14 bytes of the Ethernet header. The wrapper above reports the MTU without
// them, as Linux does for the MTU of a link. A change of the MTU through
// netlink or ioctl must add the header again, or the link would read 14 bytes
// less than the value that the guest set.
//
// +stateify savable
type vethLink struct {
	*veth.Endpoint
	mtu atomicbitops.Uint32
}

// newVethLink returns the link of one end of a veth pair. The link starts with
// the MTU mtu, which does not count the Ethernet header.
func newVethLink(end *veth.Endpoint, mtu uint32) *vethLink {
	l := &vethLink{Endpoint: end}
	l.SetMTU(mtu)
	return l
}

// MTU implements stack.LinkEndpoint.MTU. It counts the Ethernet header.
func (l *vethLink) MTU() uint32 {
	return l.mtu.Load()
}

// SetMTU implements stack.LinkEndpoint.SetMTU. It takes the MTU without the
// Ethernet header.
func (l *vethLink) SetMTU(mtu uint32) {
	l.mtu.Store(mtu + header.EthernetMinimumSize)
}

func (l *vethLink) afterLoad(goContext.Context) {
	if l.Endpoint != nil {
		l.Endpoint.Restore()
	}
}

// newVethNICEndpoint returns the link endpoint that a NIC for one end of a
// veth pair uses.
func newVethNICEndpoint(end *veth.Endpoint) stack.LinkEndpoint {
	return newHostFilterEndpoint(packetsocket.New(ethernet.New(newVethLink(end, defaultMTU))))
}

// setInterfaceMTUIoctl implements the SIOCSIFMTU ioctl, which busybox
// "ifconfig eth0 mtu N" and busybox "ip link set dev eth0 mtu N" send. The
// request follows the rules of the netlink request IFLA_MTU: the caller needs
// CAP_NET_ADMIN in the user namespace of the network namespace, and the MTU
// must lie in the range of the link.
func setInterfaceMTUIoctl(ctx context.Context, t *kernel.Task, ifr *linux.IFReq) *syserr.Error {
	if !t.NetworkNamespace().HasCapability(ctx, linux.CAP_NET_ADMIN) {
		return syserr.ErrNotPermittedNet
	}
	stk, ok := inet.StackFromContext(ctx).(*Stack)
	if !ok {
		return syserr.ErrNoDevice
	}
	// ifr_mtu is an int. Linux refuses a negative value as below the minimum.
	mtu := int32(hostarch.ByteOrder.Uint32(ifr.Data[:4]))
	if mtu < 0 {
		return syserr.ErrInvalidArgument
	}
	return stk.setLinkMTUByName(ctx, ifr.Name(), uint32(mtu))
}

// setLinkMTUByName changes the MTU of the link that has the given name, and
// sends the change event, as a netlink change of the MTU does.
func (s *Stack) setLinkMTUByName(ctx context.Context, name string, mtu uint32) *syserr.Error {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()

	for id, info := range s.Stack.NICInfo() {
		if info.Name != name {
			continue
		}
		if info.MTU == mtu {
			return nil
		}
		if err := s.Stack.SetNICMTU(id, mtu); err != nil {
			return syserr.TranslateNetstackError(err)
		}
		s.sendChangeEvent(ctx, id)
		return nil
	}
	return syserr.ErrNoDevice
}
