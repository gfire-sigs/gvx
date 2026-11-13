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
	"fmt"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// NewLinkRequest describes one RTM_NEWLINK request for a registered link kind.
type NewLinkRequest struct {
	// Stack is the network stack that receives the request. A link that opens
	// sockets keeps them in this stack, also after it moves to another
	// network namespace.
	Stack *Stack

	// ID is the interface index of the new link.
	ID tcpip.NICID

	// Name is the interface name of the new link.
	Name string

	// UserNS is the user namespace of the network namespace of the calling
	// task. A link that keeps sockets in Stack checks the CAP_NET_ADMIN of a
	// later caller against it, as Linux checks the creating namespace. It is
	// nil when the context has no task.
	UserNS *auth.UserNamespace

	// Data holds the attributes of IFLA_INFO_DATA. It is nil when the request
	// has none.
	Data map[uint16]nlmsg.BytesView
}

// LinkKind creates the links of one kind that RTM_NEWLINK names with
// IFLA_INFO_KIND.
type LinkKind struct {
	// NamePrefix starts the generated name of a link that the request does
	// not name. The stack appends the first free index.
	NamePrefix string

	// New returns the link endpoint of the new link. The stack holds its link
	// mutex during the call. The stack closes the endpoint when it removes
	// the link, and also when the creation fails after New returned.
	New func(ctx context.Context, req *NewLinkRequest) (stack.LinkEndpoint, *syserr.Error)

	// MTURange returns the smallest and the largest MTU that a later change of
	// the MTU accepts for the endpoint that New returned. A zero bound means no
	// bound. It is optional.
	MTURange func(ep stack.LinkEndpoint) (min, max uint32)

	// AdminState makes the link follow IFF_UP, as a Linux device with an
	// ndo_open operation does. The link starts down, "ip link set up" calls
	// LinkUp of the endpoint that New returned, and "ip link set down" calls
	// LinkDown. The endpoint MUST implement LinkStateListener. A link without
	// AdminState is always up, as the other links of the stack are.
	AdminState bool

	// Flags are the IFF_* flags that the device sets in dev->flags at setup and
	// that the stack does not report. The kind of wireguard sets IFF_POINTOPOINT
	// and IFF_NOARP.
	Flags uint32

	// NoLinkLayer marks a link of type ARPHRD_NONE, such as wireguard. Linux
	// reports no IFLA_ADDRESS and an empty sysfs address for it. Another link
	// with that type, such as eth0 of the NAT link, keeps a zero address.
	NoLinkLayer bool

	// OperStateUnknown makes the link report IF_OPER_UNKNOWN, and not
	// IF_OPER_UP, while it is up. A Linux device that never calls
	// netif_carrier_off or netif_dormant_on has that operstate.
	OperStateUnknown bool

	// StackEnded runs when the network stack stk ends, after the stack removed
	// the links that it holds. A kind whose links keep resources in the stack
	// of their creation, also after they moved to another network namespace,
	// frees the resources of the links that stk created. It is optional.
	StackEnded func(stk *stack.Stack)

	// Change applies the IFLA_INFO_DATA of an RTM_NEWLINK request to an existing
	// link of the kind. It is optional. A kind without it answers EOPNOTSUPP,
	// as a Linux link kind without a changelink operation does.
	Change func(ctx context.Context, ep stack.LinkEndpoint, data map[uint16]nlmsg.BytesView) *syserr.Error
}

// linkKinds maps each IFLA_INFO_KIND value to its creator. Registration runs
// in init functions, so the map needs no lock.
var linkKinds = map[string]LinkKind{}

// RegisterLinkKind registers the creator of the link kind. A kind that the
// stack creates itself ("bridge" and "veth") cannot be registered.
//
// Preconditions: RegisterLinkKind runs before any sandbox starts, in an init
// function. The kind is not registered yet.
func RegisterLinkKind(kind string, k LinkKind) {
	if kind == "" || k.New == nil || k.NamePrefix == "" {
		panic("netstack: link kind needs a name, a name prefix, and a New function")
	}
	switch kind {
	case "bridge", "veth":
		panic(fmt.Sprintf("netstack: link kind %q belongs to the stack", kind))
	}
	if _, ok := linkKinds[kind]; ok {
		panic(fmt.Sprintf("netstack: link kind %q is already registered", kind))
	}
	linkKinds[kind] = k
}

// newRegisteredLink creates a link of a kind that RegisterLinkKind added. It
// answers EOPNOTSUPP for an unknown kind, as the stack did before the
// registry existed.
//
// up is true when the request has IFF_UP, as "ip link add wg0 up type wireguard"
// sends. A kind with AdminState starts down otherwise.
func (s *Stack) newRegisteredLink(ctx context.Context, kind string, up bool, linkAttrs, linkInfoAttrs map[uint16]nlmsg.BytesView) *syserr.Error {
	k, ok := linkKinds[kind]
	if !ok {
		return syserr.ErrNotSupported
	}
	var data map[uint16]nlmsg.BytesView
	if v, ok := linkInfoAttrs[linux.IFLA_INFO_DATA]; ok {
		data, ok = nlmsg.AttrsView(v).Parse()
		if !ok {
			return syserr.ErrInvalidArgument
		}
	}

	dstNs, sysErr := s.lockSrcAndDst(ctx, linkAttrs)
	if sysErr != nil {
		return sysErr
	}
	defer s.unlockSrcAndDst(ctx, dstNs)

	ifname := ""
	if v, ok := linkAttrs[linux.IFLA_IFNAME]; ok {
		ifname = v.String()
	}
	if ifname == "" {
		ifname = s.allocDeviceName(k.NamePrefix, dstNs)
	}
	var userNS *auth.UserNamespace
	if t := kernel.TaskFromContext(ctx); t != nil {
		userNS = t.NetworkNamespace().UserNamespace()
	}
	id := s.Stack.NextNICID()
	ep, sysErr := k.New(ctx, &NewLinkRequest{Stack: s, ID: id, Name: ifname, Data: data, UserNS: userNS})
	if sysErr != nil {
		return sysErr
	}
	opts := stack.NICOptions{Name: ifname, Kind: kind, Disabled: k.AdminState}
	if k.MTURange != nil {
		opts.MinMTU, opts.MaxMTU = k.MTURange(ep)
	}
	if err := s.Stack.CreateNICWithOptions(id, ep, opts); err != nil {
		ep.Close()
		return syserr.TranslateNetstackError(err)
	}
	if up && k.AdminState {
		if err := s.setLinkAdminState(ctx, id, true); err != nil {
			s.Stack.RemoveNIC(id)
			return err
		}
	}
	if err := s.setLinkLocked(ctx, id, linkAttrs, 0 /* flags */, 0 /* change */, dstNs); err != nil {
		s.Stack.RemoveNIC(id)
		return err
	}
	return nil
}

// ChangeRegisteredLink applies the IFLA_INFO_DATA of a request that changes an
// existing link. It does nothing for a link that no registered kind created. A
// registered kind without a Change function answers EOPNOTSUPP, so the request
// does not report success for a change that it drops.
func (s *Stack) ChangeRegisteredLink(ctx context.Context, id tcpip.NICID, data map[uint16]nlmsg.BytesView) *syserr.Error {
	info, ok := s.Stack.SingleNICInfo(id)
	if !ok {
		return nil
	}
	k, ok := linkKinds[info.Kind]
	if !ok {
		return nil
	}
	if k.Change == nil {
		return syserr.ErrNotSupported
	}
	return k.Change(ctx, s.Stack.GetLinkEndpointByName(info.Name), data)
}

// RemoveRegisteredLinks removes every link of stk that a registered kind
// created, so that the link endpoint closes. Stack.Close does not close link
// endpoints. A wireguard link would keep its device goroutines and its UDP
// sockets after the network stack ends.
func RemoveRegisteredLinks(stk *stack.Stack) {
	for id, info := range stk.NICInfo() {
		if _, ok := linkKinds[info.Kind]; ok {
			stk.RemoveNIC(id)
		}
	}
	for _, k := range linkKinds {
		if k.StackEnded != nil {
			k.StackEnded(stk)
		}
	}
}
