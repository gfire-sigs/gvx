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
func (s *Stack) newRegisteredLink(ctx context.Context, kind string, linkAttrs, linkInfoAttrs map[uint16]nlmsg.BytesView) *syserr.Error {
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
	if err := s.Stack.CreateNICWithOptions(id, ep, stack.NICOptions{Name: ifname, Kind: kind}); err != nil {
		ep.Close()
		return syserr.TranslateNetstackError(err)
	}
	if err := s.setLinkLocked(ctx, id, linkAttrs, dstNs); err != nil {
		s.Stack.RemoveNIC(id)
		return err
	}
	return nil
}
