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

package route

import (
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
)

// nested returns the attribute of the type, with or without NLA_F_NESTED.
func nested(attrs map[uint16]nlmsg.BytesView, typ uint16) (nlmsg.BytesView, bool) {
	if v, ok := attrs[typ]; ok {
		return v, true
	}
	v, ok := attrs[typ|linux.NLA_F_NESTED]
	return v, ok
}

// changeLinkInfo answers a request that changes an existing link with
// IFLA_INFO_DATA, as "ip link set vxlan1 type vxlan ..." does. The link kinds
// of the registry apply the data with their Change function, or answer
// EOPNOTSUPP. Without this call the request would succeed and change nothing.
// A request that creates a link, or has no IFLA_INFO_DATA, passes.
func changeLinkInfo(ctx context.Context, s *netlink.Socket, msg *nlmsg.Message) *syserr.Error {
	if msg.Header().Flags&linux.NLM_F_CREATE != 0 {
		return nil
	}
	st, ok := s.Stack().(*netstack.Stack)
	if !ok {
		return nil
	}
	var ifi linux.InterfaceInfoMessage
	view, ok := msg.GetData(&ifi)
	if !ok {
		return nil
	}
	attrs, ok := view.Parse()
	if !ok {
		return nil
	}
	linkInfo, ok := nested(attrs, linux.IFLA_LINKINFO)
	if !ok {
		return nil
	}
	info, ok := nlmsg.AttrsView(linkInfo).Parse()
	if !ok {
		return nil
	}
	raw, ok := nested(info, linux.IFLA_INFO_DATA)
	if !ok {
		return nil
	}
	data, ok := nlmsg.AttrsView(raw).Parse()
	if !ok {
		return syserr.ErrInvalidArgument
	}
	id := tcpip.NICID(ifi.Index)
	if id == 0 {
		name, ok := attrs[linux.IFLA_IFNAME]
		if !ok {
			return nil
		}
		for nic, nicInfo := range st.Stack.NICInfo() {
			if nicInfo.Name == name.String() {
				id = nic
			}
		}
	}
	if id == 0 {
		return nil
	}
	return st.ChangeRegisteredLink(ctx, id, data)
}
