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
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// LinkStateListener is the interface of the link endpoint of a kind with
// LinkKind.AdminState. The endpoint opens its resources when the link goes up
// and frees them when the link goes down, as the ndo_open and ndo_stop
// operations of a Linux device do.
//
// The stack calls both methods without a lock of the stack, because a device
// can wait for goroutines that use the stack. A call of LinkUp for a link that
// is up, and a call of LinkDown for a link that is down, change nothing.
type LinkStateListener interface {
	// LinkUp opens the resources. A failure leaves the link down, and the
	// request answers with the error.
	LinkUp() tcpip.Error

	// LinkDown frees the resources. It cannot fail.
	LinkDown()
}

// adminKind returns the registered kind of the NIC, when the kind has an
// administrative state.
func adminKind(kind string) (LinkKind, bool) {
	k, ok := linkKinds[kind]
	return k, ok && k.AdminState
}

// setLinkAdminState brings the registered link id up or down, as the flag
// IFF_UP of "ip link set" does. It does nothing for a link without an
// administrative state, which is always up. The caller holds the link mutex of
// the stack.
func (s *Stack) setLinkAdminState(ctx context.Context, id tcpip.NICID, up bool) *syserr.Error {
	info, ok := s.Stack.SingleNICInfo(id)
	if !ok {
		return syserr.ErrUnknownNICID
	}
	if _, ok := adminKind(info.Kind); !ok {
		return nil
	}
	l, ok := s.Stack.GetLinkEndpointByName(info.Name).(LinkStateListener)
	if !ok {
		return syserr.ErrNotSupported
	}
	if info.Flags.Running == up {
		return nil
	}
	if up {
		if err := l.LinkUp(); err != nil {
			return syserr.TranslateNetstackError(err)
		}
		if err := s.Stack.EnableNIC(id); err != nil {
			l.LinkDown()
			return syserr.TranslateNetstackError(err)
		}
	} else {
		if err := s.Stack.DisableNIC(id); err != nil {
			return syserr.TranslateNetstackError(err)
		}
		l.LinkDown()
	}
	s.sendChangeEvent(ctx, id)
	return nil
}

// disableMovedLink disables the NIC that SetNICStack created for a link that
// moved to this stack, when the kind has an administrative state. SetNICStack
// enables every NIC that it creates, and the link must stay down, as the link
// of Linux does after dev_change_net_namespace.
func (s *Stack) disableMovedLink(id tcpip.NICID, kind string) {
	if _, ok := adminKind(kind); ok {
		s.Stack.DisableNIC(id)
	}
}

// requestedUp reports the state that an RTM_NEWLINK request asks for with
// ifi_flags and ifi_change. The first result is false when the request leaves
// the state as it is. A request with ifi_change 0 takes the whole of ifi_flags,
// as rtnl_dev_combine_flags does, but only when ifi_flags is not 0.
func requestedUp(ifi *linux.InterfaceInfoMessage) (up, change bool) {
	if ifi.Flags == 0 && ifi.Change == 0 {
		return false, false
	}
	if ifi.Change != 0 && ifi.Change&linux.IFF_UP == 0 {
		return false, false
	}
	return ifi.Flags&linux.IFF_UP != 0, true
}

// linuxFlags returns the IFF_* flags of a NIC. A link of a kind with an
// administrative state is up only while its NIC runs. The kind adds its own
// flags.
func linuxFlags(ni *stack.NICInfo) uint32 {
	flags := nicStateFlagsToLinux(ni.Flags)
	k, ok := linkKinds[ni.Kind]
	if !ok {
		return flags
	}
	if k.AdminState && !ni.Flags.Running {
		flags &^= linux.IFF_UP | linux.IFF_LOWER_UP
	}
	return flags | k.Flags
}

// LinkOperState returns the IFLA_OPERSTATE of an interface of the kind with
// the flags. The second result is false when the kind has no rule of its own,
// and the caller then derives the state from IFF_UP.
func LinkOperState(kind string, flags uint32) (uint8, bool) {
	k, ok := linkKinds[kind]
	if !ok || !k.OperStateUnknown {
		return 0, false
	}
	if flags&linux.IFF_UP == 0 {
		return linux.IF_OPER_DOWN, true
	}
	return linux.IF_OPER_UNKNOWN, true
}
