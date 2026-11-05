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
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

func newNothing(context.Context, *NewLinkRequest) (stack.LinkEndpoint, *syserr.Error) {
	return nil, syserr.ErrNotSupported
}

func TestRegisterLinkKindRejectsInvalidKinds(t *testing.T) {
	good := LinkKind{NamePrefix: "t", New: newNothing}
	// -count=2 runs the test twice in one process, so the kind leaves with it.
	const kind = "test-kind"
	RegisterLinkKind(kind, good)
	t.Cleanup(func() { delete(linkKinds, kind) })
	for name, tc := range map[string]struct {
		kind string
		k    LinkKind
	}{
		"empty kind":       {"", good},
		"no creator":       {"test-nocreator", LinkKind{NamePrefix: "t"}},
		"no name prefix":   {"test-noprefix", LinkKind{New: newNothing}},
		"kind of the veth": {"veth", good},
		"kind of bridge":   {"bridge", good},
		"duplicate kind":   {kind, good},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("RegisterLinkKind did not panic")
				}
			}()
			RegisterLinkKind(tc.kind, tc.k)
		})
	}
}

func TestNewRegisteredLinkAnswersNotSupportedForAnUnknownKind(t *testing.T) {
	s := &Stack{}
	if err := s.newRegisteredLink(nil, "no-such-kind", false, nil, map[uint16]nlmsg.BytesView{}); err != syserr.ErrNotSupported {
		t.Errorf("newRegisteredLink = %v, want ErrNotSupported", err)
	}
}

// adminEndpoint is a link endpoint with an administrative state. It counts
// the calls and fails LinkUp on demand.
type adminEndpoint struct {
	*channel.Endpoint
	up, down int
	failUp   tcpip.Error
}

func (e *adminEndpoint) LinkUp() tcpip.Error {
	if e.failUp != nil {
		return e.failUp
	}
	e.up++
	return nil
}

func (e *adminEndpoint) LinkDown() { e.down++ }

// registerAdminKind registers a kind with an administrative state and returns
// the stack and the endpoint of a new link of that kind. The NIC is down.
func registerAdminKind(t *testing.T, kind string) (*Stack, *adminEndpoint, tcpip.NICID) {
	t.Helper()
	ep := &adminEndpoint{Endpoint: channel.New(8, 1420, "")}
	RegisterLinkKind(kind, LinkKind{
		NamePrefix:       "ta",
		New:              func(context.Context, *NewLinkRequest) (stack.LinkEndpoint, *syserr.Error) { return ep, nil },
		AdminState:       true,
		Flags:            linux.IFF_POINTOPOINT | linux.IFF_NOARP,
		OperStateUnknown: true,
	})
	t.Cleanup(func() { delete(linkKinds, kind) })
	st := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	t.Cleanup(func() { st.Close(); st.Wait() })
	s := NewStack(st, 1)
	attrs := map[uint16]nlmsg.BytesView{linux.IFLA_IFNAME: nlmsg.BytesView("ta0\x00")}
	if err := s.newRegisteredLink(context.Background(), kind, false, attrs, map[uint16]nlmsg.BytesView{}); err != nil {
		t.Fatalf("newRegisteredLink = %v", err)
	}
	for id, info := range st.NICInfo() {
		if info.Name == "ta0" {
			return s, ep, id
		}
	}
	t.Fatal("the new link is missing")
	return nil, nil, 0
}

func infoOf(t *testing.T, s *Stack, id tcpip.NICID) *stack.NICInfo {
	t.Helper()
	info, ok := s.Stack.SingleNICInfo(id)
	if !ok {
		t.Fatalf("NIC %d is missing", id)
	}
	return info
}

func TestLinkOfAdminKindStartsDownAndReportsItsFlags(t *testing.T) {
	s, ep, id := registerAdminKind(t, "test-admin-flags")
	info := infoOf(t, s, id)
	got := linuxFlags(info)
	if want := uint32(linux.IFF_POINTOPOINT | linux.IFF_NOARP); got != want {
		t.Errorf("flags of the link that is down = %#x, want %#x", got, want)
	}
	if st, ok := LinkOperState(info.Kind, got); !ok || st != linux.IF_OPER_DOWN {
		t.Errorf("operstate while down = %d, %v, want IF_OPER_DOWN", st, ok)
	}
	if ep.up != 0 {
		t.Errorf("LinkUp ran %d times at creation, want 0", ep.up)
	}

	if err := s.setLinkAdminState(context.Background(), id, true); err != nil {
		t.Fatalf("up = %v", err)
	}
	info = infoOf(t, s, id)
	got = linuxFlags(info)
	if want := uint32(linux.IFF_UP | linux.IFF_LOWER_UP | linux.IFF_RUNNING | linux.IFF_POINTOPOINT | linux.IFF_NOARP); got != want {
		t.Errorf("flags of the link that is up = %#x, want %#x", got, want)
	}
	if st, ok := LinkOperState(info.Kind, got); !ok || st != linux.IF_OPER_UNKNOWN {
		t.Errorf("operstate while up = %d, %v, want IF_OPER_UNKNOWN as for a wireguard link", st, ok)
	}
	if ep.up != 1 {
		t.Errorf("LinkUp ran %d times, want 1", ep.up)
	}
	if err := s.setLinkAdminState(context.Background(), id, true); err != nil || ep.up != 1 {
		t.Errorf("a second up = %v with %d calls of LinkUp, want a no-op", err, ep.up)
	}

	if err := s.setLinkAdminState(context.Background(), id, false); err != nil {
		t.Fatalf("down = %v", err)
	}
	if ep.down != 1 || linuxFlags(infoOf(t, s, id))&linux.IFF_UP != 0 {
		t.Errorf("after down LinkDown ran %d times and flags = %#x, want 1 and no IFF_UP", ep.down, linuxFlags(infoOf(t, s, id)))
	}
	if err := s.setLinkAdminState(context.Background(), id, false); err != nil || ep.down != 1 {
		t.Errorf("a second down = %v with %d calls of LinkDown, want a no-op", err, ep.down)
	}
}

func TestFailedLinkUpLeavesTheLinkDown(t *testing.T) {
	s, ep, id := registerAdminKind(t, "test-admin-fail")
	ep.failUp = &tcpip.ErrPortInUse{}
	if err := s.setLinkAdminState(context.Background(), id, true); err != syserr.ErrPortInUse {
		t.Fatalf("up = %v, want EADDRINUSE", err)
	}
	if linuxFlags(infoOf(t, s, id))&linux.IFF_UP != 0 || ep.down != 0 {
		t.Errorf("the link is up after the failure, or LinkDown ran %d times", ep.down)
	}
	ep.failUp = nil
	if err := s.setLinkAdminState(context.Background(), id, true); err != nil || linuxFlags(infoOf(t, s, id))&linux.IFF_UP == 0 {
		t.Errorf("up after the failure = %v, want success", err)
	}
}

func TestRequestedUpFollowsRtnlDevCombineFlags(t *testing.T) {
	for _, tc := range []struct {
		name          string
		flags, change uint32
		up, changed   bool
	}{
		{"ip link set up", linux.IFF_UP, linux.IFF_UP, true, true},
		{"ip link set down", 0, linux.IFF_UP, false, true},
		{"flags without a change mask", linux.IFF_UP, 0, true, true},
		{"nothing", 0, 0, false, false},
		{"a mask without IFF_UP", linux.IFF_UP, linux.IFF_PROMISC, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up, changed := requestedUp(&linux.InterfaceInfoMessage{Flags: tc.flags, Change: tc.change})
			if up != tc.up || changed != tc.changed {
				t.Errorf("requestedUp = %v, %v, want %v, %v", up, changed, tc.up, tc.changed)
			}
		})
	}
}

func TestNewRegisteredLinkStartsUpWhenTheRequestHasIFFUP(t *testing.T) {
	const kind = "test-admin-create"
	ep := &adminEndpoint{Endpoint: channel.New(8, 1420, "")}
	RegisterLinkKind(kind, LinkKind{
		NamePrefix: "tc",
		New:        func(context.Context, *NewLinkRequest) (stack.LinkEndpoint, *syserr.Error) { return ep, nil },
		AdminState: true,
	})
	t.Cleanup(func() { delete(linkKinds, kind) })
	st := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	t.Cleanup(func() { st.Close(); st.Wait() })
	s := NewStack(st, 1)
	if err := s.newRegisteredLink(context.Background(), kind, true, map[uint16]nlmsg.BytesView{}, map[uint16]nlmsg.BytesView{}); err != nil {
		t.Fatalf("newRegisteredLink = %v", err)
	}
	if ep.up != 1 {
		t.Errorf("LinkUp ran %d times for a request with IFF_UP, want 1", ep.up)
	}
}

func TestRemoveRegisteredLinksCallsStackEnded(t *testing.T) {
	const kind = "test-ended"
	var ended []*stack.Stack
	RegisterLinkKind(kind, LinkKind{
		NamePrefix: "te",
		New:        newNothing,
		StackEnded: func(stk *stack.Stack) { ended = append(ended, stk) },
	})
	t.Cleanup(func() { delete(linkKinds, kind) })
	st := stack.New(stack.Options{})
	t.Cleanup(func() { st.Close(); st.Wait() })
	RemoveRegisteredLinks(st)
	if len(ended) != 1 || ended[0] != st {
		t.Errorf("StackEnded ran for %v, want the stack that ended", ended)
	}
}
