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

package netbackend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
	"z.gfire.dev/gvx/pkg/waiter"
)

// unansweredTarget is a TEST-NET-1 address. The fake dialers of these tests
// never reach it.
var unansweredTarget = tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: 80}

// errnoDialError returns the error of net.Dialer when the connect system call
// of the host fails with errno.
func errnoDialError(errno syscall.Errno) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
}

// expiredDialError returns the error of a real dial whose deadline passed. The
// dial deadline of net.nat.dial_timeout ends a dial to a host that does not
// answer with this error.
func expiredDialError(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", "192.0.2.1:80")
	if err == nil {
		_ = c.Close()
		t.Fatal("a dial with an expired deadline connected")
	}
	return err
}

// newFailingDialNATStack returns the guest stack of a NAT whose host dials
// fail with the error that fail returns.
func newFailingDialNATStack(t *testing.T, fail func() error) *stack.Stack {
	t.Helper()
	s, nf, err := NewNATStack(NATConfig{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, fail()
		},
	})
	if err != nil {
		t.Fatalf("NewNATStack: %v", err)
	}
	t.Cleanup(func() {
		_ = nf.Close()
		s.Close()
	})
	return s
}

// startGuestConnect starts a connect of a new guest TCP socket of s to dst.
// The socket binds to local first when local is set. The returned channel
// gets a value when the connect ends. The returned function then gives the
// error of the connect, or nil when it connected.
func startGuestConnect(t *testing.T, s *stack.Stack, local tcpip.Address, dst tcpip.FullAddress) (<-chan struct{}, func() tcpip.Error) {
	t.Helper()
	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("create a guest TCP endpoint: %s", err)
	}
	t.Cleanup(ep.Close)
	if local.Len() != 0 {
		if err := ep.Bind(tcpip.FullAddress{Addr: local}); err != nil {
			t.Fatalf("bind the guest TCP endpoint to %v: %s", local, err)
		}
	}
	entry, ended := waiter.NewChannelEntry(waiter.WritableEvents | waiter.EventHUp | waiter.EventErr)
	wq.EventRegister(&entry)
	t.Cleanup(func() { wq.EventUnregister(&entry) })
	if err := ep.Connect(dst); err != nil {
		if _, started := err.(*tcpip.ErrConnectStarted); !started {
			t.Fatalf("connect of the guest to %v: %s", dst, err)
		}
	}
	return ended, ep.LastError
}

// TestNATAnswersFailedHostDialAsTheHost checks that a guest connect through the
// NAT fails with the error class of the host dial (#206). A RST answers a
// refusal and an error of no known class. An unreachable host or network gets
// an ICMP error.
func TestNATAnswersFailedHostDialAsTheHost(t *testing.T) {
	for _, tc := range []struct {
		name    string
		dialErr error
		want    tcpip.Error
	}{
		{name: "refused", dialErr: errnoDialError(hostRefusedErrno), want: &tcpip.ErrConnectionRefused{}},
		{name: "host unreachable", dialErr: errnoDialError(hostUnreachableErrno), want: &tcpip.ErrHostUnreachable{}},
		{name: "host down", dialErr: errnoDialError(hostDownErrno), want: &tcpip.ErrHostUnreachable{}},
		{name: "network unreachable", dialErr: errnoDialError(netUnreachableErrno), want: &tcpip.ErrNetworkUnreachable{}},
		{name: "unclassified errno", dialErr: errnoDialError(hostAccessDeniedErrno), want: &tcpip.ErrConnectionRefused{}},
		{name: "canceled", dialErr: context.Canceled, want: &tcpip.ErrConnectionRefused{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newFailingDialNATStack(t, func() error { return tc.dialErr })
			ended, result := startGuestConnect(t, s, tcpip.Address{}, unansweredTarget)
			select {
			case <-ended:
			case <-time.After(testTimeout):
				t.Fatalf("the guest connect did not end within %v", testTimeout)
			}
			if got := result(); fmt.Sprintf("%T", got) != fmt.Sprintf("%T", tc.want) {
				t.Errorf("guest connect error after host dial error %q = %v (%T), want %T", tc.dialErr, got, got, tc.want)
			}
		})
	}
}

// TestNATLeavesTheSYNOfATimedOutDialUnanswered checks that a host dial that
// times out gives the guest no answer (#206). The guest connect stays open, and
// each retransmitted SYN of the guest starts a new host dial. A third dial
// shows that neither of the first two dials ended the connect. The guest fails
// with ETIMEDOUT when its own SYN timer ends, about 127 seconds after the
// first SYN, and the test does not wait for that.
func TestNATLeavesTheSYNOfATimedOutDialUnanswered(t *testing.T) {
	const wantDials = 3
	for _, tc := range []struct {
		name    string
		dialErr func(*testing.T) error
	}{
		{name: "dial deadline", dialErr: expiredDialError},
		{name: "OS timeout", dialErr: func(*testing.T) error { return errnoDialError(hostTimedOutErrno) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dialErr := tc.dialErr(t)
			var dials atomic.Int32
			redialed := make(chan struct{})
			s := newFailingDialNATStack(t, func() error {
				if dials.Add(1) == wantDials {
					close(redialed)
				}
				return dialErr
			})
			ended, result := startGuestConnect(t, s, tcpip.Address{}, unansweredTarget)
			select {
			case <-redialed:
			case <-ended:
				t.Fatalf("the guest connect ended with %v after %d host dials, want no answer and a new dial for each retransmitted SYN", result(), dials.Load())
			case <-time.After(testTimeout):
				t.Fatalf("%d host dials within %v, want %d", dials.Load(), testTimeout, wantDials)
			}
		})
	}
}

// addSourceNAT makes the guest stack s rewrite the source address from to to
// in its POSTROUTING chain, as the MASQUERADE rule of a container runtime does.
func addSourceNAT(t *testing.T, s *stack.Stack, from, to tcpip.Address) {
	t.Helper()
	table := s.IPTables().GetTable(stack.NATID, false)
	pos := table.BuiltinChains[stack.Postrouting]
	rule := stack.Rule{
		Filter: stack.EmptyFilter4(),
		Target: &stack.SNATTarget{Addr: to, NetworkProtocol: ipv4.ProtocolNumber, ChangeAddress: true},
	}
	rule.Filter.Src = from
	rule.Filter.SrcMask = tcpip.AddrFrom4([4]byte{255, 255, 255, 255})
	table.Rules = slices.Insert(table.Rules, pos, rule)
	for hook := range table.BuiltinChains {
		if table.BuiltinChains[hook] != stack.HookUnset && table.BuiltinChains[hook] > pos {
			table.BuiltinChains[hook]++
		}
		if table.Underflows[hook] != stack.HookUnset && table.Underflows[hook] >= pos {
			table.Underflows[hook]++
		}
	}
	s.IPTables().ForceReplaceTable(stack.NATID, table, false)
}

// TestNATUnreachableAnswerReachesASocketBehindGuestNAT checks the ICMP answer
// through the connection tracker of the guest (#206). A container connects from
// its own address, and the iptables NAT of the guest rewrites the source to
// 10.0.2.15, as in a docker build. The tracker translates the ICMP error back
// to the container only when the quote holds the full TCP header of the SYN.
func TestNATUnreachableAnswerReachesASocketBehindGuestNAT(t *testing.T) {
	s := newFailingDialNATStack(t, func() error { return errnoDialError(hostUnreachableErrno) })
	container := tcpip.AddrFrom4([4]byte{172, 17, 0, 2})
	containerAddr := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: container.WithPrefix()}
	if err := s.AddProtocolAddress(Eth0NICID, containerAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("add %v to eth0: %s", container, err)
	}
	addSourceNAT(t, s, container, tcpip.AddrFrom4([4]byte{10, 0, 2, 15}))

	ended, result := startGuestConnect(t, s, container, unansweredTarget)
	select {
	case <-ended:
	case <-time.After(testTimeout):
		t.Fatalf("the connect from %v behind the guest NAT did not end within %v, want an ICMP host unreachable", container, testTimeout)
	}
	if got := result(); fmt.Sprintf("%T", got) != fmt.Sprintf("%T", &tcpip.ErrHostUnreachable{}) {
		t.Errorf("connect error from %v behind the guest NAT = %v (%T), want %T", container, got, got, &tcpip.ErrHostUnreachable{})
	}
}

// TestClassifyDialErrorOfRealRefusal checks the classifier with the error that
// the Go runtime of the host returns for a refused connect. The test fails
// when the error chain or the errno family of the host differs from the
// values that the other tests give, such as a Win32 code in place of a WSAE
// code on Windows.
func TestClassifyDialErrorOfRealRefusal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close the listener: %v", err)
	}
	c, err := (&net.Dialer{Timeout: testTimeout}).Dial("tcp", addr)
	if err == nil {
		_ = c.Close()
		t.Fatalf("a dial to the closed port %s connected", addr)
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) || errno != hostRefusedErrno {
		t.Fatalf("refused dial error = %v (errno %d), want errno %d", err, errno, hostRefusedErrno)
	}
	if got := classifyDialError(err); got != answerReset {
		t.Errorf("classifyDialError(%v) = %v, want %v", err, got, answerReset)
	}
}
