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
	"time"

	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
)

// SetTCPFinTimeout sets how long an orphaned TCP connection stays in FIN-WAIT-2.
// It models net.ipv4.tcp_fin_timeout.
func (s *Stack) SetTCPFinTimeout(d time.Duration) error {
	opt := tcpip.TCPLingerTimeoutOption(d)
	return syserr.TranslateNetstackError(s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)).ToError()
}

// SetTCPAlwaysUseSynCookies makes every SYN get a cookie when always is true.
// Otherwise the stack sends cookies only when the accept queue is full. It
// models net.ipv4.tcp_syncookies at the values 2 and 1.
func (s *Stack) SetTCPAlwaysUseSynCookies(always bool) error {
	opt := tcpip.TCPAlwaysUseSynCookies(always)
	return syserr.TranslateNetstackError(s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)).ToError()
}

// SetTCPKeepaliveDefaults sets the keepalive parameters of new TCP sockets. It
// models net.ipv4.tcp_keepalive_time, tcp_keepalive_intvl, and
// tcp_keepalive_probes.
func (s *Stack) SetTCPKeepaliveDefaults(idle, interval time.Duration, probes int) error {
	opt := tcpip.TCPKeepaliveDefaultsOption{Idle: idle, Interval: interval, Count: probes}
	return syserr.TranslateNetstackError(s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)).ToError()
}
