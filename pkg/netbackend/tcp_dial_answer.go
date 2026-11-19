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
	"errors"
	"syscall"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/checksum"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
)

// dialAnswer is the answer of the NAT to a guest SYN when the host dial for
// that SYN fails. Each answer gives the guest connect the errno that a Linux
// host gets for the same failure.
type dialAnswer int

const (
	// answerReset sends a RST, so the guest connect fails with ECONNREFUSED.
	answerReset dialAnswer = iota
	// answerNone drops the SYN. The guest sends the SYN again, and each new
	// SYN starts a new host dial. The guest connect fails with ETIMEDOUT when
	// the SYN retries of the guest end.
	answerNone
	// answerHostUnreachable sends an ICMPv4 host unreachable message, so the
	// guest connect fails with EHOSTUNREACH.
	answerHostUnreachable
	// answerNetUnreachable sends an ICMPv4 network unreachable message, so the
	// guest connect fails with ENETUNREACH.
	answerNetUnreachable
)

// String implements fmt.Stringer for log records.
func (a dialAnswer) String() string {
	switch a {
	case answerNone:
		return "none"
	case answerHostUnreachable:
		return "host-unreachable"
	case answerNetUnreachable:
		return "network-unreachable"
	default:
		return "reset"
	}
}

// icmpCode returns the ICMPv4 destination unreachable code of a. It reports
// false when a sends no ICMP message.
func (a dialAnswer) icmpCode() (header.ICMPv4Code, bool) {
	switch a {
	case answerHostUnreachable:
		return header.ICMPv4HostUnreachable, true
	case answerNetUnreachable:
		return header.ICMPv4NetUnreachable, true
	default:
		return 0, false
	}
}

// classifyDialError selects the answer to a guest SYN from the error of its
// host dial. An errno in the chain of err decides the answer. Windows returns
// WSAE codes that the syscall constants do not match, so dialErrnoAnswer has
// one file for each OS family. A deadline error without an errno is a
// timeout. Every other error, such as a canceled context, gets a RST.
func classifyDialError(err error) dialAnswer {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return dialErrnoAnswer(errno)
	}
	if isTimeout(err) {
		return answerNone
	}
	return answerReset
}

// answerFailedDial completes r after its host dial to targetAddr failed with
// err. It sends the ICMP message of the answer before it completes r, so a
// retransmitted SYN cannot start a new dial before the guest gets the error.
// When the message cannot be sent, the SYN gets no answer.
func (nf *NATForwarder) answerFailedDial(r *tcp.ForwarderRequest, targetAddr string, err error) {
	answer := classifyDialError(err)
	if code, ok := answer.icmpCode(); ok && !nf.sendDestinationUnreachable(r.ID(), code) {
		answer = answerNone
	}
	nf.log.Debug("netbackend: dial host TCP target", "target", targetAddr, "error", err, "answer", answer.String())
	r.Complete(answer == answerReset)
}

// sendDestinationUnreachable sends an ICMPv4 destination unreachable message
// with code for the guest SYN of id. The message comes from the gateway
// 10.0.2.2, as a router sends it, and goes through the host stack to eth0 of
// the guest. It quotes the IPv4 header and the TCP header of the SYN, which it
// builds again from id. RFC 792 asks for 8 bytes of the TCP header, but the
// connection tracker of the guest reads the full 20 bytes to translate the
// error back to a socket behind the iptables NAT of the guest. Netstack and
// the tracker match the quote by its addresses and ports, so the sequence
// number in the quote is 0. The method reports false when id is not IPv4 or
// the host stack does not take the message.
func (nf *NATForwarder) sendDestinationUnreachable(id stack.TransportEndpointID, code header.ICMPv4Code) bool {
	if id.LocalAddress.Len() != header.IPv4AddressSize || id.RemoteAddress.Len() != header.IPv4AddressSize {
		return false
	}
	const quoteLen = header.IPv4MinimumSize + header.TCPMinimumSize
	const totalLen = header.IPv4MinimumSize + header.ICMPv4MinimumSize + quoteLen
	pkt := make([]byte, totalLen)

	outer := header.IPv4(pkt)
	outer.Encode(&header.IPv4Fields{
		TotalLength: totalLen,
		TTL:         defaultTTL,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4([4]byte{10, 0, 2, 2}),
		DstAddr:     id.RemoteAddress,
	})
	outer.SetChecksum(^outer.CalculateChecksum())

	icmpHdr := header.ICMPv4(pkt[header.IPv4MinimumSize:])
	icmpHdr.SetType(header.ICMPv4DstUnreachable)
	icmpHdr.SetCode(code)

	quote := pkt[header.IPv4MinimumSize+header.ICMPv4MinimumSize:]
	quotedIP := header.IPv4(quote)
	quotedIP.Encode(&header.IPv4Fields{
		TotalLength: quoteLen,
		TTL:         defaultTTL,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     id.RemoteAddress,
		DstAddr:     id.LocalAddress,
	})
	quotedIP.SetChecksum(^quotedIP.CalculateChecksum())
	header.TCP(quote[header.IPv4MinimumSize:]).Encode(&header.TCPFields{
		SrcPort:    id.RemotePort,
		DstPort:    id.LocalPort,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
	})

	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], checksum.Checksum(quote, 0)))

	if err := nf.stack.WriteRawPacket(hostNICID, ipv4.ProtocolNumber, buffer.MakeWithData(pkt)); err != nil {
		nf.log.Debug("netbackend: send ICMP destination unreachable to the guest", "code", code, "error", err)
		return false
	}
	return true
}
