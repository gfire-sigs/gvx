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

// This file repeats internal/testdns. The upstream audit forbids imports of
// internal fixtures from the tests of pkg/oci.

package oci

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const (
	dnsHeaderSize = 12
	dnsTypeA      = 1
	dnsClassIN    = 1
	// dnsFlagsResponse is a response with the RD and RA bits set.
	dnsFlagsResponse = 0x8180
	dnsRCodeServFail = 2
	dnsRCodeNXDomain = 3
	// dnsAnswerTTL is the lifetime of an answer in seconds.
	dnsAnswerTTL = 60
)

// testDNS is a DNS server on a loopback UDP port.
type testDNS struct {
	addr    netip.AddrPort
	hosts   map[string]netip.Addr
	rcode   uint16
	queries atomic.Int64
}

// startTestDNS listens on a free UDP port of 127.0.0.1 and answers queries
// until the test ends. An A query for a name in hosts gets the address of the
// name. An A query for another name gets NXDOMAIN. A query of another type
// gets an empty NOERROR answer.
func startTestDNS(t testing.TB, hosts map[string]netip.Addr) *testDNS {
	t.Helper()
	return startTestDNSWithRCode(t, hosts, 0)
}

// startFailingTestDNS listens on a free UDP port of 127.0.0.1 and answers
// every query with SERVFAIL until the test ends.
func startFailingTestDNS(t testing.TB) *testDNS {
	t.Helper()
	return startTestDNSWithRCode(t, nil, dnsRCodeServFail)
}

func startTestDNSWithRCode(t testing.TB, hosts map[string]netip.Addr, rcode uint16) *testDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("test DNS server: listen: %v", err)
	}
	s := &testDNS{addr: pc.LocalAddr().(*net.UDPAddr).AddrPort(), hosts: hosts, rcode: rcode}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			s.queries.Add(1)
			if resp := s.answer(buf[:n]); resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}
	}()
	t.Cleanup(func() {
		_ = pc.Close()
		wg.Wait()
	})
	return s
}

func (s *testDNS) AddrPort() netip.AddrPort { return s.addr }

func (s *testDNS) Queries() int { return int(s.queries.Load()) }

// answer builds the response to one query. It returns nil for a message that
// is not a query with one question.
func (s *testDNS) answer(req []byte) []byte {
	if len(req) < dnsHeaderSize || binary.BigEndian.Uint16(req[4:6]) != 1 {
		return nil
	}
	var labels []string
	off := dnsHeaderSize
	for {
		if off >= len(req) {
			return nil
		}
		n := int(req[off])
		off++
		if n == 0 {
			break
		}
		if n > 63 || off+n > len(req) {
			return nil
		}
		labels = append(labels, string(req[off:off+n]))
		off += n
	}
	if off+4 > len(req) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(req[off : off+2])
	end := off + 4
	name := strings.ToLower(strings.Join(labels, "."))

	flags := uint16(dnsFlagsResponse)
	var rdata []byte
	if s.rcode != 0 {
		flags |= s.rcode
	} else if qtype == dnsTypeA {
		if ip, ok := s.hosts[name]; ok && ip.Is4() {
			a := ip.As4()
			rdata = a[:]
		} else {
			flags |= dnsRCodeNXDomain
		}
	}

	resp := append([]byte(nil), req[0:2]...)
	resp = binary.BigEndian.AppendUint16(resp, flags)
	resp = binary.BigEndian.AppendUint16(resp, 1) // QDCOUNT
	if rdata != nil {
		resp = binary.BigEndian.AppendUint16(resp, 1) // ANCOUNT
	} else {
		resp = binary.BigEndian.AppendUint16(resp, 0)
	}
	resp = append(resp, 0, 0, 0, 0) // NSCOUNT, ARCOUNT
	resp = append(resp, req[dnsHeaderSize:end]...)
	if rdata != nil {
		resp = append(resp, 0xC0, dnsHeaderSize) // pointer to the question name
		resp = binary.BigEndian.AppendUint16(resp, dnsTypeA)
		resp = binary.BigEndian.AppendUint16(resp, dnsClassIN)
		resp = binary.BigEndian.AppendUint32(resp, dnsAnswerTTL)
		resp = binary.BigEndian.AppendUint16(resp, uint16(len(rdata)))
		resp = append(resp, rdata...)
	}
	return resp
}
