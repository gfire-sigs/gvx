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

// Package testdns runs a DNS server on a loopback UDP port for tests. The
// server answers A queries from a fixed table. It needs no host resolver
// configuration, so a test uses it to prove which server a client queries.
package testdns

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
	headerSize = 12
	typeA      = 1
	classIN    = 1
	// flagsResponse is a response with the RD and RA bits set.
	flagsResponse = 0x8180
	rcodeNXDomain = 3
	// answerTTL is the lifetime of an answer in seconds.
	answerTTL = 60
)

// Server answers DNS queries over UDP.
type Server struct {
	addr    netip.AddrPort
	hosts   map[string]netip.Addr
	queries atomic.Int64
}

// Start listens on a free UDP port of 127.0.0.1 and answers queries until the
// test ends. An A query for a name in hosts gets the address of the name. An
// A query for another name gets NXDOMAIN. A query of another type gets an
// empty NOERROR answer. Names are lowercase without the final dot.
func Start(t testing.TB, hosts map[string]netip.Addr) *Server {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("testdns: listen: %v", err)
	}
	s := &Server{addr: pc.LocalAddr().(*net.UDPAddr).AddrPort(), hosts: hosts}
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

// AddrPort returns the UDP address of the server.
func (s *Server) AddrPort() netip.AddrPort { return s.addr }

// Queries returns the count of queries that the server has received.
func (s *Server) Queries() int { return int(s.queries.Load()) }

// answer builds the response to one query. It returns nil for a message that
// is not a query with one question.
func (s *Server) answer(req []byte) []byte {
	if len(req) < headerSize || binary.BigEndian.Uint16(req[4:6]) != 1 {
		return nil
	}
	var labels []string
	off := headerSize
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

	flags := uint16(flagsResponse)
	var rdata []byte
	if qtype == typeA {
		if ip, ok := s.hosts[name]; ok && ip.Is4() {
			a := ip.As4()
			rdata = a[:]
		} else {
			flags |= rcodeNXDomain
		}
	}

	resp := make([]byte, 0, end+16)
	resp = append(resp, req[0:2]...)
	resp = binary.BigEndian.AppendUint16(resp, flags)
	resp = binary.BigEndian.AppendUint16(resp, 1) // QDCOUNT
	if rdata != nil {
		resp = binary.BigEndian.AppendUint16(resp, 1) // ANCOUNT
	} else {
		resp = binary.BigEndian.AppendUint16(resp, 0)
	}
	resp = append(resp, 0, 0, 0, 0) // NSCOUNT, ARCOUNT
	resp = append(resp, req[headerSize:end]...)
	if rdata != nil {
		resp = append(resp, 0xC0, headerSize) // pointer to the question name
		resp = binary.BigEndian.AppendUint16(resp, typeA)
		resp = binary.BigEndian.AppendUint16(resp, classIN)
		resp = binary.BigEndian.AppendUint32(resp, answerTTL)
		resp = binary.BigEndian.AppendUint16(resp, uint16(len(rdata)))
		resp = append(resp, rdata...)
	}
	return resp
}
