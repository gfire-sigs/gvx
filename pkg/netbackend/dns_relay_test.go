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
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

// buildDNSQuery returns a standard query with recursion desired.
func buildDNSQuery(id uint16, name string, qtype uint16) []byte {
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0x00, byte(qtype>>8), byte(qtype), 0x00, dnsClassIN)
}

func dnsRCode(resp []byte) uint16 { return binary.BigEndian.Uint16(resp[2:4]) & dnsRCodeMask }

// answerIPs returns the A and AAAA addresses in the answer section of a
// response that uses name compression only for the owner name.
func answerIPs(t *testing.T, resp []byte) []netip.Addr {
	t.Helper()
	if len(resp) < dnsHeaderSize {
		t.Fatalf("short DNS response: %x", resp)
	}
	q, err := parseDNSQuestion(resp, dnsHeaderSize)
	if err != nil {
		t.Fatalf("parse response question: %v", err)
	}
	off := q.endOff
	var out []netip.Addr
	for range binary.BigEndian.Uint16(resp[6:8]) {
		off += 2 + 2 + 2 + 4 // name pointer, type, class, TTL
		rdLen := int(binary.BigEndian.Uint16(resp[off : off+2]))
		off += 2
		addr, ok := netip.AddrFromSlice(resp[off : off+rdLen])
		if !ok {
			t.Fatalf("bad RDATA length %d", rdLen)
		}
		out = append(out, addr)
		off += rdLen
	}
	return out
}

// fakeDNSServer is an upstream resolver on loopback. Its handler decides the
// answer for each query.
type fakeDNSServer struct {
	addr    string
	queries atomic.Int32
}

type dnsHandler func(req []byte, viaTCP bool) []byte

// startFakeDNSServer listens on UDP and TCP at one loopback port. A handler
// result of nil sends no answer.
func startFakeDNSServer(t *testing.T, handler dnsHandler) *fakeDNSServer {
	t.Helper()
	var (
		pc  net.PacketConn
		ln  net.Listener
		err error
	)
	// The UDP and TCP sockets must share a port. Listen on TCP first so the OS
	// skips any Windows TCP excluded port ranges, then bind UDP to that port.
	for range 50 {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		pc, err = net.ListenPacket("udp", ln.Addr().String())
		if err == nil {
			break
		}
		_ = ln.Close()
	}
	if err != nil {
		t.Fatalf("no port is free for both UDP and TCP: %v", err)
	}
	srv := &fakeDNSServer{addr: pc.LocalAddr().String()}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			srv.queries.Add(1)
			if resp := handler(append([]byte(nil), buf[:n]...), false); resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				req := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				srv.queries.Add(1)
				resp := handler(req, true)
				if resp == nil {
					return
				}
				out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
				_, _ = c.Write(append(out, resp...))
			}()
		}
	}()
	t.Cleanup(func() {
		_ = pc.Close()
		_ = ln.Close()
		wg.Wait()
	})
	return srv
}

// answerWith returns a handler that answers every A query with ip.
func answerWith(ip string) dnsHandler {
	return func(req []byte, _ bool) []byte {
		q, err := parseDNSQuestion(req, dnsHeaderSize)
		if err != nil {
			return nil
		}
		return buildDNSAddressResponse(binary.BigEndian.Uint16(req[0:2]), binary.BigEndian.Uint16(req[2:4]),
			req[dnsHeaderSize:q.endOff], q.qtype, []netip.Addr{netip.MustParseAddr(ip)})
	}
}

// rcodeResponse returns a handler that answers every query with rcode.
func rcodeResponse(rcode uint16) dnsHandler {
	return func(req []byte, _ bool) []byte {
		q, err := parseDNSQuestion(req, dnsHeaderSize)
		if err != nil {
			return nil
		}
		return buildDNSErrorResponse(binary.BigEndian.Uint16(req[0:2]), binary.BigEndian.Uint16(req[2:4]), req[dnsHeaderSize:q.endOff], rcode)
	}
}

// newTestForwarder returns a NATForwarder whose relay uses only the given upstream servers.
func newTestForwarder(t *testing.T, cfg NATConfig, upstream ...string) *NATForwarder {
	t.Helper()
	s, nf, err := NewNATStack(cfg)
	if err != nil {
		t.Fatalf("NewNATStack: %v", err)
	}
	t.Cleanup(func() {
		_ = nf.Close()
		s.Close()
	})
	// NewNATStack reads the host resolver configuration when cfg has no
	// servers. Tests replace it so they never depend on the host.
	nf.upstreamDNS = upstream
	return nf
}

func TestDNSRelayForwardsQueriesToHostServers(t *testing.T) {
	srv := startFakeDNSServer(t, answerWith("198.51.100.7"))
	nf := newTestForwarder(t, NATConfig{}, srv.addr)

	resp := nf.handleDNSQuery(t.Context(), buildDNSQuery(0xabcd, "example.test", dnsTypeA))
	if binary.BigEndian.Uint16(resp[0:2]) != 0xabcd || dnsRCode(resp) != dnsRCodeNoErr {
		t.Fatalf("response header = %x, want ID 0xabcd and NOERROR", resp[:dnsHeaderSize])
	}
	if got := answerIPs(t, resp); len(got) != 1 || got[0] != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("answer = %v, want [198.51.100.7]", got)
	}
	if srv.queries.Load() != 1 {
		t.Fatalf("upstream saw %d queries, want 1", srv.queries.Load())
	}
}

func TestDNSRelayForwardsNonAddressQueriesUnchanged(t *testing.T) {
	var got atomic.Value
	srv := startFakeDNSServer(t, func(req []byte, _ bool) []byte {
		got.Store(append([]byte(nil), req...))
		return rcodeResponse(dnsRCodeNoErr)(req, false)
	})
	nf := newTestForwarder(t, NATConfig{}, srv.addr)

	const typeTXT = 16
	req := buildDNSQuery(7, "txt.example.test", typeTXT)
	resp := nf.handleDNSQuery(t.Context(), req)
	if dnsRCode(resp) != dnsRCodeNoErr {
		t.Fatalf("response rcode = %d, want NOERROR", dnsRCode(resp))
	}
	if forwarded, _ := got.Load().([]byte); string(forwarded) != string(req) {
		t.Fatalf("upstream received %x, want the guest query %x", forwarded, req)
	}
}

func TestDNSRelayAnswersSERVFAILWithoutHostServers(t *testing.T) {
	nf := newTestForwarder(t, NATConfig{})
	req := buildDNSQuery(0x1111, "example.test", dnsTypeA)
	resp := nf.handleDNSQuery(t.Context(), req)
	if binary.BigEndian.Uint16(resp[0:2]) != 0x1111 {
		t.Fatalf("transaction ID = %x, want 1111", resp[0:2])
	}
	if flags := binary.BigEndian.Uint16(resp[2:4]); flags&dnsFlagQR == 0 || dnsRCode(resp) != dnsRCodeSrv {
		t.Fatalf("flags = %#x, want a response with SERVFAIL", flags)
	}
	if binary.BigEndian.Uint16(resp[4:6]) != 1 || string(resp[dnsHeaderSize:]) != string(req[dnsHeaderSize:]) {
		t.Fatalf("response does not echo the question: %x", resp)
	}

	if _, err := nf.forwardRawDNSUpstream(t.Context(), req); !errors.Is(err, errNoDNSServers) {
		t.Fatalf("forwardRawDNSUpstream = %v, want errNoDNSServers", err)
	}
}

func TestDNSRelayTriesNextServerAfterFailure(t *testing.T) {
	deadServer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := deadServer.LocalAddr().String()
	_ = deadServer.Close() // Nothing listens here, so the first server fails.

	servfail := startFakeDNSServer(t, rcodeResponse(dnsRCodeSrv))
	refused := startFakeDNSServer(t, rcodeResponse(dnsRCodeRefus))
	good := startFakeDNSServer(t, answerWith("203.0.113.9"))
	nf := newTestForwarder(t, NATConfig{}, deadAddr, servfail.addr, refused.addr, good.addr)

	resp := nf.handleDNSQuery(t.Context(), buildDNSQuery(5, "example.test", dnsTypeA))
	if dnsRCode(resp) != dnsRCodeNoErr {
		t.Fatalf("rcode = %d, want NOERROR from the last server", dnsRCode(resp))
	}
	if got := answerIPs(t, resp); len(got) != 1 || got[0] != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("answer = %v, want [203.0.113.9]", got)
	}
	if servfail.queries.Load() != 1 || refused.queries.Load() != 1 {
		t.Fatalf("failing servers saw %d and %d queries, want 1 each", servfail.queries.Load(), refused.queries.Load())
	}
}

func TestDNSRelayAnswersSERVFAILWhenEveryServerFails(t *testing.T) {
	a := startFakeDNSServer(t, rcodeResponse(dnsRCodeSrv))
	b := startFakeDNSServer(t, rcodeResponse(dnsRCodeRefus))
	nf := newTestForwarder(t, NATConfig{}, a.addr, b.addr)
	resp := nf.handleDNSQuery(t.Context(), buildDNSQuery(5, "example.test", dnsTypeA))
	if dnsRCode(resp) != dnsRCodeSrv {
		t.Fatalf("rcode = %d, want SERVFAIL", dnsRCode(resp))
	}
}

func TestDNSRelayPassesNXDOMAINFromUpstream(t *testing.T) {
	srv := startFakeDNSServer(t, rcodeResponse(dnsRCodeNX))
	nf := newTestForwarder(t, NATConfig{}, srv.addr)
	resp := nf.handleDNSQuery(t.Context(), buildDNSQuery(5, "missing.test", dnsTypeA))
	if dnsRCode(resp) != dnsRCodeNX {
		t.Fatalf("rcode = %d, want NXDOMAIN", dnsRCode(resp))
	}
	if srv.queries.Load() != 1 {
		t.Fatalf("upstream saw %d queries, want 1: a name error ends the search", srv.queries.Load())
	}
}

func TestDNSRelayRetriesTruncatedAnswerOverTCP(t *testing.T) {
	var tcpQueries atomic.Int32
	srv := startFakeDNSServer(t, func(req []byte, viaTCP bool) []byte {
		if !viaTCP {
			resp := answerWith("192.0.2.1")(req, false)
			binary.BigEndian.PutUint16(resp[2:4], binary.BigEndian.Uint16(resp[2:4])|dnsFlagTC)
			return resp
		}
		tcpQueries.Add(1)
		return answerWith("192.0.2.200")(req, true)
	})
	nf := newTestForwarder(t, NATConfig{}, srv.addr)
	resp := nf.handleDNSQuery(t.Context(), buildDNSQuery(5, "big.test", dnsTypeA))
	if got := answerIPs(t, resp); len(got) != 1 || got[0] != netip.MustParseAddr("192.0.2.200") {
		t.Fatalf("answer = %v, want the TCP answer 192.0.2.200", got)
	}
	if tcpQueries.Load() != 1 {
		t.Fatalf("TCP queries = %d, want 1", tcpQueries.Load())
	}
}

func TestDNSRelayIgnoresAnswersWithWrongTransactionID(t *testing.T) {
	// A dedicated server sends a spoofed answer first, then the right one.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		req := buf[:n]
		spoof := answerWith("6.6.6.6")(req, false)
		binary.BigEndian.PutUint16(spoof[0:2], binary.BigEndian.Uint16(req[0:2])+1)
		_, _ = pc.WriteTo(spoof, from)
		_, _ = pc.WriteTo(answerWith("192.0.2.55")(req, false), from)
	}()
	nf := newTestForwarder(t, NATConfig{}, pc.LocalAddr().String())
	resp := nf.handleDNSQuery(t.Context(), buildDNSQuery(0x4242, "example.test", dnsTypeA))
	if got := answerIPs(t, resp); len(got) != 1 || got[0] != netip.MustParseAddr("192.0.2.55") {
		t.Fatalf("answer = %v, want the answer with the matching ID", got)
	}
}

func TestDNSRelayAnswersOwnNamesWithoutUpstream(t *testing.T) {
	srv := startFakeDNSServer(t, answerWith("198.51.100.99"))
	nf := newTestForwarder(t, NATConfig{}, srv.addr)
	tests := []struct {
		name  string
		qtype uint16
		want  []string
	}{
		{"localhost", dnsTypeA, []string{"127.0.0.1"}},
		{"localhost", dnsTypeAAAA, []string{"::1"}},
		{"LOCALHOST.", dnsTypeA, []string{"127.0.0.1"}},
		{"host.docker.internal", dnsTypeA, []string{HostGatewayIPv4}},
		{"gateway.docker.internal", dnsTypeA, []string{HostGatewayIPv4}},
		{"host.docker.internal", dnsTypeAAAA, nil},
		{"gvx", dnsTypeA, []string{DefaultGuestIPv4}},
	}
	for _, tt := range tests {
		resp := nf.handleDNSQuery(t.Context(), buildDNSQuery(9, tt.name, tt.qtype))
		if dnsRCode(resp) != dnsRCodeNoErr {
			t.Fatalf("%s type %d: rcode = %d, want NOERROR", tt.name, tt.qtype, dnsRCode(resp))
		}
		var got []string
		for _, a := range answerIPs(t, resp) {
			got = append(got, a.String())
		}
		if strings.Join(got, ",") != strings.Join(tt.want, ",") {
			t.Fatalf("%s type %d: answer = %v, want %v", tt.name, tt.qtype, got, tt.want)
		}
	}
	if srv.queries.Load() != 0 {
		t.Fatalf("upstream saw %d queries for relay-owned names, want 0", srv.queries.Load())
	}

	isolated := newTestForwarder(t, NATConfig{IsolateLAN: true}, srv.addr)
	resp := isolated.handleDNSQuery(t.Context(), buildDNSQuery(9, "host.docker.internal", dnsTypeA))
	if dnsRCode(resp) != dnsRCodeNX {
		t.Fatalf("host.docker.internal under IsolateLAN: rcode = %d, want NXDOMAIN", dnsRCode(resp))
	}
}

func TestDNSRelayLookupHook(t *testing.T) {
	srv := startFakeDNSServer(t, answerWith("198.51.100.1"))
	nf := newTestForwarder(t, NATConfig{
		LookupHost: func(_ context.Context, host string) ([]netip.Addr, error) {
			switch host {
			case "hook.test":
				return []netip.Addr{netip.MustParseAddr("192.0.2.77")}, nil
			case "absent.test":
				return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
			}
			return nil, errors.New("resolver unavailable")
		},
	}, srv.addr)

	resp := nf.handleDNSQuery(t.Context(), buildDNSQuery(1, "hook.test", dnsTypeA))
	if got := answerIPs(t, resp); len(got) != 1 || got[0] != netip.MustParseAddr("192.0.2.77") {
		t.Fatalf("hook answer = %v", got)
	}
	if resp := nf.handleDNSQuery(t.Context(), buildDNSQuery(2, "absent.test", dnsTypeA)); dnsRCode(resp) != dnsRCodeNX {
		t.Fatalf("absent name: rcode = %d, want NXDOMAIN", dnsRCode(resp))
	}
	if srv.queries.Load() != 0 {
		t.Fatalf("upstream saw %d queries although the hook answered", srv.queries.Load())
	}
	// A hook error that is not a name error falls back to the host servers.
	resp = nf.handleDNSQuery(t.Context(), buildDNSQuery(3, "broken.test", dnsTypeA))
	if got := answerIPs(t, resp); len(got) != 1 || got[0] != netip.MustParseAddr("198.51.100.1") {
		t.Fatalf("fallback answer = %v, want the upstream answer", got)
	}
	// The hook serves only A and AAAA. Other types go to the host servers.
	if resp := nf.handleDNSQuery(t.Context(), buildDNSQuery(4, "hook.test", 16)); srv.queries.Load() != 2 || dnsRCode(resp) != dnsRCodeNoErr {
		t.Fatalf("TXT query: upstream queries = %d, rcode = %d, want 2 and NOERROR", srv.queries.Load(), dnsRCode(resp))
	}
}

func TestDNSRelayRejectsMalformedQueries(t *testing.T) {
	nf := newTestForwarder(t, NATConfig{})
	if resp := nf.handleDNSQuery(t.Context(), []byte{1, 2, 3}); resp != nil {
		t.Fatalf("short message answered with %x, want no answer", resp)
	}
	noQuestion := []byte{0, 9, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if resp := nf.handleDNSQuery(t.Context(), noQuestion); dnsRCode(resp) != dnsRCodeFmt {
		t.Fatalf("query without question: rcode = %d, want FORMERR", dnsRCode(resp))
	}
	truncated := append([]byte{0, 9, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 5, 'a', 'b')
	if resp := nf.handleDNSQuery(t.Context(), truncated); dnsRCode(resp) != dnsRCodeFmt {
		t.Fatalf("truncated question: rcode = %d, want FORMERR", dnsRCode(resp))
	}
	compressed := append([]byte{0, 9, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 0xc0, 0x0c, 0, 1, 0, 1)
	if resp := nf.handleDNSQuery(t.Context(), compressed); dnsRCode(resp) != dnsRCodeFmt {
		t.Fatalf("compressed question: rcode = %d, want FORMERR", dnsRCode(resp))
	}
}

func TestDNSRelayStopsWaitingWhenContextEnds(t *testing.T) {
	// The upstream reads queries and never answers.
	received := make(chan struct{}, 4)
	silent := startFakeDNSServer(t, func([]byte, bool) []byte {
		received <- struct{}{}
		return nil
	})
	nf := newTestForwarder(t, NATConfig{}, silent.addr)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan []byte, 1)
	go func() { done <- nf.handleDNSQuery(ctx, buildDNSQuery(1, "slow.test", dnsTypeA)) }()
	// The upstream saw the query, so the relay now waits for an answer.
	select {
	case <-received:
	case <-time.After(testTimeout):
		t.Fatal("upstream never received the query")
	}
	cancel()
	select {
	case resp := <-done:
		if dnsRCode(resp) != dnsRCodeSrv {
			t.Fatalf("rcode = %d, want SERVFAIL after cancellation", dnsRCode(resp))
		}
	case <-time.After(dnsUpstreamTimeout / 2):
		t.Fatal("relay kept waiting for the upstream after the context ended")
	}
}

func TestNATDNSRelayEndToEndThroughGuestSockets(t *testing.T) {
	srv := startFakeDNSServer(t, answerWith("198.51.100.42"))
	s, nf, err := NewNATStack(NATConfig{DNSServers: []string{srv.addr}})
	if err != nil {
		t.Fatalf("NewNATStack: %v", err)
	}
	defer func() {
		_ = nf.Close()
		s.Close()
	}()
	dns := tcpip.FullAddress{NIC: Eth0NICID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 3}), Port: 53}
	query := buildDNSQuery(0x7777, "service.example.test", dnsTypeA)

	u, err := gonet.DialUDP(s, nil, &dns, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if _, err := u.Write(query); err != nil {
		t.Fatal(err)
	}
	if err := u.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := u.Read(buf)
	if err != nil {
		t.Fatalf("UDP DNS read: %v", err)
	}
	if got := answerIPs(t, buf[:n]); len(got) != 1 || got[0] != netip.MustParseAddr("198.51.100.42") {
		t.Fatalf("UDP answer = %v", got)
	}

	c, err := gonet.DialTCP(s, dns, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if _, err := c.Write(append(framed, query...)); err != nil {
		t.Fatal(err)
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	if got := answerIPs(t, resp); len(got) != 1 || got[0] != netip.MustParseAddr("198.51.100.42") {
		t.Fatalf("TCP answer = %v", got)
	}
}
