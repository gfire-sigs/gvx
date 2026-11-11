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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const (
	// DefaultDNSPort is the standard UDP and TCP port for the virtual DNS relay.
	DefaultDNSPort = 53

	dnsHeaderSize = 12
	dnsTypeA      = 1
	dnsTypeAAAA   = 28
	dnsClassIN    = 1

	dnsFlagQR     = 1 << 15
	dnsFlagAA     = 1 << 10
	dnsFlagTC     = 1 << 9
	dnsFlagRD     = 1 << 8
	dnsFlagRA     = 1 << 7
	dnsRCodeMask  = 0xf
	dnsRCodeNoErr = 0
	dnsRCodeFmt   = 1
	dnsRCodeSrv   = 2
	dnsRCodeNX    = 3
	dnsRCodeRefus = 5

	defaultDNSTTL = 60

	// maxDNSMessage is the largest DNS message that a UDP or TCP exchange carries.
	maxDNSMessage = 65535

	// maxDNSNameWireLen is the RFC 1035 maximum wire length of a domain name,
	// including label length octets and the terminating root octet.
	maxDNSNameWireLen = 255

	// maxConcurrentDNS bounds concurrent in-flight DNS queries per endpoint.
	maxConcurrentDNS = 64
)

// errNoDNSServers reports that the host has no resolver to forward a query to.
var errNoDNSServers = errors.New("netbackend: no host DNS servers are configured")

var (
	dnsGatewayAddr = netip.MustParseAddr(HostGatewayIPv4)
	dnsGuestAddr   = netip.MustParseAddr(DefaultGuestIPv4)
)

type dnsQuestion struct {
	name   string
	qtype  uint16
	qclass uint16
	endOff int
}

func (nf *NATForwarder) dnsSemaphore() chan struct{} {
	nf.mu.Lock()
	defer nf.mu.Unlock()
	if nf.dnsSem == nil {
		nf.dnsSem = make(chan struct{}, maxConcurrentDNS)
	}
	return nf.dnsSem
}

func (w *WireGuardEndpoint) dnsSemaphore() chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dnsSem == nil {
		w.dnsSem = make(chan struct{}, maxConcurrentDNS)
	}
	return w.dnsSem
}

func (nf *NATForwarder) serveUDPDNS(ctx context.Context, conn net.Conn) {
	timeout := nf.cfg.Tuning.Duration(tuning.DNSTimeout)
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	var connWG sync.WaitGroup
	defer func() {
		connWG.Wait()
		stop()
		_ = conn.Close()
	}()

	sem := nf.dnsSemaphore()
	var writeMu sync.Mutex
	buf := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		req := append([]byte(nil), buf[:n]...)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		connWG.Add(1)
		go func(pkt []byte) {
			defer func() {
				<-sem
				connWG.Done()
			}()
			resp := nf.dnsRelay().answerQuery(ctx, pkt)
			if len(resp) == 0 {
				return
			}
			writeMu.Lock()
			_ = conn.SetWriteDeadline(time.Now().Add(timeout))
			if _, err := conn.Write(resp); err != nil {
				nf.log.Debug("netbackend: write DNS response to guest", "error", err)
			}
			_ = conn.SetWriteDeadline(time.Time{})
			writeMu.Unlock()
		}(req)
	}
}

func (nf *NATForwarder) serveTCPDNS(ctx context.Context, conn net.Conn) {
	serveTCPDNSConn(ctx, conn, nf.cfg.Tuning.Duration(tuning.DNSTimeout), nf.handleDNSQuery)
}

func serveTCPDNSConn(ctx context.Context, conn net.Conn, timeout time.Duration, answer func(context.Context, []byte) []byte) {
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stop()
	defer func() {
		_ = conn.Close()
	}()
	var lenBuf [2]byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if msgLen == 0 {
			return
		}
		req := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}
		resp := answer(ctx, req)
		if len(resp) == 0 {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[0:2], uint16(len(resp)))
		copy(out[2:], resp)
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

type dnsRelay struct {
	gvxAddrs   []netip.Addr
	hasGateway bool
	isolateLAN bool
	lookupHost func(ctx context.Context, host string) ([]netip.Addr, error)
	servers    []string
	dials      []func(ctx context.Context, network, addr string) (net.Conn, error)
	log        *slog.Logger
	tune       tuning.Values
}

func (nf *NATForwarder) dnsRelay() dnsRelay {
	dialFn := nf.cfg.DialContext
	if dialFn == nil {
		var d net.Dialer
		dialFn = d.DialContext
	}
	return dnsRelay{
		gvxAddrs:   []netip.Addr{netip.MustParseAddr(DefaultGuestIPv4)},
		hasGateway: true,
		isolateLAN: nf.cfg.IsolateLAN,
		lookupHost: nf.cfg.LookupHost,
		servers:    nf.upstreamDNS,
		dials:      []func(context.Context, string, string) (net.Conn, error){dialFn},
		log:        nf.log,
		tune:       nf.cfg.Tuning,
	}
}

func (w *WireGuardEndpoint) dnsRelay(log *slog.Logger) dnsRelay {
	gvxAddrs := []netip.Addr{w.cfg.GuestIPv4.Addr()}
	if w.cfg.GuestIPv6.IsValid() {
		gvxAddrs = append(gvxAddrs, w.cfg.GuestIPv6.Addr())
	}
	stackDial := func(dctx context.Context, network, server string) (net.Conn, error) {
		return dialStackDNS(dctx, w.stack, network, server)
	}
	var hostDialer net.Dialer
	dials := []func(context.Context, string, string) (net.Conn, error){
		hostDialer.DialContext,
		stackDial,
	}
	if len(w.cfg.DNSServers) > 0 {
		// Explicit WireGuard DNS servers travel inside the tunnel first.
		dials[0], dials[1] = stackDial, hostDialer.DialContext
	}
	return dnsRelay{
		gvxAddrs:   gvxAddrs,
		lookupHost: w.cfg.LookupHost,
		servers:    w.upstreamDNS,
		dials:      dials,
		log:        log,
		tune:       w.cfg.Tuning,
	}
}

// handleDNSQuery answers one DNS message. The relay owns a few names and
// resolves A and AAAA queries through the LookupHost hook. It forwards every
// other query to the host DNS servers and answers SERVFAIL when none replies.
func (nf *NATForwarder) handleDNSQuery(ctx context.Context, req []byte) []byte {
	sem := nf.dnsSemaphore()
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		return nil
	}
	return nf.dnsRelay().answerQuery(ctx, req)
}

// forwardRawDNSUpstream sends the wire query to each host DNS server in turn
// and returns the first usable answer. A server that fails, answers SERVFAIL,
// or answers REFUSED does not stop the search.
func (nf *NATForwarder) forwardRawDNSUpstream(ctx context.Context, req []byte) ([]byte, error) {
	return nf.dnsRelay().forwardRawUpstream(ctx, req)
}

func (r dnsRelay) answerQuery(ctx context.Context, req []byte) []byte {
	if len(req) < dnsHeaderSize {
		return nil
	}
	txID := binary.BigEndian.Uint16(req[0:2])
	reqFlags := binary.BigEndian.Uint16(req[2:4])
	qdCount := binary.BigEndian.Uint16(req[4:6])
	if qdCount == 0 {
		return buildDNSErrorResponse(txID, reqFlags, nil, dnsRCodeFmt)
	}

	q, err := parseDNSQuestion(req, dnsHeaderSize)
	if err != nil {
		return buildDNSErrorResponse(txID, reqFlags, nil, dnsRCodeFmt)
	}
	rawQuestion := req[dnsHeaderSize:q.endOff]

	if q.qclass == dnsClassIN && (q.qtype == dnsTypeA || q.qtype == dnsTypeAAAA) {
		addrs, found, handled, lookupErr := r.lookupLocalAddrs(ctx, q.name)
		if lookupErr != nil && r.log != nil {
			r.log.Debug("netbackend: DNS lookup hook failed", "name", q.name, "error", lookupErr)
		}
		if handled {
			if !found {
				return buildDNSErrorResponse(txID, reqFlags, rawQuestion, dnsRCodeNX)
			}
			return buildDNSAddressResponse(txID, reqFlags, rawQuestion, q.qtype, addrs)
		}
	}

	resp, err := r.forwardRawUpstream(ctx, req)
	if err != nil {
		if r.log != nil {
			r.log.Debug("netbackend: forward DNS query", "name", q.name, "error", err)
		}
		return buildDNSErrorResponse(txID, reqFlags, rawQuestion, dnsRCodeSrv)
	}
	return resp
}

// lookupLocalAddrs resolves the names that the relay answers without an
// upstream server. handled is false when the relay must forward the query.
// found is false for a name that does not exist.
func (r dnsRelay) lookupLocalAddrs(ctx context.Context, qname string) (addrs []netip.Addr, found, handled bool, err error) {
	clean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qname)), ".")
	switch clean {
	case "localhost", "localhost.localdomain":
		return []netip.Addr{
			netip.MustParseAddr("127.0.0.1"),
			netip.MustParseAddr("::1"),
		}, true, true, nil
	case "host.docker.internal", "gateway.docker.internal":
		if r.hasGateway {
			if r.isolateLAN {
				return nil, false, true, nil
			}
			return []netip.Addr{netip.MustParseAddr(HostGatewayIPv4)}, true, true, nil
		}
	case "gvx":
		return r.gvxAddrs, true, true, nil
	}

	if r.lookupHost == nil {
		return nil, false, false, nil
	}
	rctx, cancel := context.WithTimeout(ctx, r.tune.Duration(tuning.DNSTimeout))
	defer cancel()

	addrs, err = r.lookupHost(rctx, clean)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, false, true, nil
		}
		return nil, false, false, err
	}
	if r.isolateLAN {
		filtered := make([]netip.Addr, 0, len(addrs))
		for _, addr := range addrs {
			if !isBlockedHostAddr(addr) {
				filtered = append(filtered, addr)
			}
		}
		addrs = filtered
	}
	return addrs, true, true, nil
}

// isBlockedHostAddr reports whether addr targets a host loopback, unspecified,
// private, link-local, multicast, guest, or gateway address that IsolateLAN
// forbids reaching.
func isBlockedHostAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	ip := addr.Unmap()
	return ip == dnsGatewayAddr ||
		ip == dnsGuestAddr ||
		ip.IsLoopback() ||
		ip.IsUnspecified() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast()
}

func randomDNSTxID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

func (r dnsRelay) forwardRawUpstream(ctx context.Context, req []byte) ([]byte, error) {
	if len(r.servers) == 0 {
		return nil, errNoDNSServers
	}
	if len(req) < dnsHeaderSize || binary.BigEndian.Uint16(req[4:6]) == 0 {
		return nil, errors.New("netbackend: invalid DNS query header")
	}
	wantQ, err := parseDNSQuestion(req, dnsHeaderSize)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, server := range r.servers {
		for _, dial := range r.dials {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			resp, err := exchangeDNSWithDial(ctx, dial, "udp", server, req, wantQ, r.tune.Duration(tuning.DNSUpstreamTimeout))
			if err == nil && binary.BigEndian.Uint16(resp[2:4])&dnsFlagTC != 0 {
				resp, err = exchangeDNSWithDial(ctx, dial, "tcp", server, req, wantQ, r.tune.Duration(tuning.DNSUpstreamTimeout))
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("server %s: %w", server, err))
				continue
			}
			switch binary.BigEndian.Uint16(resp[2:4]) & dnsRCodeMask {
			case dnsRCodeSrv, dnsRCodeRefus:
				errs = append(errs, fmt.Errorf("server %s: rcode %d", server, binary.BigEndian.Uint16(resp[2:4])&dnsRCodeMask))
				continue
			}
			return resp, nil
		}
	}
	return nil, fmt.Errorf("netbackend: all upstream DNS servers failed: %w", errors.Join(errs...))
}

func exchangeDNSWithDial(ctx context.Context, dial func(ctx context.Context, network, address string) (net.Conn, error), network, server string, req []byte, wantQ dnsQuestion, timeout time.Duration) ([]byte, error) {
	guestTxID := binary.BigEndian.Uint16(req[0:2])
	upstreamTxID, err := randomDNSTxID()
	if err != nil {
		return nil, err
	}
	upstreamReq := append([]byte(nil), req...)
	binary.BigEndian.PutUint16(upstreamReq[0:2], upstreamTxID)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dial(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// The deadline also bounds the read and write calls below.
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if network == "tcp" {
		framed := make([]byte, 2+len(upstreamReq))
		binary.BigEndian.PutUint16(framed[0:2], uint16(len(upstreamReq)))
		copy(framed[2:], upstreamReq)
		if _, err := conn.Write(framed); err != nil {
			return nil, err
		}
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, err
		}
		if !validDNSResponse(resp, upstreamTxID, wantQ) {
			return nil, errors.New("invalid DNS response")
		}
		binary.BigEndian.PutUint16(resp[0:2], guestTxID)
		return resp, nil
	}

	if _, err := conn.Write(upstreamReq); err != nil {
		return nil, err
	}
	buf := make([]byte, maxDNSMessage)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		// A connected UDP socket accepts datagrams from the server only. The
		// ID and question checks drop late or mismatched answers on a reused port.
		if validDNSResponse(buf[:n], upstreamTxID, wantQ) {
			resp := append([]byte(nil), buf[:n]...)
			binary.BigEndian.PutUint16(resp[0:2], guestTxID)
			return resp, nil
		}
	}
}

// dialStackDNS opens a UDP or TCP connection to server through s on Eth0NICID.
func dialStackDNS(ctx context.Context, s *stack.Stack, network, server string) (net.Conn, error) {
	ap, err := parseDNSServerAddrPort(server)
	if err != nil {
		return nil, err
	}
	addr := ap.Addr().Unmap()
	full := tcpip.FullAddress{
		NIC:  Eth0NICID,
		Port: ap.Port(),
	}
	proto := ipv4.ProtocolNumber
	if addr.Is6() {
		full.Addr = tcpip.AddrFrom16(addr.As16())
		proto = ipv6.ProtocolNumber
	} else {
		full.Addr = tcpip.AddrFrom4(addr.As4())
	}
	if network == "tcp" {
		return gonet.DialContextTCP(ctx, s, full, proto)
	}
	return gonet.DialUDP(s, nil, &full, proto)
}

func parseDNSServerAddrPort(server string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(server); err == nil {
		return ap, nil
	}
	if ip, err := netip.ParseAddr(server); err == nil {
		return netip.AddrPortFrom(ip.Unmap(), DefaultDNSPort), nil
	}
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	var port uint16 = DefaultDNSPort
	if p, err := net.LookupPort("udp", portStr); err == nil && p > 0 && p <= 65535 {
		port = uint16(p)
	}
	return netip.AddrPortFrom(ip.Unmap(), port), nil
}

// ParseDNSServers converts bare IP strings or "ip:port" strings into
// addresses. A bare IP uses DefaultDNSPort. It skips empty entries and
// rejects every other entry that is not an IP address with an optional port.
func ParseDNSServers(raw []string) ([]netip.AddrPort, error) {
	return parseDNSServers(raw, false)
}

// parseDNSServers is ParseDNSServers. Non-IP tokens (such as search domains
// in wg-quick DNS = lines) are skipped when skipInvalid is true.
func parseDNSServers(raw []string, skipInvalid bool) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	for _, item := range raw {
		s := strings.TrimSpace(item)
		if s == "" {
			continue
		}
		ap, err := parseDNSServerAddrPort(s)
		if err != nil {
			if skipInvalid {
				continue
			}
			return nil, fmt.Errorf("invalid DNS server %q: %w", s, err)
		}
		out = append(out, ap)
	}
	return out, nil
}

// normalizeDNSServers converts bare IP strings or host:port strings into
// canonical ip:port entries. Non-IP tokens (such as search domains in wg-quick
// DNS = lines) are skipped when skipInvalid is true.
func normalizeDNSServers(raw []string, skipInvalid bool) ([]string, error) {
	parsed, err := parseDNSServers(raw, skipInvalid)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ap := range parsed {
		out = append(out, ap.String())
	}
	return out, nil
}

func (w *WireGuardEndpoint) serveUDPDNS(ctx context.Context, conn *gonet.UDPConn, log *slog.Logger) {
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer func() {
		stop()
		_ = conn.Close()
	}()

	sem := w.dnsSemaphore()
	var writeMu sync.Mutex
	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		req := append([]byte(nil), buf[:n]...)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		w.dnsWG.Add(1)
		go func(pkt []byte, peer net.Addr) {
			defer func() {
				<-sem
				w.dnsWG.Done()
			}()
			resp := w.dnsRelay(log).answerQuery(ctx, pkt)
			if len(resp) > 0 {
				writeMu.Lock()
				_ = conn.SetWriteDeadline(time.Now().Add(w.cfg.Tuning.Duration(tuning.DNSTimeout)))
				_, _ = conn.WriteTo(resp, peer)
				_ = conn.SetWriteDeadline(time.Time{})
				writeMu.Unlock()
			}
		}(req, addr)
	}
}

func (w *WireGuardEndpoint) serveTCPDNSListener(ctx context.Context, ln *gonet.TCPListener, log *slog.Logger) {
	stop := context.AfterFunc(ctx, func() {
		_ = ln.Close()
	})
	defer stop()

	sem := w.dnsSemaphore()
	answer := func(qctx context.Context, req []byte) []byte {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		case <-qctx.Done():
			return nil
		}
		return w.dnsRelay(log).answerQuery(qctx, req)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		w.dnsWG.Add(1)
		go func(c net.Conn) {
			defer w.dnsWG.Done()
			serveTCPDNSConn(ctx, c, w.cfg.Tuning.Duration(tuning.DNSTimeout), answer)
		}(conn)
	}
}

func validDNSResponse(msg []byte, txID uint16, wantQ dnsQuestion) bool {
	if len(msg) < dnsHeaderSize ||
		binary.BigEndian.Uint16(msg[0:2]) != txID ||
		binary.BigEndian.Uint16(msg[2:4])&dnsFlagQR == 0 ||
		binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return false
	}
	gotQ, err := parseDNSQuestion(msg, dnsHeaderSize)
	if err != nil {
		return false
	}
	return strings.EqualFold(gotQ.name, wantQ.name) &&
		gotQ.qtype == wantQ.qtype &&
		gotQ.qclass == wantQ.qclass
}

func parseDNSQuestion(msg []byte, offset int) (dnsQuestion, error) {
	var labels []string
	cur := offset
	for {
		if cur >= len(msg) {
			return dnsQuestion{}, errors.New("truncated DNS label")
		}
		length := int(msg[cur])
		cur++
		if cur-offset > maxDNSNameWireLen {
			return dnsQuestion{}, errors.New("DNS name exceeds 255 bytes")
		}
		if length == 0 {
			break
		}
		if (length & 0xc0) != 0 {
			return dnsQuestion{}, errors.New("compressed label in question not supported")
		}
		if cur+length > len(msg) {
			return dnsQuestion{}, errors.New("DNS label exceeds packet")
		}
		if cur+length-offset > maxDNSNameWireLen {
			return dnsQuestion{}, errors.New("DNS name exceeds 255 bytes")
		}
		labels = append(labels, string(msg[cur:cur+length]))
		cur += length
	}
	if cur+4 > len(msg) {
		return dnsQuestion{}, errors.New("truncated DNS question fields")
	}
	qtype := binary.BigEndian.Uint16(msg[cur : cur+2])
	qclass := binary.BigEndian.Uint16(msg[cur+2 : cur+4])
	cur += 4
	return dnsQuestion{
		name:   strings.Join(labels, "."),
		qtype:  qtype,
		qclass: qclass,
		endOff: cur,
	}, nil
}

func buildDNSErrorResponse(txID, reqFlags uint16, rawQuestion []byte, rcode uint16) []byte {
	resp := make([]byte, dnsHeaderSize+len(rawQuestion))
	binary.BigEndian.PutUint16(resp[0:2], txID)
	flags := uint16(dnsFlagQR | dnsFlagRA | (reqFlags & dnsFlagRD) | (rcode & 0xf))
	binary.BigEndian.PutUint16(resp[2:4], flags)
	if len(rawQuestion) > 0 {
		binary.BigEndian.PutUint16(resp[4:6], 1)
		copy(resp[dnsHeaderSize:], rawQuestion)
	}
	return resp
}

func buildDNSAddressResponse(txID, reqFlags uint16, rawQuestion []byte, qtype uint16, addrs []netip.Addr) []byte {
	var matched []netip.Addr
	for _, a := range addrs {
		unmapped := a.Unmap()
		if qtype == dnsTypeA && unmapped.Is4() {
			matched = append(matched, unmapped)
		} else if qtype == dnsTypeAAAA && unmapped.Is6() {
			matched = append(matched, unmapped)
		}
	}

	out := make([]byte, dnsHeaderSize, dnsHeaderSize+len(rawQuestion)+len(matched)*28)
	binary.BigEndian.PutUint16(out[0:2], txID)
	flags := uint16(dnsFlagQR | dnsFlagAA | dnsFlagRA | (reqFlags & dnsFlagRD) | dnsRCodeNoErr)
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(out[6:8], uint16(len(matched)))
	out = append(out, rawQuestion...)

	for _, addr := range matched {
		// Pointer to QNAME at offset 12 (0xc00c).
		var rrHdr [12]byte
		binary.BigEndian.PutUint16(rrHdr[0:2], 0xc00c)
		binary.BigEndian.PutUint16(rrHdr[2:4], qtype)
		binary.BigEndian.PutUint16(rrHdr[4:6], dnsClassIN)
		binary.BigEndian.PutUint32(rrHdr[6:10], defaultDNSTTL)
		rawIP := addr.AsSlice()
		binary.BigEndian.PutUint16(rrHdr[10:12], uint16(len(rawIP)))
		out = append(out, rrHdr[:]...)
		out = append(out, rawIP...)
	}
	return out
}
