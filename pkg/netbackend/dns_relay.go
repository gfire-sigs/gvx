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

	"golang.org/x/net/dns/dnsmessage"
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

	defaultDNSTTL = 60

	// maxDNSMessage is the largest DNS message that a UDP or TCP exchange carries.
	maxDNSMessage = 65535

	// maxConcurrentDNS bounds concurrent in-flight DNS queries per endpoint.
	maxConcurrentDNS = 64
)

// errNoDNSServers reports that the host has no resolver to forward a query to.
var errNoDNSServers = errors.New("netbackend: no host DNS servers are configured")

var (
	dnsGatewayAddr = netip.MustParseAddr(HostGatewayIPv4)
	dnsGuestAddr   = netip.MustParseAddr(DefaultGuestIPv4)
)

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
	reqHdr, q, hdrOK, err := parseDNSQuery(req)
	if !hdrOK {
		return nil
	}
	if err != nil {
		return buildDNSErrorResponse(reqHdr, nil, dnsmessage.RCodeFormatError)
	}
	name := q.Name.String()

	if q.Class == dnsmessage.ClassINET && (q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA) {
		addrs, found, handled, lookupErr := r.lookupLocalAddrs(ctx, name)
		if lookupErr != nil && r.log != nil {
			r.log.Debug("netbackend: DNS lookup hook failed", "name", name, "error", lookupErr)
		}
		if handled {
			if !found {
				return buildDNSErrorResponse(reqHdr, &q, dnsmessage.RCodeNameError)
			}
			return buildDNSAddressResponse(reqHdr, q, addrs)
		}
	}

	resp, err := r.forwardRawUpstream(ctx, req)
	if err != nil {
		if r.log != nil {
			r.log.Debug("netbackend: forward DNS query", "name", name, "error", err)
		}
		return buildDNSErrorResponse(reqHdr, &q, dnsmessage.RCodeServerFailure)
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
	reqHdr, wantQ, _, err := parseDNSQuery(req)
	if err != nil {
		return nil, fmt.Errorf("netbackend: invalid DNS query: %w", err)
	}
	var errs []error
	for _, server := range r.servers {
		for _, dial := range r.dials {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			resp, respHdr, err := exchangeDNSWithDial(ctx, dial, "udp", server, req, reqHdr.ID, wantQ, r.tune.Duration(tuning.DNSUpstreamTimeout))
			if err == nil && respHdr.Truncated {
				resp, respHdr, err = exchangeDNSWithDial(ctx, dial, "tcp", server, req, reqHdr.ID, wantQ, r.tune.Duration(tuning.DNSUpstreamTimeout))
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("server %s: %w", server, err))
				continue
			}
			switch respHdr.RCode {
			case dnsmessage.RCodeServerFailure, dnsmessage.RCodeRefused:
				errs = append(errs, fmt.Errorf("server %s: rcode %v", server, respHdr.RCode))
				continue
			}
			return resp, nil
		}
	}
	return nil, fmt.Errorf("netbackend: all upstream DNS servers failed: %w", errors.Join(errs...))
}

func exchangeDNSWithDial(ctx context.Context, dial func(ctx context.Context, network, address string) (net.Conn, error), network, server string, req []byte, guestTxID uint16, wantQ dnsmessage.Question, timeout time.Duration) ([]byte, dnsmessage.Header, error) {
	upstreamTxID, err := randomDNSTxID()
	if err != nil {
		return nil, dnsmessage.Header{}, err
	}
	upstreamReq := append([]byte(nil), req...)
	binary.BigEndian.PutUint16(upstreamReq[0:2], upstreamTxID)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dial(ctx, network, server)
	if err != nil {
		return nil, dnsmessage.Header{}, err
	}
	defer conn.Close()
	// The deadline also bounds the read and write calls below.
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, dnsmessage.Header{}, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if network == "tcp" {
		framed := make([]byte, 2+len(upstreamReq))
		binary.BigEndian.PutUint16(framed[0:2], uint16(len(upstreamReq)))
		copy(framed[2:], upstreamReq)
		if _, err := conn.Write(framed); err != nil {
			return nil, dnsmessage.Header{}, err
		}
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, dnsmessage.Header{}, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, dnsmessage.Header{}, err
		}
		respHdr, ok := parseDNSResponse(resp, upstreamTxID, wantQ)
		if !ok {
			return nil, dnsmessage.Header{}, errors.New("invalid DNS response")
		}
		binary.BigEndian.PutUint16(resp[0:2], guestTxID)
		return resp, respHdr, nil
	}

	if _, err := conn.Write(upstreamReq); err != nil {
		return nil, dnsmessage.Header{}, err
	}
	buf := make([]byte, maxDNSMessage)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, dnsmessage.Header{}, err
		}
		// A connected UDP socket accepts datagrams from the server only. The
		// ID and question checks drop late or mismatched answers on a reused port.
		if respHdr, ok := parseDNSResponse(buf[:n], upstreamTxID, wantQ); ok {
			resp := append([]byte(nil), buf[:n]...)
			binary.BigEndian.PutUint16(resp[0:2], guestTxID)
			return resp, respHdr, nil
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

func parseDNSQuery(msg []byte) (dnsmessage.Header, dnsmessage.Question, bool, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		return dnsmessage.Header{}, dnsmessage.Question{}, false, err
	}
	q, err := p.Question()
	if err != nil {
		return hdr, dnsmessage.Question{}, true, err
	}
	return hdr, q, true, nil
}

func parseDNSResponse(msg []byte, wantID uint16, wantQ dnsmessage.Question) (dnsmessage.Header, bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil || !hdr.Response || hdr.ID != wantID {
		return dnsmessage.Header{}, false
	}
	gotQ, err := p.Question()
	if err != nil {
		return dnsmessage.Header{}, false
	}
	if _, err := p.Question(); !errors.Is(err, dnsmessage.ErrSectionDone) {
		return dnsmessage.Header{}, false
	}
	if !strings.EqualFold(gotQ.Name.String(), wantQ.Name.String()) ||
		gotQ.Type != wantQ.Type ||
		gotQ.Class != wantQ.Class {
		return dnsmessage.Header{}, false
	}
	return hdr, true
}

func buildDNSErrorResponse(reqHdr dnsmessage.Header, q *dnsmessage.Question, rcode dnsmessage.RCode) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 reqHdr.ID,
		Response:           true,
		RecursionDesired:   reqHdr.RecursionDesired,
		RecursionAvailable: true,
		RCode:              rcode,
	})
	b.EnableCompression()
	if q != nil {
		if err := b.StartQuestions(); err != nil {
			return nil
		}
		if err := b.Question(*q); err != nil {
			return nil
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

func buildDNSAddressResponse(reqHdr dnsmessage.Header, q dnsmessage.Question, addrs []netip.Addr) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 reqHdr.ID,
		Response:           true,
		Authoritative:      true,
		RecursionDesired:   reqHdr.RecursionDesired,
		RecursionAvailable: true,
		RCode:              dnsmessage.RCodeSuccess,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil
	}
	if err := b.Question(q); err != nil {
		return nil
	}
	if err := b.StartAnswers(); err != nil {
		return nil
	}
	hdr := dnsmessage.ResourceHeader{
		Name:  q.Name,
		Type:  q.Type,
		Class: dnsmessage.ClassINET,
		TTL:   defaultDNSTTL,
	}
	for _, a := range addrs {
		unmapped := a.Unmap()
		switch {
		case q.Type == dnsmessage.TypeA && unmapped.Is4():
			if err := b.AResource(hdr, dnsmessage.AResource{A: unmapped.As4()}); err != nil {
				return nil
			}
		case q.Type == dnsmessage.TypeAAAA && unmapped.Is6():
			if err := b.AAAAResource(hdr, dnsmessage.AAAAResource{AAAA: unmapped.As16()}); err != nil {
				return nil
			}
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}
