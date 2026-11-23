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
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/header"
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

// hostDNSConfig holds host resolver settings captured before lockdown.
type hostDNSConfig struct {
	servers []string
	search  []string
	options []string
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// sanitizeSearchDomain validates one DNS search domain token from host config
// so guest /etc/resolv.conf never receives empty labels, whitespace, or
// directive injection.
func sanitizeSearchDomain(raw string) (string, bool) {
	d := strings.TrimSuffix(strings.TrimSpace(raw), ".")
	if d == "" || len(d) > 253 {
		return "", false
	}
	for _, label := range strings.Split(d, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := range len(label) {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
				continue
			}
			return "", false
		}
	}
	return d, true
}

// capSearchDomains enforces glibc resolv.conf(5) bounds (6 domains, 256 bytes).
func capSearchDomains(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}
	var out []string
	total := 0
	for _, d := range domains {
		if len(out) >= 6 {
			break
		}
		add := len(d)
		if len(out) > 0 {
			add++
		}
		if total+add > 256 {
			break
		}
		out = append(out, d)
		total += add
	}
	return out
}

// sanitizeResolvOption filters host resolv.conf options down to the safe subset
// that guest stub resolvers understand.
func sanitizeResolvOption(raw string) (string, bool) {
	opt := strings.TrimSpace(raw)
	switch opt {
	case "rotate", "edns0", "single-request", "single-request-reopen", "no-tld-query", "trust-ad", "use-vc":
		return opt, true
	}
	key, val, ok := strings.Cut(opt, ":")
	if !ok {
		return "", false
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return "", false
	}
	switch key {
	case "ndots":
		if n >= 0 && n <= 15 {
			return fmt.Sprintf("ndots:%d", n), true
		}
	case "timeout":
		if n >= 1 && n <= 30 {
			return fmt.Sprintf("timeout:%d", n), true
		}
	case "attempts":
		if n >= 1 && n <= 5 {
			return fmt.Sprintf("attempts:%d", n), true
		}
	}
	return "", false
}

// formatGuestResolvConf builds a guest /etc/resolv.conf pointing at nameserver
// while preserving sanitized host search domains and resolver options.
func formatGuestResolvConf(nameserver string, search, options []string) string {
	var b strings.Builder
	b.WriteString("nameserver ")
	b.WriteString(nameserver)
	b.WriteByte('\n')
	if len(search) > 0 {
		b.WriteString("search ")
		b.WriteString(strings.Join(search, " "))
		b.WriteByte('\n')
	}
	if len(options) > 0 {
		b.WriteString("options ")
		b.WriteString(strings.Join(options, " "))
		b.WriteByte('\n')
	}
	return b.String()
}

// GuestResolvConf returns the /etc/resolv.conf content for a guest attached to
// nf. It points nameserver at HostDNSIPv4 and preserves sanitized host search
// domains and resolver options captured before lockdown.
func (nf *NATForwarder) GuestResolvConf() string {
	return formatGuestResolvConf(HostDNSIPv4, nf.dnsSearch, nf.dnsOptions)
}

// GuestResolvConf returns the /etc/resolv.conf content for a guest attached to
// w. It points nameserver at HostDNSIPv4 and preserves sanitized host search
// domains and resolver options captured before lockdown.
func (w *WireGuardEndpoint) GuestResolvConf() string {
	return formatGuestResolvConf(HostDNSIPv4, w.dnsSearch, w.dnsOptions)
}

func hasEth0IPv6Route(s *stack.Stack) bool {
	if s == nil {
		return false
	}
	for _, r := range s.GetRouteTable() {
		if r.NIC == Eth0NICID && r.Destination.ID().Len() == header.IPv6AddressSize {
			return true
		}
	}
	return false
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
	timeout := nf.dnsTimeout()
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
			reply := nf.dnsRelay().reply(ctx, pkt, false)
			if len(reply.wire) == 0 {
				return
			}
			write := func() (int, error) {
				writeMu.Lock()
				defer writeMu.Unlock()
				_ = conn.SetWriteDeadline(time.Now().Add(timeout))
				defer conn.SetWriteDeadline(time.Time{})
				return conn.Write(reply.wire)
			}
			if err := writeDNSReply(ctx, nf.cfg.Bandwidth, reply.local, false, len(reply.wire), timeout, write); err != nil {
				nf.log.Debug("netbackend: write DNS response to guest", "error", err)
			}
		}(req)
	}
}

func (nf *NATForwarder) serveTCPDNS(ctx context.Context, conn net.Conn) {
	timeout := nf.dnsTimeout()
	serveTCPDNSConn(ctx, conn, timeout, nf.cfg.Bandwidth, func(ctx context.Context, req []byte) dnsReply {
		return nf.queryDNS(ctx, req, true)
	})
}

func serveTCPDNSConn(ctx context.Context, conn net.Conn, timeout time.Duration, shaper *BandwidthShaper, answer func(context.Context, []byte) dnsReply) {
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
		reply := answer(ctx, req)
		if len(reply.wire) == 0 {
			return
		}
		out := make([]byte, 2+len(reply.wire))
		binary.BigEndian.PutUint16(out[0:2], uint16(len(reply.wire)))
		copy(out[2:], reply.wire)
		write := func() (int, error) {
			_ = conn.SetWriteDeadline(time.Now().Add(timeout))
			return conn.Write(out)
		}
		if err := writeDNSReply(ctx, shaper, reply.local, true, len(out), timeout, write); err != nil {
			return
		}
	}
}

func writeDNSReply(ctx context.Context, shaper *BandwidthShaper, local, stream bool, n int, timeout time.Duration, write func() (int, error)) error {
	if local && shaper.Enabled(BandwidthRX) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		_, err := shapeDNSPayload(ctx, shaper, BandwidthRX, n, stream, write)
		return err
	}
	_, err := write()
	return err
}

type dnsReply struct {
	wire  []byte
	local bool
}

type dnsRelay struct {
	gvxAddrs        []netip.Addr
	hasGateway      bool
	ipv6Enabled     bool
	isolateLAN      bool
	lookupHost      func(ctx context.Context, host string) ([]netip.Addr, error)
	servers         []string
	dials           []func(ctx context.Context, network, addr string) (net.Conn, error)
	log             *slog.Logger
	timeout         time.Duration
	upstreamTimeout time.Duration
	bandwidth       *BandwidthShaper
}

func (nf *NATForwarder) hasGuestIPv6() bool {
	nf.mu.Lock()
	s := nf.guestStack
	nf.mu.Unlock()
	return hasEth0IPv6Route(s)
}

func (nf *NATForwarder) dnsRelay() dnsRelay {
	dialFn := nf.cfg.DialContext
	if dialFn == nil {
		var d net.Dialer
		dialFn = d.DialContext
	}
	return dnsRelay{
		gvxAddrs:        []netip.Addr{netip.MustParseAddr(DefaultGuestIPv4)},
		hasGateway:      true,
		ipv6Enabled:     nf.hasGuestIPv6(),
		isolateLAN:      nf.IsolateLAN(),
		lookupHost:      nf.cfg.LookupHost,
		servers:         nf.upstreamDNS,
		dials:           []func(context.Context, string, string) (net.Conn, error){dialFn},
		log:             nf.log,
		timeout:         nf.dnsTimeout(),
		upstreamTimeout: nf.dnsUpstreamTimeout(),
		bandwidth:       nf.cfg.Bandwidth,
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
		gvxAddrs:        gvxAddrs,
		ipv6Enabled:     w.cfg.GuestIPv6.IsValid(),
		lookupHost:      w.cfg.LookupHost,
		servers:         w.upstreamDNS,
		dials:           dials,
		log:             log,
		timeout:         w.cfg.Tuning.Duration(tuning.DNSTimeout),
		upstreamTimeout: w.cfg.Tuning.Duration(tuning.DNSUpstreamTimeout),
	}
}

// handleDNSQuery answers one UDP DNS message. The relay owns internal names
// and resolves A and AAAA queries through the LookupHost hook. It forwards
// other queries to the host DNS servers and answers SERVFAIL when none replies.
func (nf *NATForwarder) handleDNSQuery(ctx context.Context, req []byte) []byte {
	return nf.queryDNS(ctx, req, false).wire
}

// handleTCPDNSQuery answers one TCP DNS message, forwarding upstream directly
// over TCP rather than UDP.
func (nf *NATForwarder) handleTCPDNSQuery(ctx context.Context, req []byte) []byte {
	return nf.queryDNS(ctx, req, true).wire
}

func (nf *NATForwarder) queryDNS(ctx context.Context, req []byte, viaTCP bool) dnsReply {
	sem := nf.dnsSemaphore()
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		return dnsReply{}
	}
	return nf.dnsRelay().reply(ctx, req, viaTCP)
}

// forwardRawDNSUpstream sends the wire query to each host DNS server in turn
// and returns the first usable answer. A server that fails, answers SERVFAIL,
// or answers REFUSED does not stop the search.
func (nf *NATForwarder) forwardRawDNSUpstream(ctx context.Context, req []byte) ([]byte, error) {
	var sent bool
	return nf.dnsRelay().forwardRawUpstream(ctx, req, false, &sent)
}

func (r dnsRelay) answerQuery(ctx context.Context, req []byte, viaTCP bool) []byte {
	return r.reply(ctx, req, viaTCP).wire
}

func (r dnsRelay) reply(ctx context.Context, req []byte, viaTCP bool) dnsReply {
	// Charge the guest leg only when no upstream send accounted for the request.
	local := func(wire []byte, sent bool) dnsReply {
		if !sent && r.bandwidth.Enabled(BandwidthTX) {
			n := len(req)
			if viaTCP {
				n += 2
			}
			qctx, cancel := context.WithTimeout(ctx, r.timeout)
			defer cancel()
			if err := admitDNSPayload(qctx, r.bandwidth, BandwidthTX, n, viaTCP); err != nil {
				return dnsReply{}
			}
		}
		return dnsReply{wire: wire, local: true}
	}
	reqHdr, q, hdrOK, err := parseDNSQuery(req)
	if !hdrOK {
		return dnsReply{}
	}
	if err != nil {
		return local(buildDNSErrorResponse(reqHdr, nil, dnsmessage.RCodeFormatError), false)
	}
	name := q.Name.String()

	if q.Class == dnsmessage.ClassINET {
		if addrs, found, owned := r.lookupOwnName(name); owned {
			if !found {
				return local(buildDNSErrorResponse(reqHdr, &q, dnsmessage.RCodeNameError), false)
			}
			if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA {
				return local(buildDNSAddressResponse(reqHdr, q, addrs, true), false)
			}
			return local(buildDNSAddressResponse(reqHdr, q, nil, true), false)
		}

		if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA {
			if !r.ipv6Enabled && q.Type == dnsmessage.TypeAAAA {
				return local(buildDNSAddressResponse(reqHdr, q, nil, false), false)
			}
			if r.lookupHost != nil {
				addrs, found, handled, lookupErr := r.lookupHookAddrs(ctx, name)
				if lookupErr != nil && r.log != nil {
					r.log.Debug("netbackend: DNS lookup hook failed", "name", name, "error", lookupErr)
				}
				if handled {
					if !found {
						return local(buildDNSErrorResponse(reqHdr, &q, dnsmessage.RCodeNameError), false)
					}
					return local(buildDNSAddressResponse(reqHdr, q, addrs, true), false)
				}
			}
		}
	}

	var sent bool
	resp, err := r.forwardRawUpstream(ctx, req, viaTCP, &sent)
	if err != nil {
		if r.log != nil {
			r.log.Debug("netbackend: forward DNS query", "name", name, "error", err)
		}
		return local(buildDNSErrorResponse(reqHdr, &q, dnsmessage.RCodeServerFailure), sent)
	}
	return dnsReply{wire: resp}
}

// lookupOwnName resolves the internal names that the relay owns authoritatively.
// owned is false when the relay must delegate the query to the hook or upstream.
// found is false when the owned name is blocked (for example under IsolateLAN).
func (r dnsRelay) lookupOwnName(qname string) (addrs []netip.Addr, found, owned bool) {
	clean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qname)), ".")
	switch clean {
	case "localhost", "localhost.localdomain":
		return []netip.Addr{
			netip.MustParseAddr("127.0.0.1"),
			netip.MustParseAddr("::1"),
		}, true, true
	case "host.docker.internal", "gateway.docker.internal":
		if r.hasGateway {
			if r.isolateLAN {
				return nil, false, true
			}
			return []netip.Addr{netip.MustParseAddr(HostGatewayIPv4)}, true, true
		}
	case "gvx":
		return r.gvxAddrs, true, true
	}
	return nil, false, false
}

// lookupHookAddrs resolves qname through the configured LookupHost hook.
func (r dnsRelay) lookupHookAddrs(ctx context.Context, qname string) (addrs []netip.Addr, found, handled bool, err error) {
	clean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qname)), ".")
	rctx, cancel := context.WithTimeout(ctx, r.timeout)
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

func (r dnsRelay) forwardRawUpstream(ctx context.Context, req []byte, viaTCP bool, sent *bool) ([]byte, error) {
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
			var (
				resp    []byte
				respHdr dnsmessage.Header
			)
			if viaTCP {
				resp, respHdr, err = r.exchangeUpstream(ctx, dial, "tcp", server, req, reqHdr.ID, wantQ, sent)
			} else {
				resp, respHdr, err = r.exchangeUpstream(ctx, dial, "udp", server, req, reqHdr.ID, wantQ, sent)
				if err == nil && respHdr.Truncated {
					resp, respHdr, err = r.exchangeUpstream(ctx, dial, "tcp", server, req, reqHdr.ID, wantQ, sent)
				}
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

func (r dnsRelay) exchangeUpstream(ctx context.Context, dial func(ctx context.Context, network, address string) (net.Conn, error), network, server string, req []byte, guestTxID uint16, wantQ dnsmessage.Question, sent *bool) ([]byte, dnsmessage.Header, error) {
	upstreamTxID, err := randomDNSTxID()
	if err != nil {
		return nil, dnsmessage.Header{}, err
	}
	upstreamReq := append([]byte(nil), req...)
	binary.BigEndian.PutUint16(upstreamReq[0:2], upstreamTxID)

	ctx, cancel := context.WithTimeout(ctx, r.upstreamTimeout)
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

	stream := network == "tcp"
	write := func(p []byte) error {
		n, err := shapeDNSPayload(ctx, r.bandwidth, BandwidthTX, len(p), stream, func() (int, error) { return conn.Write(p) })
		*sent = *sent || n > 0
		if err == nil && n != len(p) {
			return io.ErrShortWrite
		}
		return err
	}

	if stream {
		framed := make([]byte, 2+len(upstreamReq))
		binary.BigEndian.PutUint16(framed[0:2], uint16(len(upstreamReq)))
		copy(framed[2:], upstreamReq)
		if err := write(framed); err != nil {
			return nil, dnsmessage.Header{}, err
		}
		var lenBuf [2]byte
		prefixRead, err := io.ReadFull(conn, lenBuf[:])
		if err != nil {
			if prefixRead != 0 {
				err = errors.Join(err, admitDNSPayload(ctx, r.bandwidth, BandwidthRX, prefixRead, true))
			}
			return nil, dnsmessage.Header{}, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		n, readErr := io.ReadFull(conn, resp)
		if err := errors.Join(readErr, admitDNSPayload(ctx, r.bandwidth, BandwidthRX, n+len(lenBuf), true)); err != nil {
			return nil, dnsmessage.Header{}, err
		}
		respHdr, ok := parseDNSResponse(resp, upstreamTxID, wantQ)
		if !ok {
			return nil, dnsmessage.Header{}, errors.New("invalid DNS response")
		}
		binary.BigEndian.PutUint16(resp[0:2], guestTxID)
		return resp, respHdr, nil
	}

	if err := write(upstreamReq); err != nil {
		return nil, dnsmessage.Header{}, err
	}
	buf := make([]byte, maxDNSMessage)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, dnsmessage.Header{}, err
		}
		if err := admitDNSPayload(ctx, r.bandwidth, BandwidthRX, n, false); err != nil {
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

func shapeDNSPayload(ctx context.Context, shaper *BandwidthShaper, dir BandwidthDirection, n int, stream bool, write func() (int, error)) (int, error) {
	if !shaper.Enabled(dir) {
		return write()
	}
	if stream {
		return shaper.Shape(ctx, dir, n, write)
	}
	return shaper.ShapeDatagram(ctx, dir, n, write)
}

func admitDNSPayload(ctx context.Context, shaper *BandwidthShaper, dir BandwidthDirection, n int, stream bool) error {
	_, err := shapeDNSPayload(ctx, shaper, dir, n, stream, func() (int, error) { return n, nil })
	return err
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
			resp := w.dnsRelay(log).answerQuery(ctx, pkt, false)
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
	answer := func(qctx context.Context, req []byte) dnsReply {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		case <-qctx.Done():
			return dnsReply{}
		}
		return w.dnsRelay(log).reply(qctx, req, true)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		w.dnsWG.Add(1)
		go func(c net.Conn) {
			defer w.dnsWG.Done()
			serveTCPDNSConn(ctx, c, w.cfg.Tuning.Duration(tuning.DNSTimeout), nil, answer)
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

func buildDNSAddressResponse(reqHdr dnsmessage.Header, q dnsmessage.Question, addrs []netip.Addr, authoritative bool) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 reqHdr.ID,
		Response:           true,
		Authoritative:      authoritative,
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
