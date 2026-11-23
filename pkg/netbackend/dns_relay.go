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

	maxGuestUDPDNSMessage = 4096

	// maxConcurrentDNS bounds concurrent in-flight DNS queries per endpoint.
	maxConcurrentDNS = 64
)

// errNoDNSServers reports that the host has no resolver to forward a query to.
var errNoDNSServers = errors.New("netbackend: no host DNS servers are configured")

var errInvalidDNSMessage = errors.New("netbackend: invalid DNS message")

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

func (nf *NATForwarder) serveUDPDNS(ctx context.Context, conn net.Conn, requestPolicy *dnsRequestPolicy) {
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
	readSize := maxGuestUDPDNSMessage
	if requestPolicy != nil {
		// A truncated datagram must not reach the parser or the byte budget.
		readSize++
	}
	buf := make([]byte, readSize)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if n > maxGuestUDPDNSMessage {
			continue
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
			reply := nf.dnsRelay().answerQuery(ctx, pkt, false, requestPolicy)
			if len(reply.message) == 0 {
				return
			}
			writeMu.Lock()
			err := requestPolicy.sendReply(ctx, conn, reply.message, reply, timeout)
			writeMu.Unlock()
			if err != nil {
				nf.log.Debug("netbackend: write DNS response to guest", "error", err)
			}
		}(req)
	}
}

func (nf *NATForwarder) serveTCPDNS(ctx context.Context, conn net.Conn, requestPolicy *dnsRequestPolicy) {
	answer := func(ctx context.Context, req []byte) dnsReply {
		return nf.handleDNSQueryProto(ctx, req, true, requestPolicy)
	}
	serveTCPDNSConn(ctx, conn, nf.cfg.Tuning.Duration(tuning.DNSTimeout), requestPolicy, answer)
}

func serveTCPDNSConn(ctx context.Context, conn net.Conn, timeout time.Duration, requestPolicy *dnsRequestPolicy, answer func(context.Context, []byte) dnsReply) {
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stop()
	defer func() {
		_ = conn.Close()
	}()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		req, err := readDNSFrame(conn)
		if err != nil {
			return
		}
		reply := answer(ctx, req)
		if len(reply.message) == 0 {
			return
		}
		framed := frameDNSMessage(reply.message)
		if err := requestPolicy.sendReply(ctx, conn, framed, reply, timeout); err != nil {
			return
		}
	}
}

func readDNSFrame(r io.Reader) ([]byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(length[:])
	if size == 0 {
		return nil, errInvalidDNSMessage
	}
	msg := make([]byte, size)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func frameDNSMessage(msg []byte) []byte {
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out[:2], uint16(len(msg)))
	copy(out[2:], msg)
	return out
}

// dnsRequestPolicy uses the guest tuple supplied by the NAT transport, even
// when the upstream uses a different IP family or protocol.
type dnsRequestPolicy struct {
	policy *NATPolicy
	guest  PolicyTuple
}

type dnsReply struct {
	message        []byte
	upstream       PolicyTuple // The request direction of the socket that supplied the reply.
	upstreamBytes  int
	requestCharged bool
}

func (p *dnsRequestPolicy) sendReply(ctx context.Context, conn net.Conn, wire []byte, reply dnsReply, timeout time.Duration) error {
	write := func() error { return writeDNSWire(conn, wire) }
	if p == nil {
		_ = conn.SetWriteDeadline(time.Now().Add(timeout))
		defer conn.SetWriteDeadline(time.Time{})
		return write()
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tuples := [2]PolicyTuple{p.guest.Reverse()}
	count, size := 1, len(wire)
	if reply.upstream.ProtocolKnown {
		tuples[1] = reply.upstream.Reverse()
		count, size = 2, reply.upstreamBytes
	}
	if udp, ok := conn.(*gonet.UDPConn); ok {
		write = func() error {
			n, err := writeNATRelayDatagram(p.policy, udp, wire, tuples[:count]...)
			if err == nil && n != len(wire) {
				return io.ErrShortWrite
			}
			return err
		}
	}
	return p.policy.Send(ctx, PolicyOutput, size, func() error { return policyWrite(conn, write) }, tuples[:count]...)
}

func writeDNSWire(conn net.Conn, wire []byte) error {
	n, err := conn.Write(wire)
	if err == nil && n != len(wire) {
		return io.ErrShortWrite
	}
	return err
}

type dnsRelay struct {
	gvxAddrs    []netip.Addr
	hasGateway  bool
	ipv6Enabled bool
	isolateLAN  bool
	lookupHost  func(ctx context.Context, host string) ([]netip.Addr, error)
	servers     []string
	dials       []func(ctx context.Context, network, addr string) (net.Conn, error)
	log         *slog.Logger
	tune        tuning.Values
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
		gvxAddrs:    []netip.Addr{netip.MustParseAddr(DefaultGuestIPv4)},
		hasGateway:  true,
		ipv6Enabled: nf.hasGuestIPv6(),
		isolateLAN:  nf.cfg.IsolateLAN,
		lookupHost:  nf.cfg.LookupHost,
		servers:     nf.upstreamDNS,
		dials:       []func(context.Context, string, string) (net.Conn, error){dialFn},
		log:         nf.log,
		tune:        nf.cfg.Tuning,
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
		gvxAddrs:    gvxAddrs,
		ipv6Enabled: w.cfg.GuestIPv6.IsValid(),
		lookupHost:  w.cfg.LookupHost,
		servers:     w.upstreamDNS,
		dials:       dials,
		log:         log,
		tune:        w.cfg.Tuning,
	}
}

// handleDNSQuery answers one unprotected UDP DNS message.
func (nf *NATForwarder) handleDNSQuery(ctx context.Context, req []byte) []byte {
	return nf.handleDNSQueryProto(ctx, req, false, nil).message
}

func (nf *NATForwarder) handleDNSQueryProto(ctx context.Context, req []byte, viaTCP bool, requestPolicy *dnsRequestPolicy) dnsReply {
	sem := nf.dnsSemaphore()
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		return dnsReply{}
	}
	return nf.dnsRelay().answerQuery(ctx, req, viaTCP, requestPolicy)
}

// forwardRawDNSUpstream sends the wire query to each host DNS server in turn
// and returns the first usable answer. A server that fails, answers SERVFAIL,
// or answers REFUSED does not stop the search.
func (nf *NATForwarder) forwardRawDNSUpstream(ctx context.Context, req []byte) ([]byte, error) {
	hdr, q, _, err := parseDNSQuery(req)
	if err != nil {
		return nil, fmt.Errorf("netbackend: invalid DNS query: %w", err)
	}
	reply, err := nf.dnsRelay().forwardRawUpstream(ctx, req, hdr.ID, q, false, nil)
	return reply.message, err
}

func (r dnsRelay) answerQuery(ctx context.Context, req []byte, viaTCP bool, requestPolicy *dnsRequestPolicy) dnsReply {
	if requestPolicy != nil && !requestPolicy.policy.Allow(PolicyInput, requestPolicy.guest) {
		return dnsReply{}
	}
	reply := r.resolveQuery(ctx, req, viaTCP, requestPolicy)
	if requestPolicy == nil || len(reply.message) == 0 || reply.requestCharged {
		return reply
	}

	n := len(req)
	if viaTCP {
		n += 2
	}
	ctx, cancel := context.WithTimeout(ctx, r.tune.Duration(tuning.DNSTimeout))
	defer cancel()
	if err := requestPolicy.policy.Send(ctx, PolicyInput, n, admitDNSMessage, requestPolicy.guest); err != nil {
		return dnsReply{}
	}
	return reply
}

// The transfer ends at the relay for a local query or a received upstream answer.
func admitDNSMessage() error { return nil }

func (r dnsRelay) resolveQuery(ctx context.Context, req []byte, viaTCP bool, requestPolicy *dnsRequestPolicy) dnsReply {
	reqHdr, q, hdrOK, err := parseDNSQuery(req)
	if !hdrOK {
		return dnsReply{}
	}
	if err != nil {
		return dnsReply{message: buildDNSErrorResponse(reqHdr, nil, dnsmessage.RCodeFormatError)}
	}
	name := q.Name.String()

	if q.Class == dnsmessage.ClassINET {
		if addrs, found, owned := r.lookupOwnName(name); owned {
			if !found {
				return dnsReply{message: buildDNSErrorResponse(reqHdr, &q, dnsmessage.RCodeNameError)}
			}
			if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA {
				return dnsReply{message: buildDNSAddressResponse(reqHdr, q, addrs, true)}
			}
			return dnsReply{message: buildDNSAddressResponse(reqHdr, q, nil, true)}
		}

		if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA {
			if !r.ipv6Enabled && q.Type == dnsmessage.TypeAAAA {
				return dnsReply{message: buildDNSAddressResponse(reqHdr, q, nil, false)}
			}
			if requestPolicy == nil && r.lookupHost != nil {
				addrs, found, handled, lookupErr := r.lookupHookAddrs(ctx, name)
				if lookupErr != nil && r.log != nil {
					r.log.Debug("netbackend: DNS lookup hook failed", "name", name, "error", lookupErr)
				}
				if handled {
					if !found {
						return dnsReply{message: buildDNSErrorResponse(reqHdr, &q, dnsmessage.RCodeNameError)}
					}
					return dnsReply{message: buildDNSAddressResponse(reqHdr, q, addrs, true)}
				}
			}
		}
	}

	reply, err := r.forwardRawUpstream(ctx, req, reqHdr.ID, q, viaTCP, requestPolicy)
	if err == nil {
		return reply
	}
	if r.log != nil {
		r.log.Debug("netbackend: forward DNS query", "name", name, "error", err)
	}
	if requestPolicy != nil && (errors.Is(err, ErrPolicyDenied) || errors.Is(err, ErrPolicyQueueFull)) {
		return dnsReply{}
	}
	reply.message = buildDNSErrorResponse(reqHdr, &q, dnsmessage.RCodeServerFailure)
	return reply
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

func (r dnsRelay) forwardRawUpstream(ctx context.Context, req []byte, guestTxID uint16, wantQ dnsmessage.Question, viaTCP bool, requestPolicy *dnsRequestPolicy) (dnsReply, error) {
	if len(r.servers) == 0 {
		return dnsReply{}, errNoDNSServers
	}
	network := "udp"
	if viaTCP {
		network = "tcp"
	}
	timeout := r.tune.Duration(tuning.DNSUpstreamTimeout)
	var errs []error
	var requestCharged bool
	for _, server := range r.servers {
		for _, dial := range r.dials {
			if err := ctx.Err(); err != nil {
				return dnsReply{requestCharged: requestCharged}, errors.Join(append(errs, err)...)
			}
			reply, hdr, err := exchangeDNSWithDial(ctx, dial, network, server, req, guestTxID, wantQ, timeout, requestPolicy)
			requestCharged = requestCharged || reply.requestCharged
			if err == nil && !viaTCP && hdr.Truncated {
				reply, hdr, err = exchangeDNSWithDial(ctx, dial, "tcp", server, req, guestTxID, wantQ, timeout, requestPolicy)
				requestCharged = requestCharged || reply.requestCharged
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("server %s: %w", server, err))
				continue
			}
			switch hdr.RCode {
			case dnsmessage.RCodeServerFailure, dnsmessage.RCodeRefused:
				errs = append(errs, fmt.Errorf("server %s: rcode %v", server, hdr.RCode))
				continue
			}
			reply.requestCharged = requestCharged
			return reply, nil
		}
	}
	return dnsReply{requestCharged: requestCharged}, fmt.Errorf("netbackend: all upstream DNS servers failed: %w", errors.Join(errs...))
}

func exchangeDNSWithDial(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), network, server string, req []byte, guestTxID uint16, wantQ dnsmessage.Question, timeout time.Duration, requestPolicy *dnsRequestPolicy) (dnsReply, dnsmessage.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var (
		conn net.Conn
		host PolicyTuple
		err  error
	)
	if requestPolicy == nil {
		conn, err = dial(ctx, network, server)
	} else {
		conn, host, err = requestPolicy.dialUpstream(ctx, dial, network, server)
	}
	if err != nil {
		return dnsReply{}, dnsmessage.Header{}, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return dnsReply{}, dnsmessage.Header{}, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	upstreamTxID, err := randomDNSTxID()
	if err != nil {
		return dnsReply{}, dnsmessage.Header{}, err
	}
	var wire []byte
	if network == "tcp" {
		wire = frameDNSMessage(req)
		binary.BigEndian.PutUint16(wire[2:4], upstreamTxID)
	} else {
		wire = append([]byte(nil), req...)
		binary.BigEndian.PutUint16(wire[:2], upstreamTxID)
	}
	var reply dnsReply
	if requestPolicy == nil {
		err = writeDNSWire(conn, wire)
	} else {
		err = requestPolicy.policy.Send(ctx, PolicyInput, len(wire), func() error {
			reply.requestCharged = true
			return policyWrite(conn, func() error { return writeDNSWire(conn, wire) })
		}, requestPolicy.guest, host)
	}
	if err != nil {
		return reply, dnsmessage.Header{}, err
	}

	resp, hdr, err := readUpstreamDNS(conn, network, upstreamTxID, wantQ)
	if err != nil {
		return reply, dnsmessage.Header{}, err
	}
	if requestPolicy != nil {
		reply.upstreamBytes = len(resp)
		if network == "tcp" {
			reply.upstreamBytes += 2
		}
		guest, upstream := requestPolicy.guest.Reverse(), host.Reverse()
		if (network == "udp" && hdr.Truncated) || hdr.RCode == dnsmessage.RCodeServerFailure || hdr.RCode == dnsmessage.RCodeRefused {
			// The relay consumes this reply; it does not write it to the guest.
			if err := requestPolicy.policy.Send(ctx, PolicyOutput, reply.upstreamBytes, admitDNSMessage, guest, upstream); err != nil {
				return reply, dnsmessage.Header{}, err
			}
		} else if !requestPolicy.policy.Allow(PolicyOutput, guest, upstream) {
			return reply, dnsmessage.Header{}, ErrPolicyDenied
		}
	}
	binary.BigEndian.PutUint16(resp[:2], guestTxID)
	reply.message = resp
	reply.upstream = host
	return reply, hdr, nil
}

func (p *dnsRequestPolicy) dialUpstream(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), network, server string) (net.Conn, PolicyTuple, error) {
	target, err := netip.ParseAddrPort(server)
	if err != nil {
		addr, err := netip.ParseAddr(server)
		if err != nil {
			return nil, PolicyTuple{}, fmt.Errorf("%w: DNS upstream must be numeric", ErrPolicyDenied)
		}
		target = netip.AddrPortFrom(addr, DefaultDNSPort)
	}
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	if target.Port() == 0 || target.Addr().IsUnspecified() || (network == "tcp" && !p.policy.HostDialAllowed(target)) {
		return nil, PolicyTuple{}, ErrPolicyDenied
	}

	proto := uint8(header.UDPProtocolNumber)
	if network == "tcp" {
		proto = uint8(header.TCPProtocolNumber)
	}
	if target.Addr().Is4() {
		network += "4"
	} else {
		network += "6"
	}
	planned := policyAddrTuple(proto, netip.AddrPort{}, target)
	conn, err := p.policy.Dial(ctx, PolicyInput, func(ctx context.Context) (net.Conn, error) {
		return dial(ctx, network, target.String())
	}, p.guest, planned)
	if err != nil {
		return nil, PolicyTuple{}, err
	}
	actual := policySocketTuple(proto, conn.LocalAddr(), conn.RemoteAddr())
	if !actual.Source.IsValid() || actual.Source.IsUnspecified() || !actual.SourcePortKnown ||
		actual.Destination.WithZone("") != target.Addr().WithZone("") ||
		!actual.DestinationPortKnown || actual.DestinationPort != target.Port() {
		_ = conn.Close()
		return nil, PolicyTuple{}, ErrPolicyDenied
	}
	return conn, actual, nil
}

func readUpstreamDNS(conn net.Conn, network string, wantID uint16, wantQ dnsmessage.Question) ([]byte, dnsmessage.Header, error) {
	if network == "tcp" {
		resp, err := readDNSFrame(conn)
		if err != nil {
			return nil, dnsmessage.Header{}, err
		}
		hdr, ok := parseDNSResponse(resp, wantID, wantQ)
		if !ok {
			return nil, dnsmessage.Header{}, errInvalidDNSMessage
		}
		return resp, hdr, nil
	}

	buf := make([]byte, maxDNSMessage)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, dnsmessage.Header{}, err
		}
		// The connected socket filters source endpoints. The ID and question
		// checks reject late or mismatched answers on a reused port.
		if hdr, ok := parseDNSResponse(buf[:n], wantID, wantQ); ok {
			return append([]byte(nil), buf[:n]...), hdr, nil
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
			resp := w.dnsRelay(log).answerQuery(ctx, pkt, false, nil).message
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
		return w.dnsRelay(log).answerQuery(qctx, req, true, nil)
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
