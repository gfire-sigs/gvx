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
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/icmp"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
)

const (
	// DefaultWireGuardMTU is the L3 MTU for the in-memory WireGuard channel endpoint.
	DefaultWireGuardMTU uint32 = 1420

	// DefaultWireGuardListenAddr is the address of the pre-bound UDP socket.
	// The wildcard address lets remote peers reach the socket.
	DefaultWireGuardListenAddr = ":0"

	wgChannelQueueSize = 512
	wgMinMTU           = 576
	wgMinMTUWithIPv6   = header.IPv6MinimumMTU
	wgEndpointTimeout  = 10 * time.Second
	wgMaxKeepaliveSecs = 1<<16 - 1
)

// WireGuardConfig configures the Track B (-net=wg) L3 in-memory WireGuard endpoint.
type WireGuardConfig struct {
	// PrivateKey is the X25519 private key of the guest interface. It is required.
	PrivateKey [32]byte
	// PeerPublicKey is the X25519 public key of the remote peer. It is required.
	PeerPublicKey [32]byte
	// PresharedKey is the optional symmetric key. The zero value disables it.
	PresharedKey [32]byte
	// PeerEndpoint is the "host:port" of the remote peer. NewWireGuardEndpoint
	// resolves a host name before lockdown. When empty, the peer must send the
	// first handshake.
	PeerEndpoint string
	// GuestIPv4 is the IPv4 address of eth0. The default is 10.0.2.15/24.
	GuestIPv4 netip.Prefix
	// GuestIPv6 is the optional IPv6 address of eth0.
	GuestIPv6 netip.Prefix
	// AllowedIPs lists the destinations that go to the peer and the source
	// addresses that the peer may use. The default is 0.0.0.0/0 and ::/0.
	AllowedIPs []netip.Prefix
	// PersistentKeepalive is the keepalive interval in whole seconds. Zero
	// disables it. A non-zero value also starts the handshake at Start.
	PersistentKeepalive time.Duration
	// MTU is the L3 MTU of eth0. The default is DefaultWireGuardMTU.
	MTU uint32
	// ListenUDPAddr is the address of the pre-bound UDP socket. The default
	// is DefaultWireGuardListenAddr.
	ListenUDPAddr string
	// Logger receives wireguard-go device messages. When nil, the endpoint
	// discards them. Verbose messages use the Debug level.
	Logger *slog.Logger

	// ListenPacket supplies the pre-bound UDP socket. The endpoint owns the returned socket.
	// A nil function uses net.ListenPacket.
	ListenPacket func(network, address string) (net.PacketConn, error) `json:"-"`
}

// WireGuardEndpoint attaches a Netstack channel.Endpoint (MTU 1420) to the
// golang.zx2c4.com/wireguard device in Go memory. The device sends and
// receives encrypted packets through one host UDP socket that PreBindUDP opens
// before hostlockdown.Apply.
//
// The endpoint owns the UDP socket, the Netstack, and the device. Close
// releases all three.
type WireGuardEndpoint struct {
	cfg          WireGuardConfig
	peerEndpoint netip.AddrPort

	mu        sync.Mutex
	udpConn   net.PacketConn
	stack     *stack.Stack
	channelEP *channel.Endpoint
	dev       *device.Device
	closed    bool
}

// NewWireGuardEndpoint validates cfg and resolves the peer endpoint. It opens
// no socket. Call PreBindUDP, then Start.
func NewWireGuardEndpoint(cfg WireGuardConfig) (*WireGuardEndpoint, error) {
	if cfg.MTU == 0 {
		cfg.MTU = DefaultWireGuardMTU
	}
	if !cfg.GuestIPv4.IsValid() {
		cfg.GuestIPv4 = netip.MustParsePrefix("10.0.2.15/24")
	}
	if cfg.ListenUDPAddr == "" {
		cfg.ListenUDPAddr = DefaultWireGuardListenAddr
	}
	if len(cfg.AllowedIPs) == 0 {
		cfg.AllowedIPs = []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		}
	} else {
		cfg.AllowedIPs = append([]netip.Prefix(nil), cfg.AllowedIPs...)
	}
	if err := validateWireGuardConfig(&cfg); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), wgEndpointTimeout)
	defer cancel()
	peerEndpoint, err := resolveWireGuardPeerEndpoint(ctx, cfg.PeerEndpoint, net.DefaultResolver.LookupNetIP)
	if err != nil {
		return nil, err
	}
	return &WireGuardEndpoint{cfg: cfg, peerEndpoint: peerEndpoint}, nil
}

// validateWireGuardConfig rejects unusable keys, addresses, and sizes. It
// canonicalizes the allowed prefixes in place.
func validateWireGuardConfig(cfg *WireGuardConfig) error {
	if cfg.PrivateKey == [32]byte{} {
		return errors.New("netbackend: WireGuard PrivateKey is not set")
	}
	if cfg.PeerPublicKey == [32]byte{} {
		return errors.New("netbackend: WireGuard PeerPublicKey is not set")
	}
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(cfg.PrivateKey[:])
	if err != nil {
		return fmt.Errorf("netbackend: invalid WireGuard PrivateKey: %w", err)
	}
	peer, err := curve.NewPublicKey(cfg.PeerPublicKey[:])
	if err != nil {
		return fmt.Errorf("netbackend: invalid WireGuard PeerPublicKey: %w", err)
	}
	// X25519 fails when the peer key has a small order. wireguard-go would
	// accept the key and then never complete a handshake.
	if _, err := priv.ECDH(peer); err != nil {
		return fmt.Errorf("netbackend: WireGuard PeerPublicKey is not a valid curve point: %w", err)
	}
	if string(priv.PublicKey().Bytes()) == string(cfg.PeerPublicKey[:]) {
		return errors.New("netbackend: WireGuard PeerPublicKey equals the public key of PrivateKey")
	}

	if !cfg.GuestIPv4.Addr().Is4() {
		return fmt.Errorf("netbackend: WireGuard GuestIPv4 %s is not an IPv4 prefix", cfg.GuestIPv4)
	}
	minMTU := uint32(wgMinMTU)
	if cfg.GuestIPv6.IsValid() {
		if !cfg.GuestIPv6.Addr().Is6() || cfg.GuestIPv6.Addr().Is4In6() {
			return fmt.Errorf("netbackend: WireGuard GuestIPv6 %s is not an IPv6 prefix", cfg.GuestIPv6)
		}
		minMTU = wgMinMTUWithIPv6
	}
	if cfg.MTU < minMTU || cfg.MTU > device.MaxContentSize {
		return fmt.Errorf("netbackend: WireGuard MTU %d is outside %d..%d", cfg.MTU, minMTU, device.MaxContentSize)
	}
	for i, p := range cfg.AllowedIPs {
		if !p.IsValid() {
			return fmt.Errorf("netbackend: WireGuard AllowedIPs[%d] is not a valid prefix", i)
		}
		cfg.AllowedIPs[i] = p.Masked()
	}
	if cfg.PersistentKeepalive < 0 || cfg.PersistentKeepalive%time.Second != 0 ||
		cfg.PersistentKeepalive/time.Second > wgMaxKeepaliveSecs {
		return fmt.Errorf("netbackend: WireGuard PersistentKeepalive %s must be 0..%d whole seconds", cfg.PersistentKeepalive, wgMaxKeepaliveSecs)
	}
	return nil
}

// lookupNetIPFunc resolves a host name to IP addresses. net.Resolver.LookupNetIP has this shape.
type lookupNetIPFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

// resolveWireGuardPeerEndpoint turns "host:port" into an address. It runs
// before lockdown because the sandbox cannot resolve names afterward.
func resolveWireGuardPeerEndpoint(ctx context.Context, endpoint string, lookup lookupNetIPFunc) (netip.AddrPort, error) {
	if endpoint == "" {
		return netip.AddrPort{}, nil
	}
	if ap, err := netip.ParseAddrPort(endpoint); err == nil {
		return checkWireGuardPeerEndpoint(endpoint, ap)
	}
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("netbackend: invalid WireGuard peer endpoint %q: %w", endpoint, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("netbackend: invalid WireGuard peer endpoint port %q: %w", portStr, err)
	}
	addrs, err := lookup(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("netbackend: resolve WireGuard peer endpoint %q: %w", endpoint, err)
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("netbackend: WireGuard peer endpoint %q has no addresses", endpoint)
	}
	return checkWireGuardPeerEndpoint(endpoint, netip.AddrPortFrom(addrs[0].Unmap(), uint16(port)))
}

func checkWireGuardPeerEndpoint(endpoint string, ap netip.AddrPort) (netip.AddrPort, error) {
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	if ap.Addr().IsUnspecified() || ap.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("netbackend: WireGuard peer endpoint %q needs a specific address and a non-zero port", endpoint)
	}
	return ap, nil
}

// PreBindUDP opens the single host UDP socket before hostlockdown.Apply. It
// does nothing when the socket is already open.
func (w *WireGuardEndpoint) PreBindUDP() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.preBindLocked()
}

func (w *WireGuardEndpoint) preBindLocked() error {
	if w.closed {
		return errors.New("netbackend: WireGuardEndpoint is closed")
	}
	if w.udpConn != nil {
		return nil
	}
	listen := w.cfg.ListenPacket
	if listen == nil {
		listen = net.ListenPacket
	}
	pc, err := listen("udp", w.cfg.ListenUDPAddr)
	if err != nil {
		return fmt.Errorf("netbackend: bind WireGuard UDP socket %q: %w", w.cfg.ListenUDPAddr, err)
	}
	w.udpConn = pc
	return nil
}

// LocalUDPAddr returns the bound local address of the pre-opened UDP socket,
// or nil before PreBindUDP.
func (w *WireGuardEndpoint) LocalUDPAddr() net.Addr {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.udpConn == nil {
		return nil
	}
	return w.udpConn.LocalAddr()
}

// Start creates the Netstack with one channel.Endpoint NIC and starts the
// wireguard-go device over the pre-bound socket. It opens the socket first
// when PreBindUDP has not run. Start returns the same stack on later calls.
func (w *WireGuardEndpoint) Start() (*stack.Stack, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.preBindLocked(); err != nil {
		return nil, err
	}
	if w.stack != nil {
		return w.stack, nil
	}

	s, chEP, err := w.newStackLocked()
	if err != nil {
		return nil, err
	}
	bind, err := newPreboundBind(w.udpConn)
	if err != nil {
		s.Close()
		chEP.Close()
		return nil, err
	}
	dev := device.NewDevice(newChannelTUN(chEP), bind, newWireGuardLogger(w.cfg.Logger))
	if err := dev.IpcSet(wireGuardIPCConfig(w.cfg, w.peerEndpoint)); err != nil {
		dev.Close()
		s.Close()
		chEP.Close()
		return nil, fmt.Errorf("netbackend: configure WireGuard device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		s.Close()
		chEP.Close()
		return nil, fmt.Errorf("netbackend: bring up WireGuard device: %w", err)
	}

	w.stack = s
	w.channelEP = chEP
	w.dev = dev
	return s, nil
}

// newStackLocked builds the Netstack with lo and the WireGuard eth0 NIC.
func (w *WireGuardEndpoint) newStackLocked() (*stack.Stack, *channel.Endpoint, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})
	if err := configureLoopbackNIC(s, LoopbackNICID); err != nil {
		s.Close()
		return nil, nil, err
	}

	chEP := channel.New(wgChannelQueueSize, w.cfg.MTU, "")
	fail := func(err error) (*stack.Stack, *channel.Endpoint, error) {
		s.Close()
		chEP.Close()
		return nil, nil, err
	}
	if err := s.CreateNIC(Eth0NICID, chEP); err != nil {
		return fail(fmt.Errorf("netbackend: create WireGuard channel NIC: %s", err))
	}
	v4 := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(w.cfg.GuestIPv4.Addr().As4()),
			PrefixLen: w.cfg.GuestIPv4.Bits(),
		},
	}
	if err := s.AddProtocolAddress(Eth0NICID, v4, stack.AddressProperties{}); err != nil {
		return fail(fmt.Errorf("netbackend: add WireGuard guest IPv4 address: %s", err))
	}
	routes := []tcpip.Route{
		{Destination: header.IPv4LoopbackSubnet, NIC: LoopbackNICID},
		{Destination: header.IPv4EmptySubnet, NIC: Eth0NICID},
	}
	if w.cfg.GuestIPv6.IsValid() {
		v6 := tcpip.ProtocolAddress{
			Protocol: ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom16(w.cfg.GuestIPv6.Addr().As16()),
				PrefixLen: w.cfg.GuestIPv6.Bits(),
			},
		}
		if err := s.AddProtocolAddress(Eth0NICID, v6, stack.AddressProperties{}); err != nil {
			return fail(fmt.Errorf("netbackend: add WireGuard guest IPv6 address: %s", err))
		}
		routes = append(routes, tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: Eth0NICID})
	}
	s.SetRouteTable(routes)
	return s, chEP, nil
}

// wireGuardIPCConfig renders cfg in the wireguard-go UAPI "set" format.
func wireGuardIPCConfig(cfg WireGuardConfig, peerEndpoint netip.AddrPort) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(cfg.PrivateKey[:]))
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(cfg.PeerPublicKey[:]))
	if cfg.PresharedKey != [32]byte{} {
		fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(cfg.PresharedKey[:]))
	}
	if peerEndpoint.IsValid() {
		fmt.Fprintf(&b, "endpoint=%s\n", peerEndpoint)
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(cfg.PersistentKeepalive/time.Second))
	b.WriteString("replace_allowed_ips=true\n")
	for _, p := range cfg.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", p)
	}
	return b.String()
}

// newWireGuardLogger adapts l to the wireguard-go logger. A nil l discards
// every message.
func newWireGuardLogger(l *slog.Logger) *device.Logger {
	if l == nil {
		return &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	}
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			if l.Enabled(context.Background(), slog.LevelDebug) {
				l.Debug(fmt.Sprintf(format, args...))
			}
		},
		Errorf: func(format string, args ...any) {
			l.Error(fmt.Sprintf(format, args...))
		},
	}
}

// ChannelEndpoint returns the underlying Netstack channel.Endpoint, or nil
// before Start.
func (w *WireGuardEndpoint) ChannelEndpoint() *channel.Endpoint {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.channelEP
}

// Close stops the device, closes the Netstack, and closes the UDP socket. The
// device stops first, so no goroutine uses the socket or the channel after
// Close returns. Close succeeds when the endpoint is already closed.
func (w *WireGuardEndpoint) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	dev, s, chEP, sock := w.dev, w.stack, w.channelEP, w.udpConn
	w.mu.Unlock()

	if dev != nil {
		dev.Close()
	}
	if s != nil {
		s.Close()
	}
	if chEP != nil {
		chEP.Close()
	}
	if sock != nil {
		if err := sock.Close(); err != nil {
			return fmt.Errorf("netbackend: close WireGuard UDP socket: %w", err)
		}
	}
	return nil
}

// wgINISection identifies the section of a WireGuard INI file.
type wgINISection int

const (
	wgSectionNone wgINISection = iota
	wgSectionInterface
	wgSectionPeer
)

// ParseWireGuardINI parses a wg-quick style INI configuration with one
// [Interface] section and one [Peer] section into a WireGuardConfig. It
// returns an error for an unknown section, an unknown key, a key that
// wg-quick runs as a host command, or an invalid value.
func ParseWireGuardINI(iniText string) (WireGuardConfig, error) {
	cfg := WireGuardConfig{MTU: DefaultWireGuardMTU}
	section := wgSectionNone
	peers := 0
	var haveAddr4, haveAddr6 bool
	for lineNo, rawLine := range strings.Split(iniText, "\n") {
		line := rawLine
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		where := func(err error) error {
			return fmt.Errorf("netbackend: WireGuard config line %d: %w", lineNo+1, err)
		}
		if strings.HasPrefix(line, "[") {
			switch strings.ToLower(line) {
			case "[interface]":
				if section != wgSectionNone {
					return WireGuardConfig{}, where(errors.New("[Interface] must be the first section"))
				}
				section = wgSectionInterface
			case "[peer]":
				peers++
				if peers > 1 {
					return WireGuardConfig{}, where(errors.New("only one [Peer] section is supported"))
				}
				section = wgSectionPeer
			default:
				return WireGuardConfig{}, where(fmt.Errorf("unknown section %q", line))
			}
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq == -1 {
			return WireGuardConfig{}, where(fmt.Errorf("%q is not a key = value pair", line))
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])

		switch section {
		case wgSectionInterface:
			switch key {
			case "privatekey":
				k, err := decodeWGKey(val)
				if err != nil {
					return WireGuardConfig{}, where(fmt.Errorf("invalid PrivateKey: %w", err))
				}
				cfg.PrivateKey = k
			case "address":
				for _, part := range strings.Split(val, ",") {
					pfx, err := parseWGAddress(strings.TrimSpace(part))
					if err != nil {
						return WireGuardConfig{}, where(err)
					}
					switch {
					case pfx.Addr().Is4() && !haveAddr4:
						cfg.GuestIPv4, haveAddr4 = pfx, true
					case pfx.Addr().Is6() && !haveAddr6:
						cfg.GuestIPv6, haveAddr6 = pfx, true
					default:
						return WireGuardConfig{}, where(fmt.Errorf("Address %s repeats an address family; the guest NIC takes one IPv4 and one IPv6 address", pfx))
					}
				}
			case "mtu":
				m, err := strconv.ParseUint(val, 10, 32)
				if err != nil {
					return WireGuardConfig{}, where(fmt.Errorf("invalid MTU %q: %w", val, err))
				}
				cfg.MTU = uint32(m)
			case "listenport":
				p, err := strconv.ParseUint(val, 10, 16)
				if err != nil {
					return WireGuardConfig{}, where(fmt.Errorf("invalid ListenPort %q: %w", val, err))
				}
				cfg.ListenUDPAddr = ":" + strconv.FormatUint(p, 10)
			case "dns":
				// The guest resolves names through the virtual resolver, so
				// the file DNS list has no effect.
			case "fwmark", "table", "preup", "postup", "predown", "postdown", "saveconfig":
				return WireGuardConfig{}, where(fmt.Errorf("[Interface] key %q is not supported", key))
			default:
				return WireGuardConfig{}, where(fmt.Errorf("unknown [Interface] key %q", key))
			}
		case wgSectionPeer:
			switch key {
			case "publickey":
				k, err := decodeWGKey(val)
				if err != nil {
					return WireGuardConfig{}, where(fmt.Errorf("invalid PublicKey: %w", err))
				}
				cfg.PeerPublicKey = k
			case "presharedkey":
				k, err := decodeWGKey(val)
				if err != nil {
					return WireGuardConfig{}, where(fmt.Errorf("invalid PresharedKey: %w", err))
				}
				cfg.PresharedKey = k
			case "endpoint":
				cfg.PeerEndpoint = val
			case "allowedips":
				for _, part := range strings.Split(val, ",") {
					p := strings.TrimSpace(part)
					if p == "" {
						continue
					}
					pfx, err := parseWGAddress(p)
					if err != nil {
						return WireGuardConfig{}, where(fmt.Errorf("invalid AllowedIPs entry: %w", err))
					}
					cfg.AllowedIPs = append(cfg.AllowedIPs, pfx)
				}
			case "persistentkeepalive":
				if strings.EqualFold(val, "off") {
					cfg.PersistentKeepalive = 0
					break
				}
				secs, err := strconv.ParseUint(val, 10, 16)
				if err != nil {
					return WireGuardConfig{}, where(fmt.Errorf("invalid PersistentKeepalive %q: %w", val, err))
				}
				cfg.PersistentKeepalive = time.Duration(secs) * time.Second
			default:
				return WireGuardConfig{}, where(fmt.Errorf("unknown [Peer] key %q", key))
			}
		default:
			return WireGuardConfig{}, where(fmt.Errorf("key %q appears before any section", key))
		}
	}
	if cfg.PrivateKey == [32]byte{} {
		return WireGuardConfig{}, errors.New("netbackend: WireGuard config has no [Interface] PrivateKey")
	}
	if peers == 0 || cfg.PeerPublicKey == [32]byte{} {
		return WireGuardConfig{}, errors.New("netbackend: WireGuard config has no [Peer] PublicKey")
	}
	return cfg, nil
}

// parseWGAddress parses "ip/bits" or a bare IP. A bare IP becomes a host prefix.
func parseWGAddress(s string) (netip.Prefix, error) {
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address %q", s)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func decodeWGKey(s string) ([32]byte, error) {
	var out [32]byte
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		copy(out[:], b)
		return out, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		copy(out[:], b)
		return out, nil
	}
	return out, errors.New("expected 32-byte base64 or hex WireGuard key")
}
