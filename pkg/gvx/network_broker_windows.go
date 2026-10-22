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

package gvx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/netbackend"
)

const brokerSocketLimit = 1024
const brokerReadPoll = 200 * time.Millisecond
const brokerIOTimeout = 10 * time.Second
const brokerDatagramSize = 65535

// NetworkRequest identifies resources owned by one broker. Address never names a host file.
type NetworkRequest struct {
	Operation, Network, Address string
	Handle                      uint64
	Data                        []byte
	Length                      int
	Deadline                    int64
}

// NetworkReply preserves partial reads and datagram boundaries across RPC.
type NetworkReply struct {
	Handle                 uint64
	Data                   []byte
	Count                  int
	Network, Local, Remote string
	Error, ErrorKind       string
	Addresses              []netip.Addr
}

func (r *NetworkReply) setError(err error) {
	if err == nil {
		return
	}
	r.Error = err.Error()
	var timeout net.Error
	switch {
	case errors.Is(err, io.EOF):
		r.ErrorKind = "eof"
	case errors.Is(err, net.ErrClosed):
		r.ErrorKind = "closed"
	case errors.Is(err, os.ErrPermission):
		r.ErrorKind = "permission"
	case errors.As(err, &timeout) && timeout.Timeout():
		r.ErrorKind = "timeout"
	default:
		var dns *net.DNSError
		if errors.As(err, &dns) && dns.IsNotFound {
			r.ErrorKind = "notfound"
		}
	}
}

func (r NetworkReply) operationError() error {
	if r.Error == "" {
		return nil
	}
	switch r.ErrorKind {
	case "eof":
		return io.EOF
	case "closed":
		return net.ErrClosed
	case "permission":
		return os.ErrPermission
	case "timeout":
		return os.ErrDeadlineExceeded
	case "notfound":
		return &net.DNSError{Err: r.Error, IsNotFound: true}
	default:
		return errors.New(r.Error)
	}
}

type brokerSocket struct {
	connection       net.Conn
	packet           *net.UDPConn
	listener         *net.TCPListener
	peer             netip.AddrPort
	reading, writing atomic.Bool
	bindKey          string
	claimed          bool
	extra            []io.Closer
	closeOnce        sync.Once
	closeErr         error
	peerMu           sync.Mutex
	clients          map[netip.AddrPort]time.Time
}

func (s *brokerSocket) close() error {
	s.closeOnce.Do(func() {
		var errs []error
		if s.connection != nil {
			errs = append(errs, s.connection.Close())
		}
		if s.packet != nil {
			errs = append(errs, s.packet.Close())
		}
		if s.listener != nil {
			errs = append(errs, s.listener.Close())
		}
		for _, extra := range s.extra {
			errs = append(errs, extra.Close())
		}
		var failures []error
		for _, err := range errs {
			if err != nil && !errors.Is(err, net.ErrClosed) {
				failures = append(failures, err)
			}
		}
		s.closeErr = errors.Join(failures...)
	})
	return s.closeErr
}

func (s *brokerSocket) describe(id uint64) NetworkReply {
	r := NetworkReply{Handle: id}
	switch {
	case s.connection != nil:
		r.Network = s.connection.LocalAddr().Network()
		r.Local = s.connection.LocalAddr().String()
		r.Remote = s.connection.RemoteAddr().String()
	case s.packet != nil:
		r.Network = "udp"
		r.Local = s.packet.LocalAddr().String()
	case s.listener != nil:
		r.Network = "tcp"
		r.Local = s.listener.Addr().String()
	}
	return r
}

type networkBroker struct {
	mu          sync.Mutex
	mode        NetworkMode
	isolateLAN  bool
	interceptor netbackend.StreamInterceptor
	sockets     map[uint64]*brokerSocket
	next        uint64
	pending     int
	closed      bool
	ctx         context.Context
	cancel      context.CancelFunc
	tasks       sync.WaitGroup
	ports       []int
	bound       []uint64
}

func newNetworkBroker(ctx context.Context, cfg *Config) (broker *networkBroker, err error) {
	lifetime, cancel := context.WithCancel(context.Background())
	b := &networkBroker{mode: cfg.NetworkMode, isolateLAN: cfg.IsolateLAN, interceptor: cfg.StreamInterceptor, sockets: make(map[uint64]*brokerSocket), ctx: lifetime, cancel: cancel}
	defer func() {
		if err != nil {
			err = errors.Join(err, b.Close())
		}
	}()
	if cfg.NetworkMode == NetModeWireGuard {
		var config netbackend.WireGuardConfig
		if cfg.WireGuardConfig != nil {
			config = *cfg.WireGuardConfig
		} else {
			data, err := os.ReadFile(cfg.WireGuardConfigPath)
			if err != nil {
				return nil, err
			}
			config, err = netbackend.ParseWireGuardINI(string(data))
			if err != nil {
				return nil, err
			}
		}
		if config.PeerEndpoint == "" {
			return nil, fmt.Errorf("%w: process WireGuard needs a peer endpoint", ErrInvalidConfig)
		}
		host, port, err := net.SplitHostPort(config.PeerEndpoint)
		if err != nil {
			return nil, err
		}
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(addresses) == 0 {
			return nil, errors.New("gvx: WireGuard peer has no address")
		}
		portNumber, err := strconv.ParseUint(port, 10, 16)
		if err != nil || portNumber == 0 {
			return nil, fmt.Errorf("%w: invalid WireGuard peer port", ErrInvalidConfig)
		}
		peer := netip.AddrPortFrom(addresses[0].Unmap(), uint16(portNumber))
		config.PeerEndpoint = peer.String()
		config.ListenPacket = nil
		config.Logger = nil
		if _, err := netbackend.NewWireGuardEndpoint(config); err != nil {
			return nil, err
		}
		address := config.ListenUDPAddr
		if address == "" {
			address = netbackend.DefaultWireGuardListenAddr
		}
		local, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return nil, err
		}
		pc, err := net.DialUDP("udp", local, net.UDPAddrFromAddrPort(peer))
		if err != nil {
			return nil, err
		}
		id, addErr := b.add(&brokerSocket{packet: pc, peer: peer, bindKey: "udp|" + address})
		err = addErr
		if err != nil {
			pc.Close()
			return nil, err
		}
		cfg.WireGuardConfig = &config
		b.bound = append(b.bound, id)
		cfg.WireGuardConfigPath = ""
	}
	if cfg.NetworkMode == NetModeNAT {
		for _, rule := range cfg.PortForwards {
			rule.Protocol = strings.ToLower(rule.Protocol)
			if rule.Protocol == "" {
				rule.Protocol = "tcp"
			}
			host := rule.BindAddress
			if host == "" {
				host = "127.0.0.1"
			}
			address := net.JoinHostPort(host, strconv.Itoa(int(rule.HostPort)))
			socket := &brokerSocket{bindKey: rule.Protocol + "|" + address}
			switch rule.Protocol {
			case "tcp":
				addr, err := net.ResolveTCPAddr("tcp", address)
				if err != nil {
					return nil, err
				}
				socket.listener, err = net.ListenTCP("tcp", addr)
				if err != nil {
					return nil, err
				}
				b.ports = append(b.ports, socket.listener.Addr().(*net.TCPAddr).Port)
			case "udp":
				addr, err := net.ResolveUDPAddr("udp", address)
				if err != nil {
					return nil, err
				}
				socket.packet, err = net.ListenUDP("udp", addr)
				if err != nil {
					return nil, err
				}
				b.ports = append(b.ports, socket.packet.LocalAddr().(*net.UDPAddr).Port)
			default:
				return nil, fmt.Errorf("%w: unsupported forwarded protocol %q", ErrInvalidConfig, rule.Protocol)
			}
			id, err := b.add(socket)
			if err != nil {
				socket.close()
				return nil, err
			}
			b.bound = append(b.bound, id)
		}
	}
	return b, nil
}

func (b *networkBroker) add(socket *brokerSocket) (uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, net.ErrClosed
	}
	if len(b.sockets) >= brokerSocketLimit {
		return 0, errors.New("gvx: network broker socket limit reached")
	}
	b.next++
	b.sockets[b.next] = socket
	return b.next, nil
}

func (b *networkBroker) Call(request NetworkRequest, reply *NetworkReply) error {
	if len(request.Data) > brokerDatagramSize || len(request.Address) > 512 {
		return errors.New("gvx: network broker request is too large")
	}
	switch request.Operation {
	case "Dial":
		return b.dial(request, reply)
	case "Lookup":
		if b.mode != NetModeNAT || len(request.Address) > 253 {
			return os.ErrPermission
		}
		ctx, cancel := context.WithTimeout(b.ctx, brokerIOTimeout)
		defer cancel()
		var err error
		reply.Addresses, err = net.DefaultResolver.LookupNetIP(ctx, "ip", request.Address)
		reply.setError(err)
		return nil
	case "Bind":
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.closed {
			return net.ErrClosed
		}
		for _, id := range b.bound {
			socket := b.sockets[id]
			if socket == nil {
				continue
			}
			if socket.bindKey == request.Network+"|"+request.Address && !socket.claimed {
				socket.claimed = true
				*reply = socket.describe(id)
				return nil
			}
		}
		return os.ErrPermission
	}
	b.mu.Lock()
	socket := b.sockets[request.Handle]
	if request.Operation == "Close" {
		delete(b.sockets, request.Handle)
	}
	b.mu.Unlock()
	if socket == nil {
		reply.setError(net.ErrClosed)
		return nil
	}
	if request.Operation == "Close" {
		reply.setError(socket.close())
		return nil
	}
	switch request.Operation {
	case "Read", "ReadPacket", "Accept":
		if !socket.reading.CompareAndSwap(false, true) {
			return errors.New("gvx: socket already has a reader")
		}
		defer socket.reading.Store(false)
	case "Write", "WritePacket", "CloseWrite":
		if !socket.writing.CompareAndSwap(false, true) {
			return errors.New("gvx: socket already has a writer")
		}
		defer socket.writing.Store(false)
	default:
		return errors.New("gvx: unknown network broker operation")
	}
	if request.Operation == "CloseWrite" {
		writer, ok := socket.connection.(interface{ CloseWrite() error })
		if !ok {
			return errors.New("gvx: socket does not support half-close")
		}
		reply.setError(writer.CloseWrite())
		return nil
	}
	deadline := time.Now().Add(brokerIOTimeout)
	if request.Operation == "Read" || request.Operation == "ReadPacket" || request.Operation == "Accept" {
		deadline = time.Now().Add(brokerReadPoll)
	}
	if request.Deadline != 0 {
		requested := time.Unix(0, request.Deadline)
		if requested.Before(deadline) {
			deadline = requested
		}
	}
	if request.Operation == "Accept" {
		if socket.listener == nil {
			return errors.New("gvx: socket is not a listener")
		}
		if err := socket.listener.SetDeadline(deadline); err != nil {
			return err
		}
		connection, err := socket.listener.AcceptTCP()
		if err != nil {
			reply.setError(err)
			return nil
		}
		accepted := &brokerSocket{connection: connection}
		id, err := b.add(accepted)
		if err != nil {
			connection.Close()
			return err
		}
		*reply = accepted.describe(id)
		return nil
	}
	if request.Operation == "Read" || request.Operation == "ReadPacket" {
		if request.Length <= 0 || request.Length > brokerDatagramSize {
			return errors.New("gvx: invalid network read size")
		}
		data := make([]byte, request.Length)
		var n int
		var err error
		if request.Operation == "ReadPacket" {
			if socket.packet == nil {
				return errors.New("gvx: socket is not a packet socket")
			}
			if err := socket.packet.SetReadDeadline(deadline); err != nil {
				return err
			}
			var from netip.AddrPort
			n, from, err = socket.packet.ReadFromUDPAddrPort(data)
			if err == nil && !socket.peer.IsValid() && !socket.rememberClient(from) {
				reply.ErrorKind = "timeout"
				reply.Error = "gvx: published UDP client limit reached"
				return nil
			}
			reply.Remote = from.String()
		} else {
			if socket.connection == nil {
				return errors.New("gvx: socket is not a connection")
			}
			if err := socket.connection.SetReadDeadline(deadline); err != nil {
				return err
			}
			n, err = socket.connection.Read(data)
		}
		reply.Data = data[:n]
		reply.Count = n
		reply.setError(err)
		return nil
	}
	var n int
	var err error
	if request.Operation == "WritePacket" {
		if socket.packet == nil {
			return errors.New("gvx: socket is not a packet socket")
		}
		peer, err := netip.ParseAddrPort(request.Address)
		if err != nil {
			return err
		}
		peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
		if socket.peer.IsValid() && peer != socket.peer {
			return os.ErrPermission
		}
		if !socket.peer.IsValid() && !socket.authorizedClient(peer) {
			return os.ErrPermission
		}
		if err := socket.packet.SetWriteDeadline(deadline); err != nil {
			return err
		}
		if socket.peer.IsValid() {
			n, err = socket.packet.Write(request.Data)
		} else {
			n, err = socket.packet.WriteToUDPAddrPort(request.Data, peer)
		}
	} else {
		if socket.connection == nil {
			return errors.New("gvx: socket is not a connection")
		}
		if err := socket.connection.SetWriteDeadline(deadline); err != nil {
			return err
		}
		n, err = socket.connection.Write(request.Data)
	}
	reply.Count = n
	reply.setError(err)
	return nil
}

func (s *brokerSocket) rememberClient(address netip.AddrPort) bool {
	address = netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.clients == nil {
		s.clients = make(map[netip.AddrPort]time.Time)
	}
	now := time.Now()
	if _, known := s.clients[address]; !known && len(s.clients) >= brokerSocketLimit {
		for peer, last := range s.clients {
			if now.Sub(last) >= 30*time.Second {
				delete(s.clients, peer)
			}
		}
		if len(s.clients) >= brokerSocketLimit {
			return false
		}
	}
	s.clients[address] = now
	return true
}

func (s *brokerSocket) authorizedClient(address netip.AddrPort) bool {
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	last, known := s.clients[address]
	if !known || time.Since(last) >= 30*time.Second {
		return false
	}
	s.clients[address] = time.Now()
	return true
}

func (b *networkBroker) dial(request NetworkRequest, reply *NetworkReply) error {
	if b.mode != NetModeNAT || (request.Network != "tcp" && request.Network != "udp") {
		return os.ErrPermission
	}
	address, err := netip.ParseAddrPort(request.Address)
	if err != nil {
		return errors.New("gvx: broker dial requires an IP address and port")
	}
	ip := address.Addr().Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || b.isolateLAN && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()) {
		return os.ErrPermission
	}
	b.mu.Lock()
	if b.closed || len(b.sockets)+b.pending >= brokerSocketLimit {
		b.mu.Unlock()
		return errors.New("gvx: network broker is closed or full")
	}
	b.pending++
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.pending--; b.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(b.ctx, brokerIOTimeout)
	defer cancel()
	if request.Deadline != 0 {
		var deadlineCancel context.CancelFunc
		ctx, deadlineCancel = context.WithDeadline(ctx, time.Unix(0, request.Deadline))
		defer deadlineCancel()
	}
	var dialer net.Dialer
	connection, err := dialer.DialContext(ctx, request.Network, address.String())
	if err != nil {
		reply.setError(err)
		return nil
	}
	socket := &brokerSocket{connection: connection}
	if request.Network == "tcp" && b.interceptor != nil {
		worker, guest := brokerStreamPair()
		socket.connection = worker
		socket.extra = []io.Closer{guest, connection}
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			socket.close()
			return net.ErrClosed
		}
		b.tasks.Add(1)
		b.mu.Unlock()
		go func() {
			defer b.tasks.Done()
			_ = b.interceptor(b.ctx, address.String(), guest, connection)
			guest.Close()
			connection.Close()
		}()
	}
	id, err := b.add(socket)
	if err != nil {
		socket.close()
		return err
	}
	*reply = socket.describe(id)
	if b.interceptor != nil && request.Network == "tcp" {
		reply.Network = "tcp"
		reply.Local = connection.LocalAddr().String()
		reply.Remote = connection.RemoteAddr().String()
	}
	return nil
}

type brokerStream struct{ reader, writer net.Conn }

func brokerStreamPair() (*brokerStream, *brokerStream) {
	firstRead, secondWrite := net.Pipe()
	secondRead, firstWrite := net.Pipe()
	return &brokerStream{reader: firstRead, writer: firstWrite}, &brokerStream{reader: secondRead, writer: secondWrite}
}
func (s *brokerStream) Read(data []byte) (int, error)  { return s.reader.Read(data) }
func (s *brokerStream) Write(data []byte) (int, error) { return s.writer.Write(data) }
func (s *brokerStream) CloseWrite() error              { return s.writer.Close() }
func (s *brokerStream) Close() error                   { return errors.Join(s.reader.Close(), s.writer.Close()) }
func (s *brokerStream) LocalAddr() net.Addr            { return s.reader.LocalAddr() }
func (s *brokerStream) RemoteAddr() net.Addr           { return s.reader.RemoteAddr() }
func (s *brokerStream) SetDeadline(deadline time.Time) error {
	return errors.Join(s.reader.SetReadDeadline(deadline), s.writer.SetWriteDeadline(deadline))
}
func (s *brokerStream) SetReadDeadline(deadline time.Time) error {
	return s.reader.SetReadDeadline(deadline)
}
func (s *brokerStream) SetWriteDeadline(deadline time.Time) error {
	return s.writer.SetWriteDeadline(deadline)
}

func (b *networkBroker) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	b.cancel()
	sockets := b.sockets
	b.sockets = make(map[uint64]*brokerSocket)
	b.mu.Unlock()
	var errs []error
	for _, socket := range sockets {
		errs = append(errs, socket.close())
	}
	b.tasks.Wait()
	return errors.Join(errs...)
}
