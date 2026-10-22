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
	"io"
	"net"
	"net/netip"
	"net/rpc"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/netbackend"
)

type processNetworkProxy struct {
	client  *rpc.Client
	pending sync.WaitGroup
}

func (p *processNetworkProxy) call(request NetworkRequest) (reply NetworkReply, err error) {
	err = p.client.Call("Network.Call", request, &reply)
	if errors.Is(err, rpc.ErrShutdown) {
		return reply, net.ErrClosed
	}
	if err == nil {
		err = reply.operationError()
	}
	return reply, err
}

func (p *processNetworkProxy) callContext(ctx context.Context, request NetworkRequest) (NetworkReply, error) {
	reply := new(NetworkReply)
	if err := ctx.Err(); err != nil {
		return NetworkReply{}, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		request.Deadline = deadline.UnixNano()
	}
	call := p.client.Go("Network.Call", request, reply, make(chan *rpc.Call, 1))
	select {
	case result := <-call.Done:
		if result.Error != nil {
			return *reply, result.Error
		}
		return *reply, reply.operationError()
	case <-ctx.Done():
		p.pending.Add(1)
		go func() {
			defer p.pending.Done()
			result := <-call.Done
			if result.Error == nil && reply.Handle != 0 {
				_, _ = p.call(NetworkRequest{Operation: "Close", Handle: reply.Handle})
			}
		}()
		return NetworkReply{}, ctx.Err()
	}
}

func (p *processNetworkProxy) connection(reply NetworkReply) (*processConnection, error) {
	var local, remote net.Addr
	var err error
	if reply.Network == "tcp" {
		local, err = net.ResolveTCPAddr("tcp", reply.Local)
		if err == nil && reply.Remote != "" {
			remote, err = net.ResolveTCPAddr("tcp", reply.Remote)
		}
	} else if reply.Network == "udp" {
		local, err = net.ResolveUDPAddr("udp", reply.Local)
		if err == nil && reply.Remote != "" {
			remote, err = net.ResolveUDPAddr("udp", reply.Remote)
		}
	} else {
		return nil, errors.New("gvx: invalid broker network")
	}
	if err != nil {
		return nil, err
	}
	if reply.Handle == 0 {
		return nil, errors.New("gvx: missing broker socket")
	}
	return &processConnection{proxy: p, handle: reply.Handle, local: local, remote: remote, network: reply.Network}, nil
}

func (p *processNetworkProxy) dial(ctx context.Context, network, address string) (net.Conn, error) {
	reply, err := p.callContext(ctx, NetworkRequest{Operation: "Dial", Network: network, Address: address})
	if err != nil {
		return nil, err
	}
	return p.connection(reply)
}
func (p *processNetworkProxy) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	r, err := p.callContext(ctx, NetworkRequest{Operation: "Lookup", Address: host})
	return r.Addresses, err
}
func (p *processNetworkProxy) listen(network, address string) (net.Listener, error) {
	reply, err := p.call(NetworkRequest{Operation: "Bind", Network: network, Address: address})
	if err != nil {
		return nil, err
	}
	connection, err := p.connection(reply)
	if err != nil {
		return nil, err
	}
	return &processListener{processConnection: connection}, nil
}
func (p *processNetworkProxy) listenPacket(network, address string) (net.PacketConn, error) {
	reply, err := p.call(NetworkRequest{Operation: "Bind", Network: network, Address: address})
	if err != nil {
		return nil, err
	}
	connection, err := p.connection(reply)
	if err != nil {
		return nil, err
	}
	return &processPacketConnection{processConnection: connection}, nil
}
func (p *processNetworkProxy) networkIO() *processNetworkIO {
	return &processNetworkIO{dial: p.dial, lookup: p.lookup, host: netbackend.HostNetwork{Listen: p.listen, ListenPacket: p.listenPacket}}
}

type processConnection struct {
	proxy                       *processNetworkProxy
	handle                      uint64
	network                     string
	local, remote               net.Addr
	closed                      atomic.Bool
	readDeadline, writeDeadline atomic.Int64
	readMu, writeMu             sync.Mutex
}

func deadlineExpired(deadline int64) bool { return deadline != 0 && time.Now().UnixNano() >= deadline }

func (c *processConnection) read(operation string, data []byte) (int, string, error) {
	if len(data) == 0 {
		return 0, "", nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if c.closed.Load() {
			return 0, "", net.ErrClosed
		}
		deadline := c.readDeadline.Load()
		if deadlineExpired(deadline) {
			return 0, "", os.ErrDeadlineExceeded
		}
		reply, err := c.proxy.call(NetworkRequest{Operation: operation, Handle: c.handle, Length: min(len(data), brokerDatagramSize), Deadline: deadline})
		if errors.Is(err, os.ErrDeadlineExceeded) && len(reply.Data) == 0 {
			continue
		}
		if len(reply.Data) > len(data) || reply.Count != len(reply.Data) {
			return 0, "", errors.New("gvx: invalid broker read result")
		}
		return copy(data, reply.Data), reply.Remote, err
	}
}
func (c *processConnection) Read(data []byte) (int, error) {
	n, _, err := c.read("Read", data)
	return n, err
}
func (c *processConnection) Write(data []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.network == "udp" && len(data) > brokerDatagramSize {
		return 0, errors.New("gvx: UDP datagram exceeds 65535 bytes")
	}
	count := 0
	first := true
	for count < len(data) || first && c.network == "udp" {
		first = false
		if c.closed.Load() {
			return count, net.ErrClosed
		}
		deadline := c.writeDeadline.Load()
		if deadlineExpired(deadline) {
			return count, os.ErrDeadlineExceeded
		}
		length := min(len(data)-count, brokerDatagramSize)
		reply, err := c.proxy.call(NetworkRequest{Operation: "Write", Handle: c.handle, Data: data[count : count+length], Deadline: deadline})
		if reply.Count < 0 || reply.Count > length {
			return count, errors.New("gvx: invalid broker write result")
		}
		count += reply.Count
		if err != nil {
			return count, err
		}
		if reply.Count == 0 && length != 0 {
			return count, io.ErrNoProgress
		}
	}
	return count, nil
}
func (c *processConnection) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	_, err := c.proxy.call(NetworkRequest{Operation: "Close", Handle: c.handle})
	return err
}

func (c *processConnection) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}
	_, err := c.proxy.call(NetworkRequest{Operation: "CloseWrite", Handle: c.handle})
	return err
}
func (c *processConnection) LocalAddr() net.Addr  { return c.local }
func (c *processConnection) RemoteAddr() net.Addr { return c.remote }
func (c *processConnection) SetDeadline(deadline time.Time) error {
	if err := c.SetReadDeadline(deadline); err != nil {
		return err
	}
	return c.SetWriteDeadline(deadline)
}
func (c *processConnection) SetReadDeadline(deadline time.Time) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	var value int64
	if !deadline.IsZero() {
		value = deadline.UnixNano()
	}
	c.readDeadline.Store(value)
	return nil
}
func (c *processConnection) SetWriteDeadline(deadline time.Time) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	var value int64
	if !deadline.IsZero() {
		value = deadline.UnixNano()
	}
	c.writeDeadline.Store(value)
	return nil
}

type processPacketConnection struct{ *processConnection }

func (c *processPacketConnection) ReadFromUDPAddrPort(data []byte) (int, netip.AddrPort, error) {
	n, from, err := c.read("ReadPacket", data)
	if err != nil {
		return n, netip.AddrPort{}, err
	}
	address, err := netip.ParseAddrPort(from)
	return n, address, err
}
func (c *processPacketConnection) WriteToUDPAddrPort(data []byte, to netip.AddrPort) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	deadline := c.writeDeadline.Load()
	if deadlineExpired(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	reply, err := c.proxy.call(NetworkRequest{Operation: "WritePacket", Handle: c.handle, Address: to.String(), Data: data, Deadline: deadline})
	if reply.Count < 0 || reply.Count > len(data) {
		return 0, errors.New("gvx: invalid broker datagram result")
	}
	return reply.Count, err
}
func (c *processPacketConnection) ReadFrom(data []byte) (int, net.Addr, error) {
	n, from, err := c.ReadFromUDPAddrPort(data)
	if err != nil {
		return n, nil, err
	}
	return n, net.UDPAddrFromAddrPort(from), nil
}
func (c *processPacketConnection) WriteTo(data []byte, to net.Addr) (int, error) {
	address, ok := to.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("gvx: UDP destination is required")
	}
	return c.WriteToUDPAddrPort(data, address.AddrPort())
}

type processListener struct{ *processConnection }

func (l *processListener) Addr() net.Addr { return l.local }
func (l *processListener) Accept() (net.Conn, error) {
	l.readMu.Lock()
	defer l.readMu.Unlock()
	for {
		if l.closed.Load() {
			return nil, net.ErrClosed
		}
		reply, err := l.proxy.call(NetworkRequest{Operation: "Accept", Handle: l.handle})
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return l.proxy.connection(reply)
	}
}
