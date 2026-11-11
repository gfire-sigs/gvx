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

package vxlan

import (
	"sync"
	"weak"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
	"z.gfire.dev/gvx/pkg/waiter"
)

// receiveBufferSize is the receive buffer of the UDP endpoint in bytes. A
// burst of full-size datagrams from a TCP sender fits.
const receiveBufferSize = 4 << 20

// socketKey names one UDP endpoint. Links of one network stack with the same
// address family and port share the endpoint and differ in the VNI, as in
// Linux. The endpoint listens on the wildcard address, so the local address of
// a link only selects the outer source address.
type socketKey struct {
	stack weak.Pointer[stack.Stack]
	proto tcpip.NetworkProtocolNumber
	port  uint16
}

// sockets holds the open UDP endpoints.
var sockets struct {
	sync.Mutex
	m map[socketKey]*udpSocket
}

// udpSocket is the UDP endpoint of one or more links and the goroutine that
// reads it.
type udpSocket struct {
	key      socketKey
	ep       tcpip.Endpoint
	wq       waiter.Queue
	stopOnce sync.Once
	done     chan struct{}
	// exited closes when the read goroutine returns.
	exited chan struct{}

	mu    sync.RWMutex
	links map[uint32]*Endpoint
	// refs counts the links; the registry mutex guards it.
	refs int
}

// acquireSocket adds the link to the UDP endpoint for its address and port. It
// opens the endpoint when the link is the first one. It returns ErrDuplicate
// when another link uses the same VNI on that endpoint.
func acquireSocket(stk *stack.Stack, e *Endpoint) (*udpSocket, error) {
	key := socketKey{stack: e.stack, proto: e.proto, port: e.cfg.Port}
	sockets.Lock()
	defer sockets.Unlock()
	s := sockets.m[key]
	if s == nil {
		var err error
		if s, err = openSocket(stk, key); err != nil {
			return nil, err
		}
		if sockets.m == nil {
			sockets.m = make(map[socketKey]*udpSocket)
		}
		sockets.m[key] = s
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.links[e.cfg.VNI]; dup {
		if s.refs == 0 {
			s.stop()
			delete(sockets.m, key)
		}
		return nil, ErrDuplicate
	}
	s.links[e.cfg.VNI] = e
	s.refs++
	return s, nil
}

// openSocket binds the UDP endpoint and starts its read goroutine.
func openSocket(stk *stack.Stack, key socketKey) (*udpSocket, error) {
	s := &udpSocket{key: key, links: make(map[uint32]*Endpoint), done: make(chan struct{}), exited: make(chan struct{})}
	ep, terr := stk.NewEndpoint(udp.ProtocolNumber, key.proto, &s.wq)
	if terr != nil {
		return nil, &StackError{terr}
	}
	if key.proto == header.IPv6ProtocolNumber {
		ep.SocketOptions().SetV6Only(true)
	}
	ep.SocketOptions().SetReceiveBufferSize(receiveBufferSize, false /* notify */)
	if terr := ep.Bind(tcpip.FullAddress{Port: key.port}); terr != nil {
		ep.Close()
		return nil, &StackError{terr}
	}
	s.ep = ep
	go s.run()
	return s, nil
}

// stop closes the UDP endpoint and ends the read goroutine. It does not wait.
func (s *udpSocket) stop() {
	s.stopOnce.Do(func() {
		close(s.done)
		s.ep.Close()
	})
}

// CloseStack closes every UDP socket that stk opened for VXLAN links, including
// links that moved to another network namespace, and waits for their read
// goroutines to exit.
func CloseStack(stk *stack.Stack) {
	ws := weak.Make(stk)
	sockets.Lock()
	var closing []*udpSocket
	for k, s := range sockets.m {
		if k.stack == ws {
			delete(sockets.m, k)
			s.stop()
			closing = append(closing, s)
		}
	}
	sockets.Unlock()
	for _, s := range closing {
		<-s.exited
	}
}

func (s *udpSocket) evictClosed() {
	sockets.Lock()
	if sockets.m[s.key] == s {
		delete(sockets.m, s.key)
	}
	s.mu.Lock()
	links := make([]*Endpoint, 0, len(s.links))
	for vni, e := range s.links {
		links = append(links, e)
		delete(s.links, vni)
	}
	s.refs = 0
	s.mu.Unlock()
	sockets.Unlock()
	for _, e := range links {
		e.cleanup.Stop()
		vxlanNICs.Delete(nicKey{stack: e.stack, id: e.cfg.ID})
	}
}

// release removes the link. The last link closes the UDP endpoint and waits for
// the read goroutine. The wait holds no lock, because that goroutine can wait
// for a lock of the stack.
func (s *udpSocket) release(e *Endpoint) {
	sockets.Lock()
	s.mu.Lock()
	if s.links[e.cfg.VNI] == e {
		delete(s.links, e.cfg.VNI)
		s.refs--
	}
	last := s.refs == 0
	s.mu.Unlock()
	if last {
		delete(sockets.m, s.key)
		s.stop()
	}
	sockets.Unlock()
	if last {
		<-s.exited
	}
}

// sliceWriter collects the payload of one datagram. The read goroutine reuses
// the slice.
type sliceWriter struct{ b []byte }

func (w *sliceWriter) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

// run reads datagrams until the endpoint closes and gives each valid one to the
// link of its VNI.
func (s *udpSocket) run() {
	defer close(s.exited)
	defer s.evictClosed()
	we, notify := waiter.NewChannelEntry(waiter.ReadableEvents)
	s.wq.EventRegister(&we)
	defer s.wq.EventUnregister(&we)
	var w sliceWriter
	for {
		w.b = w.b[:0]
		res, err := s.ep.Read(&w, tcpip.ReadOptions{NeedRemoteAddr: true})
		if err != nil {
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				return
			}
			select {
			case <-notify:
				continue
			case <-s.done:
				return
			}
		}
		s.deliver(w.b, res.RemoteAddr.Addr)
	}
}

// deliver gives the inner frame of a datagram to the link with the VNI of the
// datagram. It drops a datagram for an unknown VNI.
func (s *udpSocket) deliver(payload []byte, src tcpip.Address) {
	// The GBP bits are valid only when the link of the VNI enables them, so
	// parse the VNI first and the flags after the lookup.
	if len(payload) < headerLen {
		return
	}
	vni := uint32(payload[4])<<16 | uint32(payload[5])<<8 | uint32(payload[6])
	s.mu.RLock()
	e := s.links[vni]
	s.mu.RUnlock()
	if e == nil {
		return
	}
	if _, frame, ok := parseHeader(payload, e.cfg.GBP); ok {
		e.receive(frame, src)
	}
}
