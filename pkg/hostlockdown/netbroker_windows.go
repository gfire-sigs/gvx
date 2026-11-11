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

//go:build windows

package hostlockdown

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

const (
	defaultNetDialWorkers = 4
	minNetAcceptWorkers   = 4
)

type winNetBroker struct {
	dialCh   chan func()
	acceptCh chan func()
	stopCh   chan struct{}
}

var activeNetBroker atomic.Pointer[winNetBroker]

func isAllowedNetBrokerNetwork(network string) bool {
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		return true
	default:
		return false
	}
}

// startNetBroker pre-spawns fixed pools of locked Low-integrity socket-broker
// OS threads before Apply lowers primary to Untrusted integrity. Each worker
// attaches its own duplicated impersonation token and closes that token handle
// immediately, and startNetBroker closes netTok before returning so zero
// broker token handles remain in the process handle table.
func startNetBroker(primary windows.Token, id *tokenIdentity, preboundListeners int) (*winNetBroker, error) {
	netTok, err := createNetBrokerImpersonationToken(primary, id)
	if err != nil {
		return nil, err
	}
	defer netTok.Close()

	b := &winNetBroker{
		dialCh:   make(chan func()),
		acceptCh: make(chan func()),
		stopCh:   make(chan struct{}),
	}
	acceptWorkers := max(preboundListeners, minNetAcceptWorkers)
	if err := startNetWorkerPool(netTok, defaultNetDialWorkers, b.dialCh, b.stopCh); err != nil {
		close(b.stopCh)
		return nil, err
	}
	if err := startNetWorkerPool(netTok, acceptWorkers, b.acceptCh, b.stopCh); err != nil {
		close(b.stopCh)
		return nil, err
	}
	return b, nil
}

func startNetWorkerPool(baseTok windows.Token, count int, workCh <-chan func(), stopCh <-chan struct{}) error {
	ready := make(chan error, count)
	started := 0
	for range count {
		var dupTok windows.Token
		if err := windows.DuplicateTokenEx(
			baseTok,
			windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY,
			nil,
			windows.SecurityImpersonation,
			windows.TokenImpersonation,
			&dupTok,
		); err != nil {
			for range started {
				<-ready
			}
			return fmt.Errorf("hostlockdown: DuplicateTokenEx(net broker): %w", err)
		}
		started++
		go func(tok windows.Token) {
			runtime.LockOSThread()
			tid := excludeCurrentThread()
			setErr := windows.SetThreadToken(nil, tok)
			_ = tok.Close()
			if setErr != nil {
				unexcludeThread(tid)
				ready <- fmt.Errorf("hostlockdown: SetThreadToken(net broker): %w", setErr)
				return
			}
			ready <- nil
			for {
				select {
				case <-stopCh:
					unexcludeThread(tid)
					return
				case fn := <-workCh:
					fn()
				}
			}
		}(dupTok)
	}
	var firstErr error
	for range started {
		if workerErr := <-ready; workerErr != nil && firstErr == nil {
			firstErr = workerErr
		}
	}
	return firstErr
}

func (b *winNetBroker) stop() {
	if b != nil {
		close(b.stopCh)
	}
}

func (b *winNetBroker) runDial(fn func()) {
	b.dialCh <- fn
}

func (b *winNetBroker) runAccept(fn func()) {
	b.acceptCh <- fn
}

func dialHostContext(ctx context.Context, network, address string) (net.Conn, error) {
	if b := activeNetBroker.Load(); b != nil && isAllowedNetBrokerNetwork(network) {
		type dialResult struct {
			conn net.Conn
			err  error
		}
		done := make(chan dialResult, 1)
		b.runDial(func() {
			// Disable Happy Eyeballs parallel racing so WSASocketW always runs
			// on this locked broker OS thread rather than a helper goroutine.
			d := net.Dialer{FallbackDelay: -1}
			c, err := d.DialContext(ctx, network, address)
			done <- dialResult{conn: c, err: err}
		})
		res := <-done
		return res.conn, res.err
	}
	if IsLockedDown() {
		_ = BindThread()
	}
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func acceptHostListener(ln net.Listener) (net.Conn, error) {
	if b := activeNetBroker.Load(); b != nil {
		type acceptResult struct {
			conn net.Conn
			err  error
		}
		done := make(chan acceptResult, 1)
		b.runAccept(func() {
			c, err := ln.Accept()
			done <- acceptResult{conn: c, err: err}
		})
		res := <-done
		return res.conn, res.err
	}
	if IsLockedDown() {
		_ = BindThread()
	}
	return ln.Accept()
}
