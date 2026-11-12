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

package stack

import "z.gfire.dev/gvx/pkg/tcpip"

type restorableLinkEndpoint interface {
	Restore()
}

func (s *Stack) initRestoreState() {
	s.fib.protocolsStarted.Store(true)
}

func (s *Stack) shouldRestoreProtocols() bool {
	return !s.fib.protocolsStarted.Swap(true)
}

// SetChildStackCallbacks registers callbacks invoked when s pauses, resumes,
// or restores.
func (s *Stack) SetChildStackCallbacks(pause, resume, restore func()) {
	s.mu.Lock()
	s.fib.childPause = pause
	s.fib.childResume = resume
	s.fib.childRestore = restore
	s.mu.Unlock()
}

func (s *Stack) pauseChildStacks() {
	s.mu.RLock()
	fn := s.fib.childPause
	s.mu.RUnlock()
	if fn != nil {
		fn()
	}
}

func (s *Stack) resumeChildStacks() {
	s.mu.RLock()
	fn := s.fib.childResume
	s.mu.RUnlock()
	if fn != nil {
		fn()
	}
}

func (s *Stack) restoreChildStacks() {
	ext := s.ensureExtState()
	ext.mu.Lock()
	eps := ext.restoredEndpoints
	ext.restoredEndpoints = nil
	ext.mu.Unlock()
	for _, ep := range eps {
		if p, ok := ep.(postRestoreTransportEndpoint); ok {
			p.FinishRestore()
		}
	}

	s.mu.RLock()
	fn := s.fib.childRestore
	s.mu.RUnlock()
	if fn != nil {
		fn()
	}
}

func isVirtualPreservedNIC(n *nic) bool {
	if n == nil {
		return false
	}
	if n.kind != "" {
		return true
	}
	if ep, ok := n.NetworkLinkEndpoint.(LinkEndpoint); ok && isPreservedEndpoint(ep) {
		return true
	}
	_, isBridge := n.NetworkLinkEndpoint.(*BridgeEndpoint)
	return isBridge
}

func isPreservableNIC(n *nic) bool {
	return isVirtualPreservedNIC(n) || (n != nil && n.IsLoopback())
}

// +checklocks:s.mu
func (s *Stack) maybePreserveNICLocked(id tcpip.NICID, n *nic) {
	if isPreservableNIC(n) {
		s.preservedNICs[id] = n
	}
}

// +checklocks:s.mu
func (s *Stack) resetPreservedConfigLocked() {
	s.fib.restoredNICs = nil
	for id, nic := range s.preservedNICs {
		if !isVirtualPreservedNIC(nic) {
			delete(s.preservedNICs, id)
		}
	}
	s.filterPreservedRoutesLocked()
}

// +checklocks:s.mu
func (s *Stack) filterPreservedRoutesLocked() {
	if len(s.preservedRoutes) == 0 {
		return
	}
	kept := s.preservedRoutes[:0]
	for _, r := range s.preservedRoutes {
		if _, ok := s.preservedNICs[r.NIC]; ok || r.TableID() != tcpip.RouteTableMain || r.RouteType() != tcpip.RouteTypeUnicast {
			kept = append(kept, r)
		}
	}
	s.preservedRoutes = kept
}

// +checklocks:s.mu
func (s *Stack) prepareRestoreLocked() {
	if s.nics == nil {
		s.nics = make(map[tcpip.NICID]*nic)
	}
	if s.tables == nil {
		s.tables = DefaultTables(s.clock, s.insecureRNG)
	}
	ext := s.ensureExtState()
	ext.mu.Lock()
	ext.restoredEndpoints = append(ext.restoredEndpoints[:0], s.restoredEndpoints...)
	ext.mu.Unlock()
}

func restoreLinkEndpoint(ep NetworkLinkEndpoint) {
	if r, ok := ep.(restorableLinkEndpoint); ok {
		r.Restore()
	}
}

// +checklocks:s.mu
func (s *Stack) restorePreservedNICLocked(id tcpip.NICID, n *nic) bool {
	if existing := s.nics[id]; existing != nil && existing != n {
		delete(s.preservedNICs, id)
		s.filterPreservedRoutesLocked()
		return false
	}
	if s.fib.restoredNICs != nil && s.fib.restoredNICs[id] == n {
		if s.nics[id] == nil {
			n.stack = s
			s.nics[id] = n
			s.nicsChanged()
			n.NetworkLinkEndpoint.SetOnCloseAction(func() {
				s.RemoveNIC(id)
			})
		}
		return false
	}
	if s.fib.restoredNICs == nil {
		s.fib.restoredNICs = make(map[tcpip.NICID]*nic)
	}
	s.fib.restoredNICs[id] = n
	restoreLinkEndpoint(n.NetworkLinkEndpoint)
	if n.IsLoopback() {
		s.loopbackNIC = n
	} else if s.externalNetworkingDisabled {
		n.disable()
	}
	for s.nicIDGen.Load() < int32(id) {
		s.nicIDGen.Add(1)
	}
	return true
}
