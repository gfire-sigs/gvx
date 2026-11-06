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

package netstack

import (
	"strconv"

	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

// The IPv4 conf and neigh directories hold one file for each setting and link,
// such as conf/<link>/proxy_arp and neigh/<link>/proxy_delay. The stack stores
// the integer of each file, as proc_dointvec does. A link follows the file of
// the directory default until the guest writes its own file. A write to the
// default changes only the links without a value of their own. Linux copies
// the default to a link when the link appears, and a write to the default
// copies it to the links that did not change it. The check of proxy_arp
// takes the value of conf/all or the value of the link.

// linkConfState holds the values that the guest wrote to the files of links.
type linkConfState struct {
	mu sync.RWMutex
	// values maps a link to the values of its files by "dir/name".
	values map[tcpip.NICID]map[string]int32
}

// Directories of the settings that this store holds. The keys of the namespace
// store for conf/all and conf/default are dir + "/all/" + name and dir +
// "/default/" + name.
const (
	// ConfDirIPv4 is the directory net/ipv4/conf.
	ConfDirIPv4 = "ipv4/conf"
	// NeighDirIPv4 is the directory net/ipv4/neigh.
	NeighDirIPv4 = "ipv4/neigh"
)

// confDefault returns the value that a link without a value of its own has: the
// value of the file in the directory default, or def when the guest never wrote
// that file.
func (s *Stack) confDefault(dir, name string, def int32) int32 {
	if text, ok := s.SysctlValue(dir + "/default/" + name); ok {
		if v, err := strconv.ParseInt(text, 10, 32); err == nil {
			return int32(v)
		}
	}
	return def
}

// LinkConfValue returns the value of the file name in the conf or neigh
// directory dir of the link with the index id.
func (s *Stack) LinkConfValue(id int32, dir, name string, def int32) (int32, error) {
	if _, ok := s.Stack.SingleNICInfo(tcpip.NICID(id)); !ok {
		return 0, syserr.ErrUnknownNICID.ToError()
	}
	return s.linkConfValue(tcpip.NICID(id), dir, name, def), nil
}

func (s *Stack) linkConfValue(id tcpip.NICID, dir, name string, def int32) int32 {
	s.linkConf.mu.RLock()
	v, ok := s.linkConf.values[id][dir+"/"+name]
	s.linkConf.mu.RUnlock()
	if ok {
		return v
	}
	return s.confDefault(dir, name, def)
}

// SetLinkConfValue stores the value of the file name in the directory dir of
// the link with the index id.
func (s *Stack) SetLinkConfValue(id int32, dir, name string, v int32) error {
	nic := tcpip.NICID(id)
	if _, ok := s.Stack.SingleNICInfo(nic); !ok {
		return syserr.ErrUnknownNICID.ToError()
	}
	s.linkConf.mu.Lock()
	defer s.linkConf.mu.Unlock()
	// Drop the values of links that ended without an event of this stack.
	for other := range s.linkConf.values {
		if _, ok := s.Stack.SingleNICInfo(other); !ok {
			delete(s.linkConf.values, other)
		}
	}
	if s.linkConf.values == nil {
		s.linkConf.values = make(map[tcpip.NICID]map[string]int32)
	}
	if s.linkConf.values[nic] == nil {
		s.linkConf.values[nic] = make(map[string]int32)
	}
	s.linkConf.values[nic][dir+"/"+name] = v
	return nil
}

// dropLinkConf forgets the values of a link that left the stack.
func (s *Stack) dropLinkConf(id tcpip.NICID) {
	s.linkConf.mu.Lock()
	defer s.linkConf.mu.Unlock()
	delete(s.linkConf.values, id)
}

// proxyARPEnabled reports whether the link answers ARP requests for addresses
// that the host routes elsewhere. conf/all/proxy_arp or the value of the link
// turns it on.
func (s *Stack) proxyARPEnabled(id tcpip.NICID) bool {
	if text, ok := s.SysctlValue(ConfDirIPv4 + "/all/proxy_arp"); ok {
		if v, err := strconv.ParseInt(text, 10, 32); err == nil && v != 0 {
			return true
		}
	}
	return s.linkConfValue(id, ConfDirIPv4, "proxy_arp", 0) != 0
}

// rpFilterPolicy gives the reverse path check the rp_filter mode of the link
// and src_valid_mark. conf/all/src_valid_mark or the value of the link turns
// the mark on, as IN_DEV_SRC_VMARK of Linux does.
func (s *Stack) rpFilterPolicy(id tcpip.NICID) (int32, bool) {
	mode := s.EffectiveRPFilter(id)
	if mode != 1 && mode != 2 {
		return 0, false
	}
	if text, ok := s.SysctlValue(ConfDirIPv4 + "/all/src_valid_mark"); ok {
		if v, err := strconv.ParseInt(text, 10, 32); err == nil && v != 0 {
			return mode, true
		}
	}
	return mode, s.linkConfValue(id, ConfDirIPv4, "src_valid_mark", 0) != 0
}

// LinkForwarding returns conf/<link>/forwarding of the IPv4 link with the index
// id.
func (s *Stack) LinkForwarding(id int32) (bool, error) {
	on, err := s.Stack.NICForwarding(tcpip.NICID(id), ipv4.ProtocolNumber)
	if err != nil {
		return false, syserr.TranslateNetstackError(err).ToError()
	}
	return on, nil
}

// SetLinkForwarding sets conf/<link>/forwarding of the IPv4 link with the index
// id. Only that link changes. Calico writes the file for the host side of each
// pod.
func (s *Stack) SetLinkForwarding(id int32, enable bool) error {
	if _, err := s.Stack.SetNICForwarding(tcpip.NICID(id), ipv4.ProtocolNumber, enable); err != nil {
		return syserr.TranslateNetstackError(err).ToError()
	}
	return nil
}
