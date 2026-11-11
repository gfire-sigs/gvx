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

package proc

import (
	"math"
	"strconv"

	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// The directories /proc/sys/net/ipv4/neigh/default and
// /proc/sys/net/ipv6/neigh/default hold gc_thresh1, gc_thresh2, and gc_thresh3
// of the ARP table and the ND table. Each network namespace has its own values.
// Linux reads and writes a single table for the whole kernel through the
// same files. Linux accepts the range 0 to 2147483647 (proc_dointvec_minmax
// with SYSCTL_ZERO and SYSCTL_INT_MAX) and does not compare the three values.

// neighFamily describes the neighbor table of one IP family.
type neighFamily struct {
	// dir is the directory of the table below /proc/sys.
	dir      string
	protocol tcpip.NetworkProtocolNumber
	ids      [3]sysctlID
}

var neighFamilies = []neighFamily{
	{"net/ipv4/neigh/default", ipv4.ProtocolNumber, [3]sysctlID{sysctlIPv4NeighGCThresh1, sysctlIPv4NeighGCThresh2, sysctlIPv4NeighGCThresh3}},
	{"net/ipv6/neigh/default", ipv6.ProtocolNumber, [3]sysctlID{sysctlIPv6NeighGCThresh1, sysctlIPv6NeighGCThresh2, sysctlIPv6NeighGCThresh3}},
}

func init() {
	for _, f := range neighFamilies {
		nodeSysctlSpecs[f.dir] = f.specs()
	}
}

// key returns the key of a gc_thresh value in the store of the stack.
func (f neighFamily) key(name string) string { return f.dir + "/" + name }

// specs returns the sysctl files of the table.
func (f neighFamily) specs() []*sysctlSpec {
	files := []struct {
		name string
		def  int
	}{
		{"gc_thresh1", stack.DefaultNeighborGCThresh1},
		{"gc_thresh2", stack.DefaultNeighborGCThresh2},
		{"gc_thresh3", stack.DefaultNeighborGCThresh3},
	}
	specs := make([]*sysctlSpec, len(files))
	for i, file := range files {
		specs[i] = registerSysctlSpec(&sysctlSpec{
			id:    f.ids[i],
			scope: scopeNet,
			name:  file.name,
			key:   f.key(file.name),
			def:   strconv.Itoa(file.def),
			parse: intVecParser(1, 0, math.MaxInt32, nil),
			apply: f.apply,
		})
	}
	return specs
}

// apply sets the thresholds of the neighbor table of the stack from the stored
// values.
func (f neighFamily) apply(stk inet.Stack, st sysctlStore) error {
	s, ok := stk.(interface {
		SetNeighborGCThresholds(protocol tcpip.NetworkProtocolNumber, thresh1, thresh2, thresh3 int32) error
	})
	if !ok {
		return nil
	}
	return s.SetNeighborGCThresholds(f.protocol,
		int32(storedInt(st, f.key("gc_thresh1"), stack.DefaultNeighborGCThresh1)),
		int32(storedInt(st, f.key("gc_thresh2"), stack.DefaultNeighborGCThresh2)),
		int32(storedInt(st, f.key("gc_thresh3"), stack.DefaultNeighborGCThresh3)))
}

// isNeighDir reports whether path is a directory of /proc/sys/net/*/neigh that
// holds no file of its own. The files of the default directories come from
// addNodeSysctlFiles.
func isNeighDir(path string) bool {
	switch path {
	case "net/ipv4/neigh", "net/ipv6/neigh", "net/ipv4/neigh/default", "net/ipv6/neigh/default":
		return true
	}
	return false
}
